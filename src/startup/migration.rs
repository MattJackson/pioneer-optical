//! Attempt-local parameter migration. No history files or saved defaults.
//! Select the target value before calling. The live A0 read/write/verify result
//! determines whether firmware transfer may begin.
use crate::drive::{self, Data, Transport};

/// Result of an attempted rollback before any firmware write was attempted.
#[derive(Debug)]
pub enum Rollback<E> {
    /// The original word was restored and read back.
    Restored,
    /// Reverse-order restoration outcomes for a multi-setting attempt.
    Settings(alloc::vec::Vec<(u16, Rollback<E>)>),
    /// No change was necessary.
    Unchanged,
    /// Firmware transfer was attempted: retaining the target value is safer
    /// than guessing which firmware is now resident.
    UnsafeAfterFirmwareWrite,
    /// Restoration or its readback failed. Do not retry automatically.
    Failed(drive::Error<E>),
}

/// Stage-aware failure, retaining the original word only in this attempt.
#[derive(Debug)]
pub enum Error<E, F> {
    /// Host policy or receiver binding refused before any parameter read/change.
    Preflight(F),
    /// The parameter index is outside the A0 0x800-byte response.
    InvalidParameter(u16),
    /// The complete settings plan contains duplicate or conflicting writes.
    ConflictingParameters,
    /// Initial read failed; no parameter or firmware write was attempted.
    Read(drive::Error<E>),
    /// Parameter change or verification failed; flash was never invoked.
    Change {
        /// Original captured word.
        original: u16,
        /// Failed write or verification.
        source: drive::Error<E>,
        /// Outcome of the single restoration attempt.
        rollback: Rollback<E>,
    },
    /// Flash callback failed, with rollback limited to pre-transfer failures.
    Flash {
        /// Original captured word.
        original: u16,
        /// Target-derived word.
        target: u16,
        /// Callback's error.
        source: F,
        /// Whether restoration was safe and successful.
        rollback: Rollback<E>,
    },
}

impl<E, F> crate::CodedError for Error<E, F> {
    fn code(&self) -> &'static str {
        match self {
            Self::Preflight(_) => "pioneer.startup.preflight_refused",
            Self::ConflictingParameters => "pioneer.settings.conflicting_parameters",
            Self::InvalidParameter(_) => "pioneer.startup.parameter_out_of_range",
            Self::Read(_) => "pioneer.startup.parameter_read_failed",
            Self::Change { .. } => "pioneer.startup.parameter_change_failed",
            Self::Flash {
                rollback: Rollback::UnsafeAfterFirmwareWrite,
                ..
            } => "pioneer.startup.flash_state_uncertain",
            Self::Flash { .. } => "pioneer.startup.flash_failed_before_transfer",
        }
    }
}

impl<E: core::fmt::Debug> core::fmt::Display for Rollback<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Settings(results) => {
                f.write_str("settings restoration:")?;
                for (parameter, result) in results { write!(f, " word {parameter:#x}: {result};")?; }
                Ok(())
            },
            Self::Restored=>f.write_str("the original startup setting was restored and verified"),
            Self::Unchanged=>f.write_str("the startup setting was unchanged"),
            Self::UnsafeAfterFirmwareWrite=>f.write_str("update commands were attempted; the target startup setting was retained because the installed firmware state is uncertain. Do not automatically repeat the flash"),
            Self::Failed(e)=>write!(f,"the original startup setting could not be restored or verified: {e}; save the diagnostic log before another attempt"),
        }
    }
}

impl<E: core::fmt::Debug, F: core::fmt::Display> core::fmt::Display for Error<E, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Preflight(source)=>write!(f,"update preflight refused before changing startup settings or firmware: {source}"),
            Self::ConflictingParameters => f.write_str("conflicting settings plan; no command was sent"),
            Self::InvalidParameter(p)=>write!(f,"startup parameter {p:#x} is outside the supported parameter surface; no command was sent"),
            Self::Read(e)=>write!(f,"A0 startup parameter read failed; no firmware was written. The drive may not implement this command in its current mode: {e}"),
            Self::Change{source,rollback,..}=>write!(f,"A0 startup parameter write or verification failed; no firmware was written: {source}; {rollback}"),
            Self::Flash{source,rollback,..}=>write!(f,"firmware update failed: {source}; {rollback}"),
        }
    }
}

impl<E: core::fmt::Debug + 'static, F: std::error::Error + 'static> std::error::Error
    for Error<E, F>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Preflight(source) | Self::Flash { source, .. } => Some(source),
            Self::Read(source) | Self::Change { source, .. } => Some(source),
            Self::InvalidParameter(_) | Self::ConflictingParameters => None,
        }
    }
}

/// Strict adapter tracking the FIRST ATTEMPT at a firmware transfer, not merely
/// successful chunks. It performs no retries and exposes no untracked adapter.
pub struct FlashTransport<'a, T> {
    inner: &'a mut T,
    attempted: bool,
}
impl<T: Transport> Transport for FlashTransport<'_, T> {
    type Error = T::Error;
    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
        // Conservatively include update entry/finish and every non-A0 vendor
        // write, rather than assuming an unsuccessful transfer changed nothing.
        if cdb.first() == Some(&0x3b) && cdb.get(2) != Some(&0xa0) {
            self.attempted = true;
        }
        self.inner.exec(cdb, data)
    }
    fn sense(&self) -> Option<(u8, u8, u8)> {
        self.inner.sense()
    }
}

fn read<T: Transport>(t: &mut T, parameter: u16) -> Result<u16, drive::Error<T::Error>> {
    let mut bytes = [0; 2];
    drive::read(
        t,
        &crate::cdb::read_parameter_word(parameter).expect("bounded parameter"),
        &mut bytes,
        2,
    )?;
    Ok(u16::from_be_bytes(bytes))
}
fn write_verified<T: Transport>(
    t: &mut T,
    parameter: u16,
    value: u16,
) -> Result<(), drive::Error<T::Error>> {
    let cdb = crate::cdb::write_parameter_word(parameter).expect("bounded parameter");
    drive::write(t, &cdb, &value.to_be_bytes())?;
    let actual = read(t, parameter)?;
    if actual != value {
        return Err(drive::Error::ReadbackMismatch {
            expected: u32::from(value),
            actual: u32::from(actual),
        });
    }
    Ok(())
}
fn rollback<T: Transport>(
    t: &mut T,
    parameter: u16,
    original: u16,
    changed: bool,
) -> Rollback<T::Error> {
    if !changed {
        return Rollback::Unchanged;
    }
    match write_verified(t, parameter, original) {
        Ok(()) => Rollback::Restored,
        Err(e) => Rollback::Failed(e),
    }
}

/// Read the original word, change and verify it, then invoke one flash attempt.
///
/// The callback MUST send all device writes through the supplied adapter and
/// use a transport which never retries writes. The caller must select the target
/// value first. A0 support is established by the live command result, not by a
/// static code match. Original state stays in RAM and is discarded on success.
/// A failed change prevents flash. A failed callback restores the original word
/// only before any update-entry/firmware command was attempted; otherwise it
/// returns an explicit unsafe-rollback outcome without sending restoration.
pub fn execute<T, F, R, X>(
    t: &mut T,
    parameter: u16,
    target: u16,
    flash: F,
) -> Result<R, Error<T::Error, X>>
where
    T: Transport,
    F: FnOnce(&mut FlashTransport<'_, T>) -> Result<R, X>,
{
    if parameter >= 0x400 {
        return Err(Error::InvalidParameter(parameter));
    }
    let original = read(t, parameter).map_err(Error::Read)?;
    let changed = original != target;
    if changed {
        if let Err(source) = write_verified(t, parameter, target) {
            let rollback = rollback(t, parameter, original, true);
            return Err(Error::Change {
                original,
                source,
                rollback,
            });
        }
    }
    let mut io = FlashTransport {
        inner: t,
        attempted: false,
    };
    match flash(&mut io) {
        Ok(result) => Ok(result),
        Err(source) => {
            let rollback = if io.attempted {
                Rollback::UnsafeAfterFirmwareWrite
            } else {
                rollback(io.inner, parameter, original, changed)
            };
            Err(Error::Flash {
                original,
                target,
                source,
                rollback,
            })
        }
    }
}

/// Execute a complete collection of bounded parameter settings around one flash.
/// All originals are read before the first mutation. A one-setting plan uses
/// the existing executor unchanged. A0 writes never count as firmware entry;
/// the first attempted update command forbids rollback for the entire plan.
pub fn execute_many<T, F, R, X>(
    t: &mut T,
    settings: &[(u16, u16)],
    flash: F,
) -> Result<R, Error<T::Error, X>>
where
    T: Transport,
    F: FnOnce(&mut FlashTransport<'_, T>) -> Result<R, X>,
{
    for (i, (parameter, _)) in settings.iter().enumerate() {
        if *parameter >= 0x400 {
            return Err(Error::InvalidParameter(*parameter));
        }
        if settings[..i].iter().any(|(p, _)| p == parameter) {
            return Err(Error::ConflictingParameters);
        }
    }
    if let [(parameter, target)] = settings {
        return execute(t, *parameter, *target, flash);
    }
    let mut originals = alloc::vec::Vec::new();
    for &(parameter, target) in settings {
        let original = read(t, parameter).map_err(Error::Read)?;
        originals.push((parameter, original, target));
    }
    fn restore<T: Transport>(t: &mut T, values: &[(u16, u16, u16)]) -> Rollback<T::Error> {
        Rollback::Settings(
            values
                .iter()
                .rev()
                .map(|&(p, old, new)| (p, rollback(t, p, old, old != new)))
                .collect(),
        )
    }
    for (index, &(parameter, original, target)) in originals.iter().enumerate() {
        if original != target {
            if let Err(source) = write_verified(t, parameter, target) {
                let rollback = restore(t, &originals[..=index]);
                return Err(Error::Change {
                    original,
                    source,
                    rollback,
                });
            }
        }
    }
    let mut io = FlashTransport {
        inner: t,
        attempted: false,
    };
    match flash(&mut io) {
        Ok(result) => Ok(result),
        Err(source) => {
            let rollback = if io.attempted {
                Rollback::UnsafeAfterFirmwareWrite
            } else {
                restore(io.inner, &originals)
            };
            // Retain legacy mutation reporting: any changed word makes these
            // unequal. Attempt-local originals are used only for safe restoration.
            let (_, original, target) = originals
                .iter()
                .copied()
                .find(|(_, old, new)| old != new)
                .unwrap_or((0, 0, 0));
            Err(Error::Flash {
                original,
                target,
                source,
                rollback,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Mock {
        word: u16,
        writes: std::vec::Vec<u16>,
        firmware_attempts: usize,
        reads: usize,
        bad_verification: bool,
        fail_initial_read: bool,
        fail_restore: bool,
    }
    impl Transport for Mock {
        type Error = &'static str;
        fn exec(&mut self, c: &[u8], d: Data<'_>) -> Result<usize, Self::Error> {
            if c[0] == 0x3c {
                self.reads += 1;
                if self.fail_initial_read && self.reads == 1 {
                    return Err("initial read failed");
                }
                assert_eq!(c, &[0x3c, 2, 0xa0, 0, 1, 0x3e, 0, 0, 2, 0]);
                if let Data::In(b) = d {
                    let value = if self.bad_verification && self.reads == 2 {
                        0xaaaa
                    } else {
                        self.word
                    };
                    b.copy_from_slice(&value.to_be_bytes());
                    return Ok(2);
                }
            } else if c[2] == 0xa0 {
                assert_eq!(c, &[0x3b, 2, 0xa0, 0, 1, 0x3e, 0, 0, 2, 0]);
                if let Data::Out(b) = d {
                    if self.fail_restore && !self.writes.is_empty() {
                        return Err("restore failed");
                    }
                    self.word = u16::from_be_bytes(b.try_into().unwrap());
                    self.writes.push(self.word);
                    return Ok(2);
                }
            } else {
                self.firmware_attempts += 1;
                return Err("uncertain firmware write");
            }
            panic!("unexpected phase")
        }
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
    }
    fn mock(word: u16) -> Mock {
        Mock {
            word,
            writes: std::vec![],
            firmware_attempts: 0,
            reads: 0,
            bad_verification: false,
            fail_initial_read: false,
            fail_restore: false,
        }
    }
    #[test]
    fn failed_change_verification_never_calls_flash() {
        let mut t = mock(0xffff);
        t.bad_verification = true;
        let err = execute(&mut t, 0x9f, 0xfe24, |_| -> Result<(), &str> {
            panic!("flash must not run")
        })
        .unwrap_err();
        assert!(format!("{err}").contains("A0 startup parameter write or verification failed"));
        assert!(matches!(
            err,
            Error::Change {
                rollback: Rollback::Restored,
                ..
            }
        ));
        assert_eq!(t.word, 0xffff);
        assert_eq!(t.firmware_attempts, 0);
    }
    #[test]
    fn invalid_index_sends_no_commands() {
        let mut t = mock(0xffff);
        let err = execute(&mut t, 0x400, 0xffff, |_| -> Result<(), ()> {
            panic!("flash must not run")
        })
        .unwrap_err();
        assert!(matches!(err, Error::InvalidParameter(0x400)));
        assert_eq!(t.reads, 0);
        assert!(t.writes.is_empty());
    }
    #[test]
    fn both_directions_are_target_driven_without_history() {
        let mut t = mock(0xffff);
        execute(&mut t, 0x9f, 0xfe24, |_| Ok::<_, ()>(())).unwrap();
        execute(&mut t, 0x9f, 0xffff, |_| Ok::<_, ()>(())).unwrap();
        assert_eq!(t.writes, [0xfe24, 0xffff]);
    }
    #[test]
    fn pretransfer_failure_restores_original() {
        let mut t = mock(0xffff);
        let err = execute(&mut t, 0x9f, 0xfe24, |_| Err::<(), _>("preflight")).unwrap_err();
        assert!(matches!(
            err,
            Error::Flash {
                rollback: Rollback::Restored,
                ..
            }
        ));
        assert_eq!(t.writes, [0xfe24, 0xffff]);
    }
    #[test]
    fn rejected_first_firmware_write_also_prohibits_rollback() {
        let mut t = mock(0xffff);
        let err = execute(&mut t, 0x9f, 0xfe24, |io| {
            io.exec(&[0x3b, 7, 0xfe, 0, 0, 0, 0, 0, 1, 0], Data::Out(&[1]))
        })
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Flash {
                rollback: Rollback::UnsafeAfterFirmwareWrite,
                ..
            }
        ));
        assert_eq!(t.writes, [0xfe24]);
        assert_eq!(t.firmware_attempts, 1);
    }
    #[test]
    fn unchanged_word_is_not_rewritten() {
        let mut t = mock(0xfe24);
        execute(&mut t, 0x9f, 0xfe24, |_| Ok::<_, ()>(())).unwrap();
        assert!(t.writes.is_empty());
    }

    #[test]
    fn unreadable_original_prevents_change_and_flash() {
        let mut t = mock(0xffff);
        t.fail_initial_read = true;
        let err = execute(&mut t, 0x9f, 0xfe24, |_| -> Result<(), &str> {
            panic!("flash must not run without original state")
        })
        .unwrap_err();
        assert!(format!("{err}").contains("A0 startup parameter read failed"));
        assert!(matches!(err, Error::Read(_)));
        assert!(t.writes.is_empty());
        assert_eq!(t.firmware_attempts, 0);
    }

    #[test]
    fn failed_restore_is_reported_without_retrying() {
        let mut t = mock(0xffff);
        t.fail_restore = true;
        let err = execute(&mut t, 0x9f, 0xfe24, |_| Err::<(), _>("preflight")).unwrap_err();
        assert!(matches!(
            err,
            Error::Flash {
                rollback: Rollback::Failed(_),
                ..
            }
        ));
        assert_eq!(t.word, 0xfe24);
        assert_eq!(t.writes, [0xfe24]);
        assert_eq!(t.firmware_attempts, 0);
    }

    #[test]
    fn uncertain_update_entry_also_prevents_restoration() {
        let mut t = mock(0xffff);
        let err = execute(&mut t, 0x9f, 0xfe24, |io| {
            io.exec(&[0x3b, 5, 0xff, 0, 0, 0, 0, 0, 0, 0], Data::Out(&[]))
        })
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Flash {
                rollback: Rollback::UnsafeAfterFirmwareWrite,
                ..
            }
        ));
        assert_eq!(t.writes, [0xfe24]);
        assert_eq!(t.firmware_attempts, 1);
    }
}

#[cfg(test)]
mod collection_tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    struct Mock {
        words: [u16; 2],
        log: Vec<(u8, usize, u16)>,
        fail_read: Option<usize>,
        fail_write: Option<usize>,
    }
    impl Transport for Mock {
        type Error = &'static str;
        fn exec(&mut self, c: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
            if c[2] != 0xa0 {
                self.log.push((0x3b, 99, 0));
                return Err("entry uncertain");
            }
            let offset = (usize::from(c[3]) << 16) | (usize::from(c[4]) << 8) | usize::from(c[5]);
            let index = offset / 2 - 0x9f;
            match data {
                Data::In(b) => {
                    self.log.push((0x3c, index, self.words[index]));
                    if self.fail_read == Some(index) {
                        return Err("read failed");
                    }
                    b.copy_from_slice(&self.words[index].to_be_bytes());
                    Ok(2)
                }
                Data::Out(b) => {
                    let v = u16::from_be_bytes(b.try_into().unwrap());
                    self.log.push((0x3b, index, v));
                    if self.fail_write == Some(index) {
                        self.fail_write = None;
                        return Err("write uncertain");
                    }
                    self.words[index] = v;
                    Ok(2)
                }
                _ => unreachable!(),
            }
        }
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
    }
    fn mock() -> Mock {
        Mock {
            words: [1, 2],
            log: vec![],
            fail_read: None,
            fail_write: None,
        }
    }
    #[test]
    fn validates_whole_plan_before_commands() {
        for plan in [vec![(0x9f, 3), (0x9f, 4)], vec![(0x9f, 3), (0x400, 4)]] {
            let mut m = mock();
            assert!(execute_many(&mut m, &plan, |_| Ok::<_, &str>(())).is_err());
            assert!(m.log.is_empty());
        }
    }
    #[test]
    fn reads_all_originals_before_first_write_and_verifies_each() {
        let mut m = mock();
        execute_many(&mut m, &[(0x9f, 3), (0xa0, 4)], |_| Ok::<_, &str>(())).unwrap();
        assert_eq!(
            m.log,
            vec![
                (0x3c, 0, 1),
                (0x3c, 1, 2),
                (0x3b, 0, 3),
                (0x3c, 0, 3),
                (0x3b, 1, 4),
                (0x3c, 1, 4)
            ]
        );
    }
    #[test]
    fn late_initial_read_failure_sends_no_writes() {
        let mut m = mock();
        m.fail_read = Some(1);
        assert!(execute_many(&mut m, &[(0x9f, 3), (0xa0, 4)], |_| Ok::<_, &str>(())).is_err());
        assert!(m.log.iter().all(|e| e.0 == 0x3c));
    }
    #[test]
    fn partial_change_rolls_back_in_reverse_order_without_flash() {
        let mut m = mock();
        m.fail_write = Some(1);
        assert!(
            execute_many(&mut m, &[(0x9f, 3), (0xa0, 4)], |_| -> Result<(), &str> {
                panic!("must not flash")
            })
            .is_err()
        );
        assert_eq!(m.words, [1, 2]);
        let writes: Vec<_> = m.log.iter().filter(|e| e.0 == 0x3b).copied().collect();
        assert_eq!(
            writes,
            vec![(0x3b, 0, 3), (0x3b, 1, 4), (0x3b, 1, 2), (0x3b, 0, 1)]
        );
    }
    #[test]
    fn callback_preflight_failure_restores_all_changed_words() {
        let mut m = mock();
        assert!(execute_many(&mut m, &[(0x9f, 3), (0xa0, 4)], |_| Err::<(), _>("policy")).is_err());
        assert_eq!(m.words, [1, 2]);
    }
    #[test]
    fn uncertain_firmware_entry_forbids_any_rollback() {
        let mut m = mock();
        let err = execute_many(&mut m, &[(0x9f, 3), (0xa0, 4)], |t| {
            t.exec(&[0x3b, 0, 0xfe], Data::None)
        })
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Flash {
                rollback: Rollback::UnsafeAfterFirmwareWrite,
                ..
            }
        ));
        assert_eq!(m.words, [3, 4]);
        assert_eq!(m.log.last(), Some(&(0x3b, 99, 0)));
    }
}
