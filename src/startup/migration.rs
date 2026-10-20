//! Attempt-local parameter migration. No history files or saved defaults.
//! Call only after proving the current firmware's A0 word-write contract and
//! deriving the target value. This API does not turn a detector miss into FFFF.
use crate::drive::{self, Data, Transport};

/// Result of an attempted rollback before any firmware write was attempted.
#[derive(Debug)]
pub enum Rollback<E> {
    /// The original word was restored and read back.
    Restored,
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
            Self::Restored=>f.write_str("the original startup setting was restored and verified"),
            Self::Unchanged=>f.write_str("the startup setting was unchanged"),
            Self::UnsafeAfterFirmwareWrite=>f.write_str("update commands were attempted; the target startup setting was retained because the installed firmware state is uncertain. Do not automatically repeat the flash"),
            Self::Failed(e)=>write!(f,"the original startup setting could not be restored or verified: {e}; save the diagnostic log before another attempt"),
        }
    }
}

impl<E: core::fmt::Debug, F: core::fmt::Debug> core::fmt::Display for Error<E, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Preflight(source)=>write!(f,"update preflight refused before changing startup settings or firmware: {source:?}"),
            Self::InvalidParameter(p)=>write!(f,"startup parameter {p:#x} is outside the supported parameter surface; no command was sent"),
            Self::Read(e)=>write!(f,"unable to read the current startup setting; firmware flashing did not begin: {e}"),
            Self::Change{source,rollback,..}=>write!(f,"unable to change and verify the startup setting; firmware flashing did not begin: {source}; {rollback}"),
            Self::Flash{source,rollback,..}=>write!(f,"firmware update failed: {source:?}; {rollback}"),
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
            Self::InvalidParameter(_) => None,
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
/// use a transport which never retries writes. The caller must establish A0
/// support and target semantics first. There is no model table or default-value
/// inference here. Original state stays in RAM and is discarded on success.
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
        let err = execute(&mut t, 0x9f, 0xfe24, |_| -> Result<(), ()> {
            panic!("flash must not run")
        })
        .unwrap_err();
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
        let err = execute(&mut t, 0x9f, 0xfe24, |_| -> Result<(), ()> {
            panic!("flash must not run without original state")
        })
        .unwrap_err();
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
