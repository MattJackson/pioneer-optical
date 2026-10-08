//! Command sequences over a caller-supplied [`Transport`]: identify, protected
//! memory read, and the update session.
//!
//! ```no_run
//! # use pioneer_optical::{drive, Role};
//! # fn run<T: drive::Transport>(t: &mut T, control: &drive::Control, kernel: &[u8], normal: &[u8])
//! #     -> Result<(), drive::Error<T::Error>> {
//! let id = drive::identify(t)?;
//! let class = id.class().ok_or(drive::Error::UnknownClass)?;
//! let mut session = drive::enter_update(t, class, control)?;
//! session.write(Role::Kernel, 0, kernel)?;
//! session.write(Role::Normal, 0, normal)?;
//! session.finish()?;
//! # Ok(()) }
//! ```
//!
//! Requires the `drive` feature.

use crate::cdb::{self, CONTROL_LEN, DVR_CHALLENGE_LEN};
use crate::{DriveClass, Identity, Role, IDENTITY_LEN, INQUIRY_LEN};

/// The control buffer carried by [`cdb::enter_update`] and [`cdb::finish`].
pub type Control = [u8; CONTROL_LEN as usize];

/// Largest offset or length a vendor CDB can encode (24 bits).
const FIELD_MAX: usize = 0xFF_FFFF;

/// The data phase of one command.
#[derive(Debug)]
pub enum Data<'a> {
    /// No data phase.
    None,
    /// Device to host: the drive fills up to `len()` bytes.
    In(&'a mut [u8]),
    /// Host to device: the drive receives every byte.
    Out(&'a [u8]),
}

/// A SCSI pass-through.
pub trait Transport {
    /// Transport error.
    type Error: core::fmt::Debug;

    /// Execute one CDB. Returns the number of bytes transferred (`0` for
    /// [`Data::None`]).
    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, Self::Error>;

    /// Sense `(key, asc, ascq)` of the most recent failed command, if any.
    fn sense(&self) -> Option<(u8, u8, u8)>;
}

/// Errors from the command sequences.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error<E> {
    /// The transport failed.
    Transport(E),
    /// The drive refused with `05/24/00` (see [`crate::sense::is_locked`]).
    Locked,
    /// The drive returned fewer bytes than required.
    Short {
        /// Bytes required.
        expected: usize,
        /// Bytes received.
        actual: usize,
    },
    /// A command completed, but the live value did not match the requested value.
    ReadbackMismatch {
        /// Requested value.
        expected: u32,
        /// Value returned by the drive.
        actual: u32,
    },
    /// An offset or length does not fit the 24-bit CDB field.
    Oversize(usize),
    /// The DVR challenge has no solution.
    Challenge,
    /// The identity matches no [`DriveClass`].
    UnknownClass,
}

#[cfg(feature = "std")]
impl<E: core::fmt::Debug> std::error::Error for Error<E> {}

impl<E: core::fmt::Debug> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {e:?}"),
            Self::Locked => f.write_str("drive refused the command (sense 05/24/00)"),
            Self::Short { expected, actual } => {
                write!(f, "short transfer: expected {expected} bytes, got {actual}")
            }
            Self::ReadbackMismatch { expected, actual } => write!(
                f,
                "readback mismatch: expected {expected:#010x}, got {actual:#010x}"
            ),
            Self::Oversize(n) => write!(f, "{n:#x} exceeds the 24-bit CDB field"),
            Self::Challenge => f.write_str("DVR challenge has no solution"),
            Self::UnknownClass => f.write_str("drive identity matches no known class"),
        }
    }
}

/// Execute `cdb`, mapping a `05/24/00` refusal to [`Error::Locked`].
fn exec<T: Transport>(t: &mut T, cdb: &[u8], data: Data<'_>) -> Result<usize, Error<T::Error>> {
    t.exec(cdb, data).map_err(|e| match t.sense() {
        Some((k, a, q)) if crate::sense::is_locked(k, a, q) => Error::Locked,
        _ => Error::Transport(e),
    })
}

/// Execute a data-in `cdb` that must return at least `min` bytes.
pub(crate) fn read<T: Transport>(
    t: &mut T,
    cdb: &[u8],
    buf: &mut [u8],
    min: usize,
) -> Result<usize, Error<T::Error>> {
    let n = exec(t, cdb, Data::In(buf))?.min(buf.len());
    if n < min {
        return Err(Error::Short {
            expected: min,
            actual: n,
        });
    }
    Ok(n)
}

/// Execute a data-out `cdb` that must transfer every byte of `data`.
pub(crate) fn write<T: Transport>(
    t: &mut T,
    cdb: &[u8],
    data: &[u8],
) -> Result<(), Error<T::Error>> {
    let n = exec(t, cdb, Data::Out(data))?;
    if n < data.len() {
        return Err(Error::Short {
            expected: data.len(),
            actual: n,
        });
    }
    Ok(())
}

fn field<E>(n: usize) -> Result<u32, Error<E>> {
    if n > FIELD_MAX {
        return Err(Error::Oversize(n));
    }
    Ok(n as u32)
}

/// Read the drive's [`Identity`] (INQUIRY and vendor identity). Changes no
/// drive state.
pub fn identify<T: Transport>(t: &mut T) -> Result<Identity, Error<T::Error>> {
    let mut inquiry = [0; INQUIRY_LEN];
    read(
        t,
        &cdb::inquiry(INQUIRY_LEN as u8),
        &mut inquiry,
        INQUIRY_LEN,
    )?;
    let mut vendor = [0; IDENTITY_LEN];
    let n = read(t, &cdb::vendor_identity(), &mut vendor, crate::IDENTITY_MIN)?;
    Identity::parse(&inquiry, &vendor[..n]).ok_or(Error::Short {
        expected: crate::IDENTITY_MIN,
        actual: n,
    })
}

/// Enable extended read, then read `buf.len()` bytes of drive memory at `off`.
/// Returns the number of bytes read (at most `buf.len()`). Fails with
/// [`Error::Oversize`] when `off` or `buf.len()` does not fit the 24-bit CDB
/// field.
pub fn read_memory<T: Transport>(
    t: &mut T,
    off: u32,
    buf: &mut [u8],
) -> Result<usize, Error<T::Error>> {
    let len = field(buf.len())?;
    field::<T::Error>(off as usize)?;
    exec(t, &cdb::knock(), Data::None)?;
    let blen = buf.len();
    let n = exec(t, &cdb::read_memory(off, len), Data::In(buf))?;
    Ok(n.min(blen))
}

/// An open update session, returned by [`enter_update`].
///
/// [`finish`](Self::finish) commits the update. Dropping the session without
/// finishing sends nothing; the drive stays in the update session.
pub struct Session<'a, T: Transport> {
    t: &'a mut T,
    control: &'a Control,
}

impl<T: Transport> core::fmt::Debug for Session<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

impl<T: Transport> Session<'_, T> {
    /// Write `data` as the chunk of the `role` component at byte offset `off`
    /// within the component. Both `off` and `data.len()` must fit in 24 bits.
    pub fn write(&mut self, role: Role, off: u32, data: &[u8]) -> Result<(), Error<T::Error>> {
        let len = field(data.len())?;
        field::<T::Error>(off as usize)?;
        write(self.t, &cdb::transfer(role, off, len), data)
    }

    /// Commit the update with the session's control buffer.
    pub fn finish(self) -> Result<(), Error<T::Error>> {
        write(self.t, &cdb::finish(), self.control)
    }
}

/// Enter the update session with `control`. On [`DriveClass::Dvr`] the
/// [`crate::dvr`] handshake runs first.
pub fn enter_update<'a, T: Transport>(
    t: &'a mut T,
    class: DriveClass,
    control: &'a Control,
) -> Result<Session<'a, T>, Error<T::Error>> {
    if class == DriveClass::Dvr {
        exec(t, &cdb::dvr_arm(), Data::None)?;
        let mut challenge = [0; DVR_CHALLENGE_LEN as usize];
        read(t, &cdb::dvr_challenge(), &mut challenge, 4)?;
        let response = crate::dvr::solve(&challenge).ok_or(Error::Challenge)?;
        write(t, &cdb::dvr_response(), &response)?;
    }
    write(t, &cdb::enter_update(), control)?;
    Ok(Session { t, control })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Records every command; answers data-in from a FIFO of responses.
    #[derive(Default)]
    struct Mock {
        calls: Vec<(Vec<u8>, char, Vec<u8>)>,
        responses: Vec<Vec<u8>>,
        locked: bool,
    }

    impl Transport for Mock {
        type Error = ();
        fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, ()> {
            if self.locked {
                return Err(());
            }
            let (dir, bytes, n) = match data {
                Data::None => ('-', Vec::new(), 0),
                Data::Out(b) => ('>', b.to_vec(), b.len()),
                Data::In(b) => {
                    let r = if self.responses.is_empty() {
                        Vec::new()
                    } else {
                        self.responses.remove(0)
                    };
                    let n = r.len().min(b.len());
                    b[..n].copy_from_slice(&r[..n]);
                    ('<', Vec::new(), n)
                }
            };
            self.calls.push((cdb.to_vec(), dir, bytes));
            Ok(n)
        }
        fn sense(&self) -> Option<(u8, u8, u8)> {
            self.locked.then_some((0x05, 0x24, 0x00))
        }
    }

    impl Mock {
        fn cdbs(&self) -> Vec<(Vec<u8>, char)> {
            self.calls.iter().map(|c| (c.0.clone(), c.1)).collect()
        }
    }

    /// Reports more bytes than it was given.
    struct Liar;
    impl Transport for Liar {
        type Error = ();
        fn exec(&mut self, _: &[u8], _: Data<'_>) -> Result<usize, ()> {
            Ok(0x1000)
        }
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
    }

    #[test]
    fn reported_length_is_clamped_to_the_buffer() {
        // Identity is all zeros, so parse succeeds without panicking.
        assert!(identify(&mut Liar).is_ok());
        let mut buf = [0u8; 8];
        assert_eq!(read_memory(&mut Liar, 0, &mut buf).unwrap(), 8);
    }

    #[test]
    fn read_memory_rejects_offsets_beyond_24_bits() {
        let mut m = Mock::default();
        let mut buf = [0u8; 4];
        assert!(matches!(
            read_memory(&mut m, 0x0100_0000, &mut buf),
            Err(Error::Oversize(0x0100_0000))
        ));
        assert!(m.calls.is_empty());
        assert!(read_memory(&mut m, 0x00FF_FFFF, &mut buf).is_ok());
    }

    #[test]
    fn bd_session_sequence_carries_the_control_buffer() {
        let control = [0x5A; CONTROL_LEN as usize];
        let mut m = Mock::default();
        let mut s = enter_update(&mut m, DriveClass::Bd, &control).unwrap();
        s.write(Role::Kernel, 0, &[1, 2, 3, 4]).unwrap();
        s.write(Role::Normal, 0x8000, &[5, 6]).unwrap();
        s.finish().unwrap();
        assert_eq!(
            m.cdbs(),
            [
                (cdb::enter_update().to_vec(), '>'),
                (cdb::transfer(Role::Kernel, 0, 4).to_vec(), '>'),
                (cdb::transfer(Role::Normal, 0x8000, 2).to_vec(), '>'),
                (cdb::finish().to_vec(), '>'),
            ]
        );
        assert_eq!(m.calls[0].2, control);
        assert_eq!(m.calls[1].2, [1, 2, 3, 4]);
        assert_eq!(m.calls[3].2, control);
    }

    #[test]
    fn dropped_session_sends_nothing() {
        let control = [0; CONTROL_LEN as usize];
        let mut m = Mock::default();
        enter_update(&mut m, DriveClass::Bd, &control).unwrap();
        assert_eq!(m.calls.len(), 1);
    }

    #[test]
    fn dvr_handshake_precedes_entry() {
        let control = [0; CONTROL_LEN as usize];
        let challenge = crate::dvr::challenge(0x1234);
        let mut m = Mock {
            responses: std::vec![challenge.to_vec()],
            ..Mock::default()
        };
        enter_update(&mut m, DriveClass::Dvr, &control).unwrap();
        assert_eq!(
            m.cdbs(),
            [
                (cdb::dvr_arm().to_vec(), '-'),
                (cdb::dvr_challenge().to_vec(), '<'),
                (cdb::dvr_response().to_vec(), '>'),
                (cdb::enter_update().to_vec(), '>'),
            ]
        );
        assert_eq!(m.calls[2].2, crate::dvr::solve(&challenge).unwrap());
    }

    #[test]
    fn read_memory_knocks_first() {
        let mut m = Mock {
            responses: std::vec![std::vec![7; 0x10]],
            ..Mock::default()
        };
        let mut buf = [0; 0x10];
        assert_eq!(read_memory(&mut m, 0x1234, &mut buf).unwrap(), 0x10);
        assert_eq!(
            m.cdbs(),
            [
                (cdb::knock().to_vec(), '-'),
                (cdb::read_memory(0x1234, 0x10).to_vec(), '<')
            ]
        );
        assert_eq!(buf, [7; 0x10]);
    }

    #[test]
    fn identify_parses_and_checks_length() {
        let mut inq = std::vec![b' '; INQUIRY_LEN];
        inq[16..32].copy_from_slice(b"BD-RW   BDR-UD04");
        let mut m = Mock {
            responses: std::vec![inq.clone(), std::vec![b' '; 48]],
            ..Mock::default()
        };
        assert_eq!(identify(&mut m).unwrap().class(), Some(DriveClass::Bd));
        let mut m = Mock {
            responses: std::vec![inq, std::vec![0; 20]],
            ..Mock::default()
        };
        assert!(matches!(
            identify(&mut m),
            Err(Error::Short {
                expected: crate::IDENTITY_MIN,
                actual: 20
            })
        ));
    }

    #[test]
    fn locked_sense_and_oversize() {
        let control = [0; CONTROL_LEN as usize];
        let mut m = Mock {
            locked: true,
            ..Mock::default()
        };
        assert!(matches!(
            enter_update(&mut m, DriveClass::Bd, &control),
            Err(Error::Locked)
        ));
        let mut m = Mock::default();
        let mut s = enter_update(&mut m, DriveClass::Bd, &control).unwrap();
        assert!(matches!(
            s.write(Role::Normal, 0x100_0000, &[0]),
            Err(Error::Oversize(_))
        ));
    }

    /// Returns a configurable byte count and sense.
    struct Fixed {
        n: usize,
        sense: Option<(u8, u8, u8)>,
        fail: bool,
    }
    impl Transport for Fixed {
        type Error = u8;
        fn exec(&mut self, _: &[u8], _: Data<'_>) -> Result<usize, u8> {
            if self.fail {
                Err(9)
            } else {
                Ok(self.n)
            }
        }
        fn sense(&self) -> Option<(u8, u8, u8)> {
            self.sense
        }
    }

    #[test]
    fn write_requires_every_byte_transferred() {
        let control = [0; CONTROL_LEN as usize];
        // Exactly the data length: ok. More than asked: still ok.
        for n in [4, 5] {
            let mut t = Fixed {
                n,
                sense: None,
                fail: false,
            };
            let mut s = Session {
                t: &mut t,
                control: &control,
            };
            s.write(Role::Kernel, 0, &[1, 2, 3, 4]).unwrap();
        }
        // Fewer: Short with exact counts.
        let mut t = Fixed {
            n: 3,
            sense: None,
            fail: false,
        };
        let mut s = Session {
            t: &mut t,
            control: &control,
        };
        assert!(matches!(
            s.write(Role::Kernel, 0, &[1, 2, 3, 4]),
            Err(Error::Short {
                expected: 4,
                actual: 3
            })
        ));
    }

    #[test]
    fn field_limit_is_inclusive() {
        let control = [0; CONTROL_LEN as usize];
        let mut t = Fixed {
            n: 1,
            sense: None,
            fail: false,
        };
        let mut s = Session {
            t: &mut t,
            control: &control,
        };
        s.write(Role::Normal, 0xFF_FFFF, &[0]).unwrap();
        assert!(matches!(
            s.write(Role::Normal, 0x100_0000, &[0]),
            Err(Error::Oversize(0x100_0000))
        ));
    }

    #[test]
    fn only_the_lock_sense_maps_to_locked() {
        let mut buf = [0u8; 4];
        let mut t = Fixed {
            n: 0,
            sense: Some((0x05, 0x24, 0x00)),
            fail: true,
        };
        assert!(matches!(
            read_memory(&mut t, 0, &mut buf),
            Err(Error::Locked)
        ));
        for sense in [None, Some((0x05, 0x20, 0x00)), Some((0x02, 0x24, 0x00))] {
            let mut t = Fixed {
                n: 0,
                sense,
                fail: true,
            };
            assert!(matches!(
                read_memory(&mut t, 0, &mut buf),
                Err(Error::Transport(9))
            ));
        }
    }

    #[test]
    fn display_and_debug_text() {
        use std::string::ToString;
        type E = Error<u8>;
        assert_eq!(E::Transport(7).to_string(), "transport error: 7");
        assert_eq!(
            E::Locked.to_string(),
            "drive refused the command (sense 05/24/00)"
        );
        assert_eq!(
            E::Short {
                expected: 4,
                actual: 3
            }
            .to_string(),
            "short transfer: expected 4 bytes, got 3"
        );
        assert_eq!(
            E::Oversize(0x100_0000).to_string(),
            "0x1000000 exceeds the 24-bit CDB field"
        );
        assert_eq!(E::Challenge.to_string(), "DVR challenge has no solution");
        assert_eq!(
            E::UnknownClass.to_string(),
            "drive identity matches no known class"
        );
        let control = [0; CONTROL_LEN as usize];
        let mut t = Fixed {
            n: 0,
            sense: None,
            fail: false,
        };
        let s = Session {
            t: &mut t,
            control: &control,
        };
        assert_eq!(std::format!("{s:?}"), "Session { .. }");
    }
}
