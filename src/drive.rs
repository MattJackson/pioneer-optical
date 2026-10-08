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

mod update;
pub use update::{execute_update, UpdateError, UpdateOptions, UpdateRuntime, UpdateTransfer};

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
/// Component transfers may already program flash before [`finish`](Self::finish).
/// Dropping the session sends nothing and does not roll back earlier writes.
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
#[path = "drive_tests.rs"]
mod tests;
