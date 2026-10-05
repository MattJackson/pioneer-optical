//! Transport abstraction for the high-level [`flash`](crate::flash) API.
//!
//! A flasher implements [`Transport`] over whatever SCSI pass-through it has
//! (SG_IO on Linux, SPTI on Windows, libusb, a test mock…) and then hands the
//! transport to the drive-generic [`crate::flash`] helpers — which issue every
//! vendor CDB on the caller's behalf. The flasher never touches raw CDB bytes.
//!
//! Only available with the non-default `highlevel` feature.

/// Which direction (if any) a SCSI command's data phase runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferDir {
    /// No data phase (e.g. the read-unlock knock, kernel-mode arm).
    None,
    /// Device-to-host: the drive fills `buf` with up to `buf.len()` bytes.
    DataIn,
    /// Host-to-device: the drive consumes `buf.len()` bytes from `buf`.
    DataOut,
}

/// SCSI pass-through used by the high-level [`flash`](crate::flash) API.
///
/// Implementors run one CDB per [`exec`](Transport::exec) call and surface the
/// drive's sense data (when the command produced any) via
/// [`sense`](Transport::sense) so the crate can distinguish the vendor
/// `05/24/00` "locked / unsupported" refusal from other failures.
///
/// The caller sizes `buf`. For [`TransferDir::DataIn`] it is the receive
/// buffer; for [`TransferDir::DataOut`] it holds the bytes to send; for
/// [`TransferDir::None`] it is ignored (pass `&mut []`).
pub trait Transport {
    /// Transport-specific error type (SG_IO error, OS error, mock failure…).
    type Error: core::fmt::Debug;

    /// Execute one CDB. Returns the number of bytes actually transferred
    /// (for `DataIn`/`DataOut`) or `0` for `None`.
    fn exec(&mut self, cdb: &[u8], dir: TransferDir, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Sense (`key`, `asc`, `ascq`) from the most recent command, if any.
    ///
    /// Returning `Some((0x05, 0x24, 0x00))` after an `exec` error lets
    /// [`flash`](crate::flash) report [`crate::flash::FlashError::Locked`]
    /// instead of an opaque transport error.
    fn sense(&self) -> Option<(u8, u8, u8)>;
}
