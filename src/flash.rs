//! Drive-generic flash API — the one a flasher calls.
//!
//! A thin, drive-aware layer over the raw CDB catalogue at the crate root.
//! Callers hand it a [`Transport`] and this module issues every vendor CDB on
//! their behalf: identify the drive, enter the OEM update ("kernel-mode")
//! session, stream Kernel/Normal chunks, commit, and release.
//!
//! ```text
//! let id = flash::Drive::identify(&mut t)?;
//! let mut sess = flash::enter_kernel_mode(&mut t, id.class())?;
//! sess.write_kernel(0, &kernel_bytes)?;
//! sess.write_normal(0, &normal_bytes)?;
//! sess.finish()?;
//! ```
//!
//! ## What "kernel mode" means here
//! Throughout this crate "kernel mode" is the **OEM update session** entered by
//! `3B 04 FF` ([`crate::enter_update`]). It is the state in which the drive
//! will accept Kernel (`07/FE`) and Normal (`07/F0`) chunk writes and the
//! `3B 05 FF` commit ([`crate::finish`]).
//!
//! The three `F3`/`F2`/`F2` CDBs in [`crate::kernel_mode`] are the **DVR-era
//! handshake** that precedes `3B 04 FF` on drive generations that implement
//! it. On BD generations (verified by direct disassembly of BDR-UD04 /
//! `SAT 8A10` Normal bodies) those CDBs are inert — the handlers are
//! phase-gated and set a single RAM flag; no LCG is called from them; the
//! challenge-response model does not exist — so BD enters the update session
//! with `3B 04 FF` alone.
//!
//! ## DVR path is experimental
//! The DVR challenge-response path in [`enter_kernel_mode`] is **unverified on
//! hardware** at the time of this release. The math (seed brute-force and
//! response byte) in [`crate::kernel_mode`] is the one from the reverse-engineered
//! handshake, but no DVR unit has been exercised end-to-end through this crate.
//!
//! Only available with the non-default `highlevel` feature.

extern crate alloc;

use alloc::vec;

use crate::transport::{TransferDir, Transport};
use crate::{CONTROL_LEN, IDENTITY_LEN};

/// Trim trailing ASCII spaces/NULs and interpret as UTF-8.
fn trim(raw: &[u8]) -> &str {
    let end = raw
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map_or(0, |i| i + 1);
    core::str::from_utf8(&raw[..end]).unwrap_or("")
}

/// Which Pioneer drive dialect a given unit speaks.
///
/// Chosen by [`Identity::class`] from the INQUIRY product id and the vendor
/// identity's platform code (e.g. `SAT 8A10`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriveClass {
    /// BD generations (BDR-\*) — enter the update session with `3B 04 FF`.
    Bd,
    /// DVR generations (DVR-\*) — perform the F3/F2/F2 handshake first.
    Dvr,
}

/// Errors from the high-level flash API.
#[derive(Debug)]
pub enum FlashError<E: core::fmt::Debug> {
    /// The underlying [`Transport`] returned an error.
    Transport(E),
    /// The drive refused the CDB with sense `05/24/00` — the vendor
    /// "locked / wrong state / unsupported on this platform" response.
    Locked,
    /// The drive returned fewer bytes than expected for a fixed-size read.
    Short {
        /// How many bytes were expected.
        expected: usize,
        /// How many bytes were actually received.
        actual: usize,
    },
    /// The DVR challenge did not reduce to a valid LCG seed.
    SolveFailed,
}

impl<E: core::fmt::Debug> core::fmt::Display for FlashError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {:?}", e),
            Self::Locked => write!(f, "drive refused the command (sense 05/24/00)"),
            Self::Short { expected, actual } => {
                write!(f, "short transfer: expected {}, got {}", expected, actual)
            }
            Self::SolveFailed => write!(f, "could not recover DVR kernel-mode seed"),
        }
    }
}

/// Internal: run a CDB and promote a `05/24/00` sense to [`FlashError::Locked`].
fn exec<T: Transport>(
    t: &mut T,
    cdb: &[u8],
    dir: TransferDir,
    buf: &mut [u8],
) -> Result<usize, FlashError<T::Error>> {
    match t.exec(cdb, dir, buf) {
        Ok(n) => Ok(n),
        Err(e) => {
            if let Some((k, a, q)) = t.sense() {
                if crate::sense::is_locked(k, a, q) {
                    return Err(FlashError::Locked);
                }
            }
            Err(FlashError::Transport(e))
        }
    }
}

/// INQUIRY + vendor identity, together.
///
/// Owned (no borrows) so the identification call site can return it from a
/// scope without the response buffers escaping.
#[derive(Clone, Debug)]
pub struct Identity {
    inq: [u8; 36],
    vid: [u8; IDENTITY_LEN as usize],
}

impl Identity {
    /// INQUIRY vendor id, trimmed (e.g. `PIONEER`).
    pub fn vendor(&self) -> &str {
        trim(&self.inq[8..16])
    }
    /// INQUIRY product id, trimmed (e.g. `BD-RW   BDR-UD04`).
    pub fn product(&self) -> &str {
        trim(&self.inq[16..32])
    }
    /// INQUIRY product revision, trimmed (e.g. `1.14`).
    pub fn revision(&self) -> &str {
        trim(&self.inq[32..36])
    }
    /// Vendor identity serial (e.g. `QHDL433450WL`).
    pub fn serial(&self) -> &str {
        trim(&self.vid[0..16])
    }
    /// Vendor identity platform (e.g. `SAT 8A10`). Vendor-identity bytes
    /// `0x10..0x18` of the `3C 02 F1` response — the hardware/SAT tag.
    pub fn platform(&self) -> &str {
        trim(&self.vid[16..24])
    }
    /// Installed-Kernel ID tag (e.g. `ID58`). Vendor-identity bytes
    /// `0x18..0x20` of the `3C 02 F1` response. OEM updaters compare this,
    /// byte-for-byte, against a Normal envelope's `Kernel Version` header
    /// field: equality means the installed Kernel is the ABI generation this
    /// Normal expects, so a Normal-only flash is safe; mismatch means a
    /// Normal-only flash will land on the wrong Kernel and the OEM updater
    /// refuses it with "Model name of kernel part is not matched."
    pub fn kernel_tag(&self) -> &str {
        trim(&self.vid[24..32])
    }
    /// Installed-Normal ID tag (e.g. `ID58`). Vendor-identity bytes
    /// `0x20..0x28` of the `3C 02 F1` response. 8 ASCII spaces when the
    /// drive is already in kernel/update mode. OEM updaters compare this
    /// against a Normal envelope's `Destination` header field.
    pub fn normal_tag(&self) -> &str {
        trim(&self.vid[32..40])
    }
    /// Raw 48-byte vendor identity block (serial / platform / kernel / normal / code).
    pub fn vendor_identity_bytes(&self) -> &[u8; IDENTITY_LEN as usize] {
        &self.vid
    }
    /// Raw 36-byte INQUIRY response.
    pub fn inquiry_bytes(&self) -> &[u8; 36] {
        &self.inq
    }

    /// Infer the drive dialect from product id and platform.
    ///
    /// Rules:
    /// - product starts with `BD-` → [`DriveClass::Bd`]
    /// - product starts with `DVD-R` *and* platform starts with `DVR`
    ///   → [`DriveClass::Dvr`]
    /// - otherwise (conservative fallback) → [`DriveClass::Bd`]
    pub fn class(&self) -> DriveClass {
        let product = self.product();
        let platform = self.platform();
        if product.starts_with("BD-") {
            DriveClass::Bd
        } else if product.starts_with("DVD-R") && platform.starts_with("DVR") {
            DriveClass::Dvr
        } else {
            DriveClass::Bd
        }
    }
}

/// Entry point for drive identification.
pub struct Drive;

impl Drive {
    /// Issue INQUIRY and the vendor identity read and wrap both bytes in an
    /// [`Identity`]. Makes no state-changing calls.
    pub fn identify<T: Transport>(t: &mut T) -> Result<Identity, FlashError<T::Error>> {
        let mut inq = [0u8; 36];
        let cdb = crate::inquiry(36);
        let n = exec(t, &cdb, TransferDir::DataIn, &mut inq)?;
        if n < 36 {
            return Err(FlashError::Short {
                expected: 36,
                actual: n,
            });
        }
        let mut vid = [0u8; IDENTITY_LEN as usize];
        let cdb = crate::vendor_identity();
        let n = exec(t, &cdb, TransferDir::DataIn, &mut vid)?;
        if n < 44 {
            return Err(FlashError::Short {
                expected: 48,
                actual: n,
            });
        }
        Ok(Identity { inq, vid })
    }
}

/// An open OEM update session.
///
/// Returned by [`enter_kernel_mode`]. Dropping it without calling
/// [`finish`](Self::finish) issues `3B 05 FF` once as a best-effort release so
/// the drive is not left stuck mid-update; any error from that release is
/// swallowed (callers who care should use [`finish`](Self::finish) explicitly).
pub struct KernelSession<'t, T: Transport> {
    t: &'t mut T,
    finished: bool,
}

impl<'t, T: Transport> KernelSession<'t, T> {
    /// Write a Kernel-component chunk (`3B 07 FE`).
    pub fn write_kernel(&mut self, offset: u32, data: &[u8]) -> Result<(), FlashError<T::Error>> {
        let cdb = crate::transfer_kernel(offset, data.len() as u32);
        let mut tmp = data.to_vec();
        let n = exec(self.t, &cdb, TransferDir::DataOut, &mut tmp)?;
        if n < data.len() {
            return Err(FlashError::Short {
                expected: data.len(),
                actual: n,
            });
        }
        Ok(())
    }

    /// Write a Normal-component chunk (`3B 07 F0`).
    pub fn write_normal(&mut self, offset: u32, data: &[u8]) -> Result<(), FlashError<T::Error>> {
        let cdb = crate::transfer_normal(offset, data.len() as u32);
        let mut tmp = data.to_vec();
        let n = exec(self.t, &cdb, TransferDir::DataOut, &mut tmp)?;
        if n < data.len() {
            return Err(FlashError::Short {
                expected: data.len(),
                actual: n,
            });
        }
        Ok(())
    }

    /// Commit the update (`3B 05 FF`) and close the session.
    pub fn finish(mut self) -> Result<(), FlashError<T::Error>> {
        let cdb = crate::finish();
        let mut tmp = vec![0u8; CONTROL_LEN as usize];
        let _ = exec(self.t, &cdb, TransferDir::DataOut, &mut tmp)?;
        self.finished = true;
        Ok(())
    }
}

impl<'t, T: Transport> Drop for KernelSession<'t, T> {
    fn drop(&mut self) {
        if !self.finished {
            let cdb = crate::finish();
            let mut tmp = vec![0u8; CONTROL_LEN as usize];
            let _ = self.t.exec(&cdb, TransferDir::DataOut, &mut tmp);
        }
    }
}

/// Enter the OEM update session ("kernel mode"), performing the DVR F3/F2/F2
/// challenge-response first when `class` is [`DriveClass::Dvr`].
///
/// - [`DriveClass::Bd`]: issues `3B 04 FF` ([`crate::enter_update`]) alone.
/// - [`DriveClass::Dvr`]: issues `3B 01 F3` (arm) → `3C 01 F2` (read challenge)
///   → `3B 01 F2` (write response, bytes from [`crate::kernel_mode::solve`])
///   → `3B 04 FF`. **Experimental** — the handshake math is correct per the
///   reverse-engineered DVR firmware but has not been exercised end-to-end on
///   hardware through this crate.
pub fn enter_kernel_mode<T: Transport>(
    t: &mut T,
    class: DriveClass,
) -> Result<KernelSession<'_, T>, FlashError<T::Error>> {
    if class == DriveClass::Dvr {
        // DVR handshake. The three CDBs are deprecated at the catalogue level
        // (they are legal to issue, but callers should not reach for them
        // directly) — the handshake belongs here.
        #[allow(deprecated)]
        {
            let arm = crate::kernel_mode_arm();
            exec(t, &arm, TransferDir::None, &mut [])?;

            let chal_cdb = crate::kernel_mode_challenge();
            let mut challenge = vec![0u8; crate::KERNEL_CHALLENGE_LEN as usize];
            let n = exec(t, &chal_cdb, TransferDir::DataIn, &mut challenge)?;
            if n < 4 {
                return Err(FlashError::Short {
                    expected: 4,
                    actual: n,
                });
            }

            let solution = crate::kernel_mode::solve(&challenge).ok_or(FlashError::SolveFailed)?;

            let resp_cdb = crate::kernel_mode_response();
            let mut resp = solution.response.to_vec();
            exec(t, &resp_cdb, TransferDir::DataOut, &mut resp)?;
        }
    }

    let cdb = crate::enter_update();
    let mut tmp = vec![0u8; CONTROL_LEN as usize];
    let _ = exec(t, &cdb, TransferDir::DataOut, &mut tmp)?;
    Ok(KernelSession { t, finished: false })
}

/// Read `len` bytes from drive memory at `off`, performing the read-unlock
/// knock (`3B 02 41`) first.
///
/// `buf` must be at least `len` bytes. Returns the number of bytes actually
/// returned by the drive.
pub fn read_memory<T: Transport>(
    t: &mut T,
    off: u32,
    len: u32,
    buf: &mut [u8],
) -> Result<usize, FlashError<T::Error>> {
    let knock = crate::knock();
    exec(t, &knock, TransferDir::None, &mut [])?;
    let cdb = crate::read_memory(off, len);
    exec(t, &cdb, TransferDir::DataIn, buf)
}

/// Read the 48-byte vendor identity block (`3C 02 F1`).
///
/// Returned by value so the bytes outlive the transport call; parse with
/// [`crate::response::VendorIdentity::parse`]. Deviates from the design-doc
/// signature `response::VendorIdentity<'_>` because the parser borrows its
/// backing buffer and the buffer must be owned somewhere.
pub fn vendor_identity<T: Transport>(
    t: &mut T,
) -> Result<[u8; IDENTITY_LEN as usize], FlashError<T::Error>> {
    let mut out = [0u8; IDENTITY_LEN as usize];
    let cdb = crate::vendor_identity();
    let n = exec(t, &cdb, TransferDir::DataIn, &mut out)?;
    if n < 44 {
        return Err(FlashError::Short {
            expected: 48,
            actual: n,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[derive(Default)]
    struct Mock {
        calls: Vec<(Vec<u8>, TransferDir, Vec<u8>)>,
        // Pre-canned responses for DataIn calls (FIFO).
        responses: Vec<Vec<u8>>,
    }

    impl Transport for Mock {
        type Error = ();
        fn exec(&mut self, cdb: &[u8], dir: TransferDir, buf: &mut [u8]) -> Result<usize, ()> {
            let out = buf.to_vec();
            if dir == TransferDir::DataIn && !self.responses.is_empty() {
                let r = self.responses.remove(0);
                let n = r.len().min(buf.len());
                buf[..n].copy_from_slice(&r[..n]);
                self.calls.push((cdb.to_vec(), dir, out));
                return Ok(n);
            }
            let n = buf.len();
            self.calls.push((cdb.to_vec(), dir, out));
            Ok(n)
        }
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
    }

    #[test]
    fn bd_enter_kernel_mode_sends_only_enter_update() {
        let mut m = Mock::default();
        let sess = enter_kernel_mode(&mut m, DriveClass::Bd).unwrap();
        core::mem::forget(sess); // skip Drop's best-effort finish
        assert_eq!(m.calls.len(), 1);
        assert_eq!(m.calls[0].0, vec![0x3B, 0x04, 0xFF, 0, 0, 0, 0, 0x01, 0, 0]);
        assert_eq!(m.calls[0].1, TransferDir::DataOut);
        assert_eq!(m.calls[0].2.len(), CONTROL_LEN as usize);
    }

    #[test]
    fn bd_session_write_kernel_normal_finish_sequence() {
        let mut m = Mock::default();
        let mut sess = enter_kernel_mode(&mut m, DriveClass::Bd).unwrap();
        sess.write_kernel(0, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        sess.write_normal(0x8000, &[0x11, 0x22]).unwrap();
        sess.finish().unwrap();
        let cdbs: Vec<Vec<u8>> = m.calls.iter().map(|c| c.0.clone()).collect();
        assert_eq!(cdbs.len(), 4);
        assert_eq!(cdbs[0], vec![0x3B, 0x04, 0xFF, 0, 0, 0, 0, 0x01, 0, 0]);
        assert_eq!(cdbs[1], vec![0x3B, 0x07, 0xFE, 0, 0, 0, 0, 0, 0x04, 0]);
        assert_eq!(cdbs[2], vec![0x3B, 0x07, 0xF0, 0, 0x80, 0, 0, 0, 0x02, 0]);
        assert_eq!(cdbs[3], vec![0x3B, 0x05, 0xFF, 0, 0, 0, 0, 0x01, 0, 0]);
        assert_eq!(m.calls[1].2, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(m.calls[2].2, vec![0x11, 0x22]);
    }

    #[test]
    fn dvr_enter_kernel_mode_runs_handshake_then_enter_update() {
        // Build a challenge from a known seed so solve() succeeds.
        let seed: u16 = 0x1234;
        let mut s = seed as u32;
        let mut challenge = vec![0u8; crate::KERNEL_CHALLENGE_LEN as usize];
        for b in challenge.iter_mut() {
            s = s.wrapping_mul(0x41C6_4E6D).wrapping_add(0x3039);
            *b = (s >> 16) as u8;
        }

        let mut m = Mock::default();
        m.responses.push(challenge);

        let sess = enter_kernel_mode(&mut m, DriveClass::Dvr).unwrap();
        core::mem::forget(sess);

        let cdbs: Vec<Vec<u8>> = m.calls.iter().map(|c| c.0.clone()).collect();
        assert_eq!(cdbs.len(), 4);
        assert_eq!(cdbs[0], vec![0x3B, 0x01, 0xF3, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(cdbs[0].len(), 10);
        assert_eq!(m.calls[0].1, TransferDir::None);
        assert_eq!(cdbs[1], vec![0x3C, 0x01, 0xF2, 0, 0, 0, 0, 0x04, 0, 0]);
        assert_eq!(m.calls[1].1, TransferDir::DataIn);
        assert_eq!(cdbs[2], vec![0x3B, 0x01, 0xF2, 0, 0, 0, 0, 0x01, 0, 0]);
        assert_eq!(m.calls[2].1, TransferDir::DataOut);
        // Response payload is the response byte repeated.
        let expected_byte = crate::kernel_mode::response_byte(seed);
        assert!(m.calls[2].2.iter().all(|&b| b == expected_byte));
        assert_eq!(m.calls[2].2.len(), crate::KERNEL_RESPONSE_LEN as usize);
        assert_eq!(cdbs[3], vec![0x3B, 0x04, 0xFF, 0, 0, 0, 0, 0x01, 0, 0]);
    }

    #[test]
    fn read_memory_knocks_before_reading() {
        let mut m = Mock::default();
        m.responses.push(vec![0u8; 0x10]); // read response
        let mut buf = [0u8; 0x10];
        read_memory(&mut m, 0x1234, 0x10, &mut buf).unwrap();
        let cdbs: Vec<Vec<u8>> = m.calls.iter().map(|c| c.0.clone()).collect();
        assert_eq!(cdbs.len(), 2);
        assert_eq!(
            cdbs[0],
            vec![0x3B, 0x02, 0x41, 0xA5, 0xAA, 0xAA, 0, 0, 0, 0]
        );
        assert_eq!(m.calls[0].1, TransferDir::None);
        assert_eq!(
            cdbs[1],
            vec![0x3C, 0x02, 0xB0, 0, 0x12, 0x34, 0, 0, 0x10, 0]
        );
        assert_eq!(m.calls[1].1, TransferDir::DataIn);
    }

    #[test]
    fn locked_sense_promotes_to_flasherror_locked() {
        struct LockedMock;
        impl Transport for LockedMock {
            type Error = &'static str;
            fn exec(
                &mut self,
                _cdb: &[u8],
                _dir: TransferDir,
                _buf: &mut [u8],
            ) -> Result<usize, Self::Error> {
                Err("check condition")
            }
            fn sense(&self) -> Option<(u8, u8, u8)> {
                Some((0x05, 0x24, 0x00))
            }
        }
        let mut m = LockedMock;
        let r = enter_kernel_mode(&mut m, DriveClass::Bd);
        let is_locked = matches!(r, Err(FlashError::Locked));
        if let Ok(sess) = r {
            core::mem::forget(sess);
        }
        assert!(is_locked, "expected FlashError::Locked");
    }
}
