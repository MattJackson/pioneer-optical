//! Vendor SCSI command catalogue for **Pioneer optical drives** (BD/DVD).
//!
//! This crate is the single source of truth for the Pioneer vendor CDBs: named,
//! documented constructors plus the field constants behind them. It is pure data
//! — every function returns the raw CDB bytes and performs no I/O — so any
//! transport (a flasher, an unlocker, a diagnostic) can depend on it and issue
//! the commands itself. `no_std`, no allocation, no dependencies.
//!
//! ## Read vs. update privilege
//! - **read unlock** — the zero-length "knock" [`knock`] (`3B 02 41 A5 AA AA`).
//!   Opens [`read_memory`] (`3C 02 B0`) reads of protected memory above the
//!   `0x8000` boot window, up to [`READ_CEILING`]. Proven live on a BDR-UD04 and
//!   confirmed firmware-wide read-only (sets one RAM flag whose only consumers
//!   are read paths; it cannot enable writes).
//! - **"kernel mode" = OEM update session** — the state entered by `3B 04 FF`
//!   ([`enter_update`]) in which the drive accepts Kernel (`07/FE`) and Normal
//!   (`07/F0`) chunk writes and the `3B 05 FF` commit ([`finish`]). On DVR
//!   generations entry is gated by an F3/F2/F2 challenge-response whose math
//!   lives in [`kernel_mode`]; on BD the F3/F2 CDBs are inert (verified by
//!   disassembly) and `3B 04 FF` enters directly. The drive-generic entry
//!   point is [`flash::enter_kernel_mode`].
//!
//! The read knock and the update session are disjoint state cells; neither
//! enables the other.
//!
//! All vendor CDBs are 10 bytes; 24-bit offsets and lengths are big-endian.
//!
//! ## Optional firmware-body analysis (`fw` feature)
//! The non-default [`fw`] module adds deterministic crossflash-compatibility
//! family ids and the UHD capability test over envelope-decoded firmware bodies.
//! It pulls in `alloc` and a zlib inflater; the default build stays `no_std`,
//! no-alloc and dependency-free.
//!
//! [`fw`]: crate::fw
#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(any(feature = "fw", feature = "highlevel"))]
extern crate alloc;

#[cfg(feature = "fw")]
pub mod fw;

#[cfg(feature = "highlevel")]
pub mod transport;

#[cfg(feature = "highlevel")]
pub mod flash;

/// SCSI `WRITE BUFFER` opcode — every vendor *write/command* CDB.
pub const WRITE_BUFFER: u8 = 0x3B;
/// SCSI `READ BUFFER` opcode — every vendor *read* CDB.
pub const READ_BUFFER: u8 = 0x3C;

/// `3C 02 B0` / `3C 02 F1` read mode (`02`).
pub const READ_MODE: u8 = 0x02;
/// Gated memory-read buffer-id (`B0`).
pub const READ_MEMORY_ID: u8 = 0xB0;
/// Vendor identity-read buffer-id (`F1`).
pub const IDENTITY_ID: u8 = 0xF1;
/// Identity block length (`0x30` = 48 bytes).
pub const IDENTITY_LEN: u32 = 0x30;
/// Highest address the `02/B0` read reaches once unlocked (empirical ceiling).
pub const READ_CEILING: u32 = 0x0088_0300;

/// Read-unlock knock mode (WRITE BUFFER mode `02`).
pub const KNOCK_MODE: u8 = 0x02;
/// Read-unlock knock buffer-id (`41`).
pub const KNOCK_ID: u8 = 0x41;
/// Fixed magic in the knock's offset field (`A5 AA AA`); the drive checks only
/// the trailing `AA AA`.
pub const KNOCK_MAGIC: [u8; 3] = [0xA5, 0xAA, 0xAA];

/// OEM update: enter-update mode (`04`).
pub const ENTRY_MODE: u8 = 0x04;
/// OEM update: chunk-transfer mode (`07`).
pub const TRANSFER_MODE: u8 = 0x07;
/// OEM update: finish/commit mode (`05`).
pub const FINISH_MODE: u8 = 0x05;
/// Control-buffer id for entry/finish (`FF`).
pub const CONTROL_ID: u8 = 0xFF;
/// Kernel-chunk transfer buffer-id (`FE`).
pub const KERNEL_ID: u8 = 0xFE;
/// Normal-chunk transfer buffer-id (`F0`).
pub const NORMAL_ID: u8 = 0xF0;
/// The control buffer carried by entry/finish is 256 bytes.
pub const CONTROL_LEN: u32 = 0x100;

/// Kernel-mode (write-unlock) mode field (`01`).
pub const KERNEL_MODE_MODE: u8 = 0x01;
/// Kernel-mode arm buffer-id (`F3`).
pub const KERNEL_ARM_ID: u8 = 0xF3;
/// Kernel-mode challenge/response buffer-id (`F2`).
pub const KERNEL_CHALLENGE_ID: u8 = 0xF2;
/// Kernel-mode challenge status length (`0x400`).
pub const KERNEL_CHALLENGE_LEN: u32 = 0x400;
/// Kernel-mode response length (`0x100`).
pub const KERNEL_RESPONSE_LEN: u32 = 0x100;

/// Generic 10-byte vendor CDB: `op, mode&0x1f, id, off[24 BE], len[24 BE], 00`.
fn cdb(op: u8, mode: u8, id: u8, off: u32, len: u32) -> [u8; 10] {
    [
        op,
        mode & 0x1f,
        id,
        (off >> 16) as u8,
        (off >> 8) as u8,
        off as u8,
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        0x00,
    ]
}

/// `12 00 00 00 <alloc> 00` — standard INQUIRY (completion/identity polling).
pub fn inquiry(alloc: u8) -> [u8; 6] {
    [0x12, 0, 0, 0, alloc, 0]
}

/// `3C 02 F1 00 00 00 00 00 30 00` — vendor identity read (48-byte block).
/// Pure identity: sets no state and does not unlock anything.
pub fn vendor_identity() -> [u8; 10] {
    cdb(READ_BUFFER, READ_MODE, IDENTITY_ID, 0, IDENTITY_LEN)
}

/// `3C 02 B0 <off3> <len3> 00` — gated memory read. Refused with sense
/// `05/24/00` for any protected offset until the [`knock`] has run.
pub fn read_memory(off: u32, len: u32) -> [u8; 10] {
    cdb(READ_BUFFER, READ_MODE, READ_MEMORY_ID, off, len)
}

/// `3B 02 41 A5 AA AA 00 00 00 00` — the read-unlock "knock" (Extended-read
/// enable). Zero-length, no data phase; read-only privilege.
pub fn knock() -> [u8; 10] {
    [
        WRITE_BUFFER,
        KNOCK_MODE & 0x1f,
        KNOCK_ID,
        KNOCK_MAGIC[0],
        KNOCK_MAGIC[1],
        KNOCK_MAGIC[2],
        0,
        0,
        0,
        0,
    ]
}

/// `3B 04 FF 00 00 00 00 01 00 00` — enter OEM update mode (256-byte control out).
pub fn enter_update() -> [u8; 10] {
    cdb(WRITE_BUFFER, ENTRY_MODE, CONTROL_ID, 0, CONTROL_LEN)
}

/// `3B 07 FE <off3> <len3> 00` — transfer a Kernel chunk (raw envelope bytes out).
pub fn transfer_kernel(off: u32, len: u32) -> [u8; 10] {
    cdb(WRITE_BUFFER, TRANSFER_MODE, KERNEL_ID, off, len)
}

/// `3B 07 F0 <off3> <len3> 00` — transfer a Normal chunk (raw envelope bytes out).
pub fn transfer_normal(off: u32, len: u32) -> [u8; 10] {
    cdb(WRITE_BUFFER, TRANSFER_MODE, NORMAL_ID, off, len)
}

/// `3B 05 FF 00 00 00 00 01 00 00` — finish/commit the update (256-byte control out).
pub fn finish() -> [u8; 10] {
    cdb(WRITE_BUFFER, FINISH_MODE, CONTROL_ID, 0, CONTROL_LEN)
}

/// `3B 01 F3 00 00 00 00 00 00 00` — DVR-era handshake arm: zero-length.
///
/// Prefer the drive-generic [`flash::enter_kernel_mode`] which issues this (or
/// skips it on BD) on the caller's behalf.
#[deprecated(note = "DVR-era handshake; use flash::enter_kernel_mode instead")]
pub fn kernel_mode_arm() -> [u8; 10] {
    cdb(WRITE_BUFFER, KERNEL_MODE_MODE, KERNEL_ARM_ID, 0, 0)
}

/// `3C 01 F2 00 00 00 00 04 00 00` — DVR-era challenge read (0x400-byte status).
///
/// Prefer the drive-generic [`flash::enter_kernel_mode`].
#[deprecated(note = "DVR-era handshake; use flash::enter_kernel_mode instead")]
pub fn kernel_mode_challenge() -> [u8; 10] {
    cdb(
        READ_BUFFER,
        KERNEL_MODE_MODE,
        KERNEL_CHALLENGE_ID,
        0,
        KERNEL_CHALLENGE_LEN,
    )
}

/// `3B 01 F2 00 00 00 00 01 00 00` — DVR-era response write (0x100-byte reply).
///
/// Prefer the drive-generic [`flash::enter_kernel_mode`].
#[deprecated(note = "DVR-era handshake; use flash::enter_kernel_mode instead")]
pub fn kernel_mode_response() -> [u8; 10] {
    cdb(
        WRITE_BUFFER,
        KERNEL_MODE_MODE,
        KERNEL_CHALLENGE_ID,
        0,
        KERNEL_RESPONSE_LEN,
    )
}

/// `00 00 00 00 00 00` — TEST UNIT READY (completion poll).
pub fn test_unit_ready() -> [u8; 6] {
    [0, 0, 0, 0, 0, 0]
}

/// `4A 00 00 00 10 00 00 00 08 00` — GET EVENT STATUS NOTIFICATION (poll drain).
pub fn get_event_status() -> [u8; 10] {
    [0x4A, 0, 0, 0, 0x10, 0, 0, 0, 0x08, 0]
}

/// Typed parsers for the data a Pioneer drive returns to the read commands.
///
/// Each parser borrows the response buffer (zero-copy) and exposes the vendor
/// fields as trimmed `&str` / integers, so callers never index magic offsets.
pub mod response {
    /// Trim trailing ASCII spaces and NULs, then interpret as UTF-8 (vendor
    /// fields are ASCII in practice). Returns `""` if the slice is not valid.
    fn field(raw: &[u8]) -> &str {
        let end = raw
            .iter()
            .rposition(|&b| b != b' ' && b != 0)
            .map_or(0, |i| i + 1);
        core::str::from_utf8(&raw[..end]).unwrap_or("")
    }

    /// Parsed standard `INQUIRY` (opcode `12`) response.
    #[derive(Clone, Copy, Debug)]
    pub struct Inquiry<'a> {
        raw: &'a [u8],
    }

    impl<'a> Inquiry<'a> {
        /// Borrow an INQUIRY response. Needs the 36-byte standard header.
        pub fn parse(raw: &'a [u8]) -> Option<Self> {
            (raw.len() >= 36).then_some(Self { raw })
        }
        /// Peripheral device type (low 5 bits of byte 0); `0x05` = BD/DVD/CD.
        pub fn device_type(&self) -> u8 {
            self.raw[0] & 0x1f
        }
        /// Vendor identification (bytes 8..16), e.g. `PIONEER`.
        pub fn vendor(&self) -> &str {
            field(&self.raw[8..16])
        }
        /// Product identification (bytes 16..32), e.g. `BD-RW   BDR-UD04`.
        pub fn product(&self) -> &str {
            field(&self.raw[16..32])
        }
        /// Product revision level (bytes 32..36), e.g. `1.14`.
        pub fn revision(&self) -> &str {
            field(&self.raw[32..36])
        }
    }

    /// Parsed vendor identity block (`3C 02 F1`, 48 bytes).
    ///
    /// The [`platform`](Self::platform) field (e.g. `SAT 8A10`) is the drive's
    /// hardware/firmware generation code — the value that governs which vendor
    /// command dialect a drive speaks.
    #[derive(Clone, Copy, Debug)]
    pub struct VendorIdentity<'a> {
        raw: &'a [u8],
    }

    impl<'a> VendorIdentity<'a> {
        /// Borrow a 48-byte identity block (see [`crate::IDENTITY_LEN`]).
        pub fn parse(raw: &'a [u8]) -> Option<Self> {
            (raw.len() >= 44).then_some(Self { raw })
        }
        /// Drive serial number (bytes 0..16), e.g. `QHDL433450WL`.
        pub fn serial(&self) -> &str {
            field(&self.raw[0..16])
        }
        /// Platform / generation code (bytes 16..24), e.g. `SAT 8A10`.
        pub fn platform(&self) -> &str {
            field(&self.raw[16..24])
        }
        /// First market/region descriptor (bytes 24..32), e.g. `GENERAL`.
        pub fn market(&self) -> &str {
            field(&self.raw[24..32])
        }
        /// Second market/region descriptor (bytes 32..40).
        pub fn market_alt(&self) -> &str {
            field(&self.raw[32..40])
        }
        /// Trailing numeric code (bytes 40..44), e.g. `0000`.
        pub fn code(&self) -> &str {
            field(&self.raw[40..44])
        }
    }
}

/// Math for the **DVR-era** F3/F2/F2 handshake that precedes the OEM update
/// entry (`3B 04 FF`) on DVR drive generations.
///
/// **This module is not the write-unlock.** Throughout this crate, "kernel
/// mode" means the OEM update session entered by `3B 04 FF`
/// ([`enter_update`]); the drive-generic entry point for callers is
/// [`flash::enter_kernel_mode`]. The three CDBs
/// ([`kernel_mode_arm`] / [`kernel_mode_challenge`] / [`kernel_mode_response`])
/// are the DVR challenge-response primitives — the solver below computes the
/// response bytes [`flash::enter_kernel_mode`] writes back on
/// [`flash::DriveClass::Dvr`].
///
/// **On BD the F3/F2 CDBs are inert.** Direct disassembly of the BDR-UD04 /
/// `SAT 8A10` Normal body shows: `F3` is phase-9 gated and only sets
/// `@0x2c24 = 0xf0`; `F2`'s prerequisite requires `phase >= 8` and only sets
/// `@0x2c28 = 0x00100000`; no LCG is called from either handler. The vendor
/// challenge-response model does not exist on BD firmware — BD enters the
/// update session with `3B 04 FF` alone. The solver below is kept for the
/// DVR path and does nothing on BD even if invoked by hand.
pub mod kernel_mode {
    /// One step of the ANSI-C LCG: advance state, return bits 16..24.
    fn lcg_step(state: &mut u32) -> u8 {
        *state = state.wrapping_mul(0x41C6_4E6D).wrapping_add(0x3039);
        (*state >> 16) as u8
    }

    /// Recovered seed plus the full response payload to write back.
    #[derive(Clone)]
    pub struct Solution {
        /// The 16-bit seed whose LCG stream reproduces the challenge.
        pub seed: u16,
        /// The response buffer for [`crate::kernel_mode_response`]
        /// ([`crate::KERNEL_RESPONSE_LEN`] bytes).
        pub response: [u8; crate::KERNEL_RESPONSE_LEN as usize],
    }

    /// Recover the LCG seed from the first four challenge bytes.
    ///
    /// Brute-forces all 65 536 seeds — cheap and deterministic. Returns `None`
    /// if the buffer is shorter than four bytes or no seed reproduces it.
    pub fn recover_seed(challenge: &[u8]) -> Option<u16> {
        if challenge.len() < 4 {
            return None;
        }
        (0u32..=0xFFFF).find_map(|v| {
            let mut s = v;
            (0..4)
                .all(|i| lcg_step(&mut s) == challenge[i])
                .then_some(v as u16)
        })
    }

    /// The response byte for a recovered seed: advance the LCG past the whole
    /// challenge window, then invert the next output.
    pub fn response_byte(seed: u16) -> u8 {
        let mut s = seed as u32;
        for _ in 0..crate::KERNEL_CHALLENGE_LEN {
            lcg_step(&mut s);
        }
        !lcg_step(&mut s)
    }

    /// Solve a challenge end-to-end: recover the seed and build the response
    /// payload (the response byte repeated across the buffer).
    pub fn solve(challenge: &[u8]) -> Option<Solution> {
        let seed = recover_seed(challenge)?;
        Some(Solution {
            seed,
            response: [response_byte(seed); crate::KERNEL_RESPONSE_LEN as usize],
        })
    }
}

/// Minimal SCSI sense helpers for recognising the vendor lock refusal.
pub mod sense {
    /// SCSI sense key `ILLEGAL REQUEST`.
    pub const ILLEGAL_REQUEST: u8 = 0x05;
    /// Additional sense code `INVALID FIELD IN CDB` (ASC `24`, ASCQ `00`).
    pub const INVALID_FIELD_IN_CDB: (u8, u8) = (0x24, 0x00);

    /// `true` if `(key, asc, ascq)` is the `05/24/00` the drive returns when a
    /// gated command is issued without the matching unlock (or is unsupported).
    pub fn is_locked(key: u8, asc: u8, ascq: u8) -> bool {
        key == ILLEGAL_REQUEST && (asc, ascq) == INVALID_FIELD_IN_CDB
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-exact lock between this catalogue and the whitepaper's Appendix B.
    /// If a row changes here, update Appendix B (and vice-versa).
    #[test]
    #[allow(deprecated)]
    fn cdb_catalogue_is_byte_exact() {
        assert_eq!(
            vendor_identity(),
            [0x3C, 0x02, 0xF1, 0, 0, 0, 0, 0, 0x30, 0]
        );
        assert_eq!(
            read_memory(0, 0xA4),
            [0x3C, 0x02, 0xB0, 0, 0, 0, 0, 0, 0xA4, 0]
        );
        assert_eq!(
            read_memory(0x1234, 0x1000),
            [0x3C, 0x02, 0xB0, 0, 0x12, 0x34, 0, 0x10, 0, 0]
        );
        assert_eq!(knock(), [0x3B, 0x02, 0x41, 0xA5, 0xAA, 0xAA, 0, 0, 0, 0]);
        assert_eq!(enter_update(), [0x3B, 0x04, 0xFF, 0, 0, 0, 0, 0x01, 0, 0]);
        assert_eq!(
            transfer_kernel(0, 0x80),
            [0x3B, 0x07, 0xFE, 0, 0, 0, 0, 0, 0x80, 0]
        );
        assert_eq!(
            transfer_normal(0x8000, 0x80),
            [0x3B, 0x07, 0xF0, 0, 0x80, 0, 0, 0, 0x80, 0]
        );
        assert_eq!(finish(), [0x3B, 0x05, 0xFF, 0, 0, 0, 0, 0x01, 0, 0]);
        assert_eq!(kernel_mode_arm(), [0x3B, 0x01, 0xF3, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            kernel_mode_challenge(),
            [0x3C, 0x01, 0xF2, 0, 0, 0, 0, 0x04, 0, 0]
        );
        assert_eq!(
            kernel_mode_response(),
            [0x3B, 0x01, 0xF2, 0, 0, 0, 0, 0x01, 0, 0]
        );
        assert_eq!(inquiry(0x60), [0x12, 0, 0, 0, 0x60, 0]);
        assert_eq!(test_unit_ready(), [0, 0, 0, 0, 0, 0]);
        assert_eq!(get_event_status(), [0x4A, 0, 0, 0, 0x10, 0, 0, 0, 0x08, 0]);
    }
}
