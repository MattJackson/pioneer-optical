//! Vendor SCSI command catalogue for **Pioneer optical drives** (BD/DVD).
//!
//! This crate is the single source of truth for the Pioneer vendor CDBs: named,
//! documented constructors plus the field constants behind them. It is pure data
//! — every function returns the raw CDB bytes and performs no I/O — so any
//! transport (a flasher, an unlocker, a diagnostic) can depend on it and issue
//! the commands itself. `no_std`, no allocation, no dependencies.
//!
//! ## The two independent privilege unlocks
//! - **read unlock** — the zero-length "knock" [`knock`] (`3B 02 41 A5 AA AA`).
//!   Opens [`read_memory`] (`3C 02 B0`) reads of protected memory above the
//!   `0x8000` boot window, up to [`READ_CEILING`]. Proven live on a BDR-UD04 and
//!   confirmed firmware-wide read-only (sets one RAM flag whose only consumers
//!   are read paths; it cannot enable writes).
//! - **write unlock** — vendor "kernel mode", the `F3`/`F2` challenge-response
//!   ([`kernel_mode_arm`] / [`kernel_mode_challenge`] / [`kernel_mode_response`]).
//!   Gates the OEM write-accept path (both Kernel `07/FE` and Normal `07/F0`
//!   components). Independent of the read knock (a disjoint state cell).
//!
//! The two are distinct and independent: neither enables the other.
//!
//! All vendor CDBs are 10 bytes; 24-bit offsets and lengths are big-endian.
#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

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

/// `3B 01 F3 00 00 00 00 00 00 00` — kernel-mode (write-unlock) arm: zero-length.
pub fn kernel_mode_arm() -> [u8; 10] {
    cdb(WRITE_BUFFER, KERNEL_MODE_MODE, KERNEL_ARM_ID, 0, 0)
}

/// `3C 01 F2 00 00 00 00 04 00 00` — kernel-mode challenge read (0x400-byte status).
pub fn kernel_mode_challenge() -> [u8; 10] {
    cdb(
        READ_BUFFER,
        KERNEL_MODE_MODE,
        KERNEL_CHALLENGE_ID,
        0,
        KERNEL_CHALLENGE_LEN,
    )
}

/// `3B 01 F2 00 00 00 00 01 00 00` — kernel-mode response write (0x100-byte reply).
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-exact lock between this catalogue and the whitepaper's Appendix B.
    /// If a row changes here, update Appendix B (and vice-versa).
    #[test]
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
