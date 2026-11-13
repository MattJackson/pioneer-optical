//! Command descriptor blocks.
//!
//! Every constructor returns the raw CDB bytes. Vendor CDBs are 10 bytes:
//! `opcode, mode, buffer id, offset[24 BE], length[24 BE], 00`.

use crate::Role;

/// SCSI `WRITE BUFFER` opcode, used by every vendor write or control command.
pub const WRITE_BUFFER: u8 = 0x3B;
/// SCSI `READ BUFFER` opcode, used by every vendor read command.
pub const READ_BUFFER: u8 = 0x3C;

/// Buffer mode 02 shared by vendor reads, A0 parameter and diagnostic-control
/// writes, and the [`knock`].
pub const READ_MODE: u8 = 0x02;
/// Buffer id of [`read_memory`].
pub const MEMORY_ID: u8 = 0xB0;
/// Buffer id of [`vendor_identity`].
pub const IDENTITY_ID: u8 = 0xF1;
/// Length of the vendor identity block.
pub const IDENTITY_LEN: u32 = 0x30;
/// Highest address [`read_memory`] reaches with extended read enabled.
pub const READ_CEILING: u32 = 0x0088_0300;

/// Buffer id of the [`knock`].
pub const KNOCK_ID: u8 = 0x41;
/// Offset field of the [`knock`].
pub const KNOCK_MAGIC: [u8; 3] = [0xA5, 0xAA, 0xAA];

/// Mode of [`enter_update`].
pub const ENTER_MODE: u8 = 0x04;
/// Mode of [`transfer`].
pub const TRANSFER_MODE: u8 = 0x07;
/// Mode of [`finish`].
pub const FINISH_MODE: u8 = 0x05;
/// Buffer id of [`enter_update`] and [`finish`].
pub const CONTROL_ID: u8 = 0xFF;
/// Length of the control buffer carried by [`enter_update`] and [`finish`].
pub const CONTROL_LEN: u32 = 0x100;
/// Buffer id of a Kernel [`transfer`].
pub const KERNEL_ID: u8 = 0xFE;
/// Buffer id of a Normal [`transfer`].
pub const NORMAL_ID: u8 = 0xF0;

/// Mode of the DVR handshake commands.
pub const DVR_MODE: u8 = 0x01;
/// Buffer id of [`dvr_arm`].
pub const DVR_ARM_ID: u8 = 0xF3;
/// Buffer id of [`dvr_challenge`] and [`dvr_response`].
pub const DVR_CHALLENGE_ID: u8 = 0xF2;
/// Length of the challenge read by [`dvr_challenge`].
pub const DVR_CHALLENGE_LEN: u32 = 0x400;
/// Length of the response written by [`dvr_response`].
pub const DVR_RESPONSE_LEN: u32 = 0x100;

/// A 10-byte vendor CDB. `off` and `len` are 24-bit fields: the top byte of
/// each is discarded, so callers must range-check first ([`crate::drive`] does).
fn vendor(op: u8, mode: u8, id: u8, off: u32, len: u32) -> [u8; 10] {
    let [_, o2, o1, o0] = off.to_be_bytes();
    let [_, l2, l1, l0] = len.to_be_bytes();
    [op, mode & 0x1f, id, o2, o1, o0, l2, l1, l0, 0]
}

/// Selector of the diagnostic circular-buffer read.
pub const DIAGNOSTIC_LOG_ID: u8 = 0xFC;
/// Maximum diagnostic circular-buffer response size.
pub const DIAGNOSTIC_LOG_LEN: u32 = 0x4000;
/// Selector of the internal diagnostic control envelope.
pub const DIAGNOSTIC_CONTROL_ID: u8 = 0xE1;
/// Size of an internal diagnostic control envelope.
pub const DIAGNOSTIC_CONTROL_LEN: u32 = 32;

/// Read a diagnostic selector. Offset and length must fit 24 bits.
/// Selector-specific bounds and side effects are the caller's responsibility.
pub fn read_diagnostic(id: u8, off: u32, len: u32) -> [u8; 10] {
    vendor(READ_BUFFER, READ_MODE, id, off, len)
}

/// Read one big-endian word from the A0 parameter surface.
/// The drive may reject the command when its Normal firmware does not implement A0.
pub fn read_parameter_word(index: u16) -> Option<[u8; 10]> {
    (index < 0x400).then(|| vendor(READ_BUFFER, READ_MODE, 0xa0, u32::from(index) * 2, 2))
}

/// Persist one word through the firmware's native A0 record writer.
/// The caller must check the command result and read the word back.
pub fn write_parameter_word(index: u16) -> Option<[u8; 10]> {
    (index < 0x400).then(|| vendor(WRITE_BUFFER, READ_MODE, 0xa0, u32::from(index) * 2, 2))
}

/// Read the 16 KiB diagnostic circular buffer on audited H8 firmware.
pub fn read_diagnostic_log() -> [u8; 10] {
    vendor(
        READ_BUFFER,
        READ_MODE,
        DIAGNOSTIC_LOG_ID,
        0,
        DIAGNOSTIC_LOG_LEN,
    )
}

/// Send a 32-byte internal control envelope on audited H8 firmware.
pub fn write_diagnostic_control() -> [u8; 10] {
    vendor(
        WRITE_BUFFER,
        READ_MODE,
        DIAGNOSTIC_CONTROL_ID,
        0,
        DIAGNOSTIC_CONTROL_LEN,
    )
}

/// `12 00 00 00 <alloc> 00` — standard INQUIRY.
pub fn inquiry(alloc: u8) -> [u8; 6] {
    [0x12, 0, 0, 0, alloc, 0]
}

/// `00 00 00 00 00 00` — TEST UNIT READY.
pub fn test_unit_ready() -> [u8; 6] {
    [0; 6]
}

/// Standard fixed-format REQUEST SENSE. Update receivers permit this command
/// while programming; its command-completion path also checks for restart.
pub fn request_sense(alloc: u8) -> [u8; 6] {
    [0x03, 0, 0, 0, alloc, 0]
}

/// `4A 00 00 00 10 00 00 00 08 00` — GET EVENT STATUS NOTIFICATION (media
/// class, 8 bytes).
pub fn get_event_status() -> [u8; 10] {
    [0x4A, 0, 0, 0, 0x10, 0, 0, 0, 0x08, 0]
}

/// `3C 02 F1 00 00 00 00 00 30 00` — read the vendor identity block.
pub fn vendor_identity() -> [u8; 10] {
    vendor(READ_BUFFER, READ_MODE, IDENTITY_ID, 0, IDENTITY_LEN)
}

/// `3C 02 B0 <off> <len> 00` — read drive memory. Above `0x8000` the drive
/// refuses with `05/24/00` unless extended read is enabled ([`knock`]).
pub fn read_memory(off: u32, len: u32) -> [u8; 10] {
    vendor(READ_BUFFER, READ_MODE, MEMORY_ID, off, len)
}

/// `3B 02 41 A5 AA AA 00 00 00 00` — enable extended read. No data phase.
pub fn knock() -> [u8; 10] {
    let [a, b, c] = KNOCK_MAGIC;
    [WRITE_BUFFER, READ_MODE, KNOCK_ID, a, b, c, 0, 0, 0, 0]
}

/// `3B 04 FF 00 00 00 00 01 00 00` — enter the update session. Data out: the
/// [`CONTROL_LEN`]-byte control buffer.
pub fn enter_update() -> [u8; 10] {
    vendor(WRITE_BUFFER, ENTER_MODE, CONTROL_ID, 0, CONTROL_LEN)
}

/// `3B 07 FE|F0 <off> <len> 00` — write a chunk of the `role` component at
/// `off`. Data out: `len` bytes of the component.
pub fn transfer(role: Role, off: u32, len: u32) -> [u8; 10] {
    let id = match role {
        Role::Kernel => KERNEL_ID,
        Role::Normal => NORMAL_ID,
    };
    transfer_with_id(id, off, len)
}

/// A `TRANSFER_MODE` [`WRITE_BUFFER`] to an explicit buffer `id`. A receive
/// plan addresses segments by raw buffer id, so a single component can target
/// more than one receive buffer (the role-keyed [`transfer`] cannot). Offset
/// and length must fit 24 bits; the caller range-checks.
pub fn transfer_with_id(id: u8, off: u32, len: u32) -> [u8; 10] {
    vendor(WRITE_BUFFER, TRANSFER_MODE, id, off, len)
}

/// `3B 05 FF 00 00 00 00 01 00 00` — commit the update. Data out: the
/// [`CONTROL_LEN`]-byte control buffer.
pub fn finish() -> [u8; 10] {
    vendor(WRITE_BUFFER, FINISH_MODE, CONTROL_ID, 0, CONTROL_LEN)
}

/// `3B 01 F3 00 00 00 00 00 00 00` — arm the DVR handshake. No data phase.
pub fn dvr_arm() -> [u8; 10] {
    vendor(WRITE_BUFFER, DVR_MODE, DVR_ARM_ID, 0, 0)
}

/// `3C 01 F2 00 00 00 00 04 00 00` — read the DVR challenge
/// ([`DVR_CHALLENGE_LEN`] bytes).
pub fn dvr_challenge() -> [u8; 10] {
    vendor(
        READ_BUFFER,
        DVR_MODE,
        DVR_CHALLENGE_ID,
        0,
        DVR_CHALLENGE_LEN,
    )
}

/// `3B 01 F2 00 00 00 00 01 00 00` — write the DVR response
/// ([`DVR_RESPONSE_LEN`] bytes, from [`crate::cdb::dvr::solve`]).
pub fn dvr_response() -> [u8; 10] {
    vendor(
        WRITE_BUFFER,
        DVR_MODE,
        DVR_CHALLENGE_ID,
        0,
        DVR_RESPONSE_LEN,
    )
}

#[cfg(test)]
#[path = "cdb_tests.rs"]
mod tests;

/// The challenge-response handshake that precedes update entry on
/// [`crate::DriveClass::Dvr`] drives.
///
/// Sequence: [`dvr_arm`], read the challenge with [`dvr_challenge`],
/// [`solve`](dvr::solve) it, write the response with [`dvr_response`].
pub mod dvr {
    use crate::cdb::{DVR_CHALLENGE_LEN, DVR_RESPONSE_LEN};

    /// Advance the challenge generator; return its output byte.
    fn step(state: &mut u32) -> u8 {
        *state = state.wrapping_mul(0x41C6_4E6D).wrapping_add(0x3039);
        (*state >> 16) as u8
    }

    /// Solve a challenge: the response payload for [`crate::cdb::dvr_response`],
    /// or `None` if `challenge` is shorter than four bytes or not a valid
    /// challenge.
    pub fn solve(challenge: &[u8]) -> Option<[u8; DVR_RESPONSE_LEN as usize]> {
        let head = challenge.get(..4)?;
        let seed = (0u32..=0xFFFF).find(|&v| {
            let mut s = v;
            head.iter().all(|&b| step(&mut s) == b)
        })?;
        let mut s = seed;
        for _ in 0..DVR_CHALLENGE_LEN {
            step(&mut s);
        }
        Some([!step(&mut s); DVR_RESPONSE_LEN as usize])
    }

    #[cfg(test)]
    pub(crate) fn challenge(seed: u16) -> [u8; DVR_CHALLENGE_LEN as usize] {
        let mut s = seed as u32;
        let mut out = [0; DVR_CHALLENGE_LEN as usize];
        out.iter_mut().for_each(|b| *b = step(&mut s));
        out
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn solves_a_generated_challenge() {
            let r = super::solve(&super::challenge(0x1234)).unwrap();
            assert!(r.iter().all(|&b| b == r[0]));
            // The response depends on the challenge.
            let other = super::solve(&super::challenge(0x4321)).unwrap();
            assert_ne!(r[0], other[0]);
            assert_eq!(super::solve(&[1, 2]), None);
            // Exact responses (independently computed LCG).
            assert_eq!(r, [0x55; crate::cdb::DVR_RESPONSE_LEN as usize]);
            assert_eq!(other, [0xb9; crate::cdb::DVR_RESPONSE_LEN as usize]);
        }

        #[test]
        fn generator_outputs_exact_bytes() {
            // state 1 -> 0x41C67EA6 -> high-half low byte 0xC6.
            assert_eq!(super::challenge(1)[0], 0xC6);
            let mut s = 0u32;
            assert_eq!(super::step(&mut s), 0);
            assert_eq!(s, 0x3039);
            let mut s = 1u32;
            assert_eq!(super::step(&mut s), 0xC6);
            assert_eq!(s, 0x41C6_7EA6);
        }

        #[test]
        fn rejects_a_non_challenge() {
            // A genuine challenge with a corrupted head matches no seed.
            let mut c = super::challenge(0x1234);
            for b in c.iter_mut().take(4) {
                *b ^= 0xFF;
            }
            assert_eq!(super::solve(&c), None);
        }
    }
}

/// Classification of the sense data returned with a refused vendor command.
pub mod sense {
    /// Sense key `ILLEGAL REQUEST`.
    pub const ILLEGAL_REQUEST: u8 = 0x05;
    /// Additional sense `INVALID FIELD IN CDB` (ASC `24`, ASCQ `00`).
    pub const INVALID_FIELD_IN_CDB: (u8, u8) = (0x24, 0x00);

    /// `true` for `05/24/00`: the command needs a drive state that is not
    /// active, or is unsupported on this drive.
    pub fn is_locked(key: u8, asc: u8, ascq: u8) -> bool {
        key == ILLEGAL_REQUEST && (asc, ascq) == INVALID_FIELD_IN_CDB
    }
}
