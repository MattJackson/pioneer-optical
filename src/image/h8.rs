//! H8S decoding through the shared instruction library.
use h8_asm::{isa::decode_insn, Mode, Target};

/// Instruction length, or one word for resynchronization after unrecognized data.
pub(crate) fn ilen(bytes: &[u8], offset: usize) -> usize {
    bytes
        .get(offset..)
        .and_then(|code| decode_insn(code, Target::H8S2000, Mode::Advanced).ok())
        .map_or(2, |decoded| decoded.len)
}

/// Whether a complete, defined H8S instruction starts at this offset.
pub(crate) fn valid(bytes: &[u8], offset: usize) -> bool {
    bytes
        .get(offset..)
        .is_some_and(|code| decode_insn(code, Target::H8S2000, Mode::Advanced).is_ok())
}
