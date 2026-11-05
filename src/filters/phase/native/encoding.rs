//! Shared typed H8 instruction encoding; firmware logic remains OEM-derived.
use alloc::vec::Vec;
use h8_asm::{
    isa::{encode_insn, Ea, Insn, Operand},
    Mode, Target,
};

pub(crate) fn jump(address: u32) -> Option<Vec<u8>> {
    encode_insn(
        Insn::new(
            "JMP",
            None,
            [
                Operand::Address(Ea::Absolute {
                    value: address,
                    bits: 24,
                }),
                Operand::None,
                Operand::None,
            ],
        ),
        Target::H8S2000,
        Mode::Advanced,
    )
    .ok()
}
pub(crate) fn nops(bytes: &mut [u8]) -> Option<()> {
    let nop = encode_insn(
        Insn::new("NOP", None, [Operand::None; 3]),
        Target::H8S2000,
        Mode::Advanced,
    )
    .ok()?;
    if bytes.len() % nop.len() != 0 {
        return None;
    }
    for slot in bytes.chunks_exact_mut(nop.len()) {
        slot.copy_from_slice(&nop);
    }
    Some(())
}
