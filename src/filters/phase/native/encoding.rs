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

/// Retarget one complete absolute JSR through decoded operands and the encoder.
pub(crate) fn retarget_call(bytes: &mut [u8], at: usize, address: u32) -> Option<()> {
    let decoded =
        h8_asm::isa::decode_insn(bytes.get(at..)?, Target::H8S2000, Mode::Advanced).ok()?;
    let mut instruction = decoded.insn;
    if instruction.mnemonic != "JSR"
        || !matches!(
            instruction.operands[0],
            Operand::Address(Ea::Absolute { bits: 24, .. })
        )
    {
        return None;
    }
    instruction.operands[0] = Operand::Address(Ea::Absolute {
        value: address,
        bits: 24,
    });
    let encoded = encode_insn(instruction, Target::H8S2000, Mode::Advanced).ok()?;
    if encoded.len() != decoded.len {
        return None;
    }
    bytes
        .get_mut(at..at.checked_add(decoded.len)?)?
        .copy_from_slice(&encoded);
    Some(())
}

/// Swap one proved F910/F911 or F912/F913 destination through typed H8 operands.
pub(crate) fn swap_output(bytes: &mut [u8], operand: usize) -> Option<()> {
    let at = operand.checked_sub(3)?;
    let d = h8_asm::isa::decode_insn(bytes.get(at..)?, Target::H8S2000, Mode::Advanced).ok()?;
    let mut instruction = d.insn;
    let Operand::Address(Ea::Absolute { value, bits: 16 }) = instruction.operands[1] else {
        return None;
    };
    if instruction.mnemonic != "MOV" || d.len != 4 || !(0xf910..=0xf913).contains(&value) {
        return None;
    }
    instruction.operands[1] = Operand::Address(Ea::Absolute {
        value: value ^ 1,
        bits: 16,
    });
    let encoded = encode_insn(instruction, Target::H8S2000, Mode::Advanced).ok()?;
    if encoded.len() != d.len || encoded[..3] != bytes[at..at + 3] {
        return None;
    }
    bytes[at..at + d.len].copy_from_slice(&encoded);
    Some(())
}
