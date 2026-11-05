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

/// Retarget a declared address field only after h8-asm proves the containing
/// operand and its exact encoded byte span. Data and opcode bytes cannot pass.
pub(crate) fn retarget_field(
    bytes: &mut [u8],
    field: usize,
    width: usize,
    address: u32,
) -> Option<()> {
    if !(2..=4).contains(&width) || (width < 4 && address >> (width * 8) != 0) {
        return None;
    }
    let end = field.checked_add(width)?;
    let old = bytes
        .get(field..end)?
        .iter()
        .fold(0u32, |v, b| (v << 8) | u32::from(*b));
    let mut at = 0;
    while at < bytes.len() {
        let d = h8_asm::isa::decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced).ok()?;
        let next = at.checked_add(d.len)?;
        if field >= next {
            at = next;
            continue;
        }
        if field < at || end > next {
            return None;
        }
        let original = &bytes[at..next];
        let local = field - at;
        let fits = |encoded: &[u8], value: u32| {
            encoded.len() == original.len()
                && encoded[..local] == original[..local]
                && encoded[local + width..] == original[local + width..]
                && encoded[local..local + width] == value.to_be_bytes()[4 - width..]
        };
        let mut selected = None;
        for (index, operand) in d.insn.operands.iter().enumerate() {
            let replace = |value| match *operand {
                Operand::Immediate {
                    value: previous,
                    bits,
                } if previous == old && usize::from(bits) == width * 8 => {
                    Some(Operand::Immediate { value, bits })
                }
                Operand::Address(Ea::Absolute {
                    value: previous,
                    bits,
                }) if previous == old && usize::from(bits) == width * 8 => {
                    Some(Operand::Address(Ea::Absolute { value, bits }))
                }
                Operand::Address(Ea::Displacement {
                    base,
                    value: previous,
                    bits,
                }) if previous as u32 == old && usize::from(bits) == width * 8 => {
                    Some(Operand::Address(Ea::Displacement {
                        base,
                        value: value as i32,
                        bits,
                    }))
                }
                _ => None,
            };
            let Some(probe) = replace(old ^ 1) else {
                continue;
            };
            let mut instruction = d.insn;
            instruction.operands[index] = probe;
            let Ok(probed) = encode_insn(instruction, Target::H8S2000, Mode::Advanced) else {
                continue;
            };
            if !fits(&probed, old ^ 1) {
                continue;
            }
            instruction.operands[index] = replace(address)?;
            let encoded = encode_insn(instruction, Target::H8S2000, Mode::Advanced).ok()?;
            if !fits(&encoded, address) || selected.is_some() {
                return None;
            }
            selected = Some(encoded);
        }
        bytes[at..next].copy_from_slice(&selected?);
        return Some(());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use h8_asm::isa::{Reg, Size};
    #[test]
    fn address_fields_are_bound_to_typed_operands_and_cannot_change_opcodes() {
        for (instruction, field, width, value) in [
            (
                Insn::new(
                    "JSR",
                    None,
                    [
                        Operand::Address(Ea::Absolute {
                            value: 0x412000,
                            bits: 24,
                        }),
                        Operand::None,
                        Operand::None,
                    ],
                ),
                1,
                3,
                0x413000,
            ),
            (
                Insn::new(
                    "MOV",
                    Some(Size::Long),
                    [
                        Operand::Immediate {
                            value: 0x412000,
                            bits: 32,
                        },
                        Operand::Register(Reg::Long(1)),
                        Operand::None,
                    ],
                ),
                2,
                4,
                0x413000,
            ),
            (
                Insn::new(
                    "MOV",
                    Some(Size::Word),
                    [
                        Operand::Address(Ea::Displacement {
                            base: Reg::Long(0),
                            value: 0x412000,
                            bits: 32,
                        }),
                        Operand::Register(Reg::Word(0)),
                        Operand::None,
                    ],
                ),
                4,
                4,
                0x413000,
            ),
        ] {
            let original = encode_insn(instruction, Target::H8S2000, Mode::Advanced).unwrap();
            let mut changed = original.clone();
            assert_eq!(retarget_field(&mut changed, field, width, value), Some(()));
            let after =
                h8_asm::isa::decode_insn(&changed, Target::H8S2000, Mode::Advanced).unwrap();
            assert_eq!(after.insn.mnemonic, instruction.mnemonic);
            assert_eq!(after.insn.operands[1..], instruction.operands[1..]);
            assert_eq!(retarget_field(&mut changed, field, width, value), Some(()));
            for bad in [0, field + 1, original.len()] {
                let mut invalid = original.clone();
                assert_eq!(retarget_field(&mut invalid, bad, width, value), None);
                assert_eq!(invalid, original);
            }
        }
    }
}
