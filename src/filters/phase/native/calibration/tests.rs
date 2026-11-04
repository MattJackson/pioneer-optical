use super::*;
use h8_asm::{
    isa::{self, Ea, Insn, Operand, Reg},
    Mode, Target,
};
use std::collections::BTreeMap;

fn instructions(bytes: &[u8]) -> BTreeMap<usize, (Insn, usize)> {
    let mut result = BTreeMap::new();
    let mut at = 0;
    while at < bytes.len() {
        let decoded = isa::decode_insn(&bytes[at..], Target::H8S2600, Mode::Advanced).unwrap();
        result.insert(at, (decoded.insn, decoded.len));
        at += decoded.len;
    }
    assert_eq!(at, bytes.len());
    result
}

struct Reader {
    registers: [u32; 8],
    saved: Vec<u32>,
    reads: Vec<u16>,
    words: [u16; 2],
    zero: bool,
}
impl Reader {
    fn get(&self, reg: Reg) -> u32 {
        match reg {
            Reg::Byte(n) => (self.registers[(n % 8) as usize] >> if n < 8 { 8 } else { 0 }) & 255,
            Reg::Word(n) => {
                (self.registers[(n % 8) as usize] >> if n < 8 { 0 } else { 16 }) & 65535
            }
            Reg::Long(n) => self.registers[n as usize],
            _ => panic!("unsupported register {reg:?}"),
        }
    }
    fn set(&mut self, reg: Reg, value: u32) {
        let (n, shift, mask) = match reg {
            Reg::Byte(n) => (n % 8, if n < 8 { 8 } else { 0 }, 255),
            Reg::Word(n) => (n % 8, if n < 8 { 0 } else { 16 }, 65535),
            Reg::Long(n) => (n, 0, u32::MAX),
            _ => panic!("unsupported register {reg:?}"),
        };
        let old = &mut self.registers[n as usize];
        *old = (*old & !(mask << shift)) | ((value & mask) << shift);
        self.zero = value & mask == 0;
    }
    fn value(&self, operand: Operand) -> u32 {
        match operand {
            Operand::Register(r) => self.get(r),
            Operand::Immediate { value, .. } => value,
            _ => panic!("{operand:?}"),
        }
    }
    fn run(program: &BTreeMap<usize, (Insn, usize)>, mode: u8, words: [u16; 2]) -> (u16, Vec<u16>) {
        let mut cpu = Self {
            registers: [0xa55a_5aa5; 8],
            saved: Vec::new(),
            reads: Vec::new(),
            words,
            zero: false,
        };
        cpu.set(Reg::Byte(8), mode.into());
        let original_r3 = cpu.registers[3];
        let mut at = 0;
        for _ in 0..64 {
            let (i, len) = program[&at];
            let [a, b, _] = i.operands;
            let next = at + len;
            at = next;
            match (i.mnemonic, a, b) {
                ("MOV", Operand::Register(r), Operand::Address(Ea::PreDecrement(Reg::Long(7)))) => {
                    cpu.saved.push(cpu.get(r))
                }
                (
                    "MOV",
                    Operand::Address(Ea::PostIncrement(Reg::Long(7))),
                    Operand::Register(r),
                ) => {
                    let v = cpu.saved.pop().unwrap();
                    cpu.set(r, v);
                }
                ("MOV", a, Operand::Register(r)) => cpu.set(r, cpu.value(a)),
                ("SUB", a, Operand::Register(r)) => {
                    cpu.set(r, cpu.get(r).wrapping_sub(cpu.value(a)))
                }
                ("AND", a, Operand::Register(r)) => cpu.set(r, cpu.get(r) & cpu.value(a)),
                ("CMP", a, b) => cpu.zero = cpu.value(a) == cpu.value(b),
                ("BRA" | "BEQ" | "BNE", Operand::Address(Ea::PcRelative { value, .. }), _) => {
                    if i.mnemonic == "BRA"
                        || (i.mnemonic == "BEQ" && cpu.zero)
                        || (i.mnemonic == "BNE" && !cpu.zero)
                    {
                        at = next.wrapping_add_signed(value as isize);
                    }
                }
                ("JSR", Operand::Address(Ea::Absolute { value, .. }), _) => {
                    assert_eq!(value, 0x410600);
                    let index = cpu.get(Reg::Word(0)) as u16;
                    assert!(matches!(index, 0x112 | 0x113));
                    cpu.reads.push(index);
                    cpu.set(Reg::Word(0), cpu.words[(index - 0x112) as usize].into());
                }
                ("NOP", _, _) => {}
                ("RTS", _, _) => {
                    assert!(cpu.saved.is_empty());
                    assert_eq!(cpu.registers[3], original_r3);
                    return (cpu.get(Reg::Word(0)) as u16, cpu.reads);
                }
                _ => panic!("unsupported reader instruction {i:?}"),
            }
        }
        panic!("reader did not terminate");
    }
}

fn fixture(packed: bool, address: u32) -> Vec<u8> {
    let mut normal = alloc::vec![0xff;0x800];
    let mut code = if packed {
        PACKED.to_vec()
    } else {
        WHOLE.to_vec()
    };
    for at in if packed {
        &[43usize, 53][..]
    } else {
        &[31usize][..]
    } {
        code[*at..*at + 3].copy_from_slice(&address.to_be_bytes()[1..]);
    }
    normal[0x100..0x100 + code.len()].copy_from_slice(&code);
    normal
}
fn program(normal: &[u8]) -> BTreeMap<usize, (Insn, usize)> {
    let bound = bind(normal).unwrap();
    instructions(
        &normal[bound.at
            ..bound.at
                + if bound.packed_shape {
                    PACKED.len()
                } else {
                    WHOLE.len()
                }],
    )
}

#[test]
fn rewritten_readers_preserve_consumed_calibration_bytes_for_every_word_and_mode() {
    let whole = fixture(false, 0x410600);
    let packed = fixture(true, 0x410600);
    let to_whole = rewrite(&packed, &fixture(false, 0x410700), None).unwrap();
    let to_packed = rewrite(&whole, &fixture(true, 0x410700), Some(0x300..0x344)).unwrap();
    let cases = [
        (program(&whole), false),
        (program(&packed), true),
        (program(&to_whole), false),
        (program(&to_packed), true),
    ];
    for word in 0..=u16::MAX {
        let words = [word, !word];
        for mode in 0..4u8 {
            let index = usize::from(mode / 2);
            for (program, packed) in &cases {
                let (actual, reads) = Reader::run(program, mode, words);
                let expected = if *packed && mode % 2 == 0 {
                    words[index] >> 8
                } else {
                    words[index] & 255
                };
                assert_eq!(
                    actual & 255,
                    expected,
                    "word {word:#x}, mode {mode}, packed {packed}"
                );
                assert_eq!(reads, [0x112 + index as u16]);
            }
        }
    }
    for mode in 4..=255 {
        for (program, _) in &cases {
            let (actual, reads) = Reader::run(program, mode, [0x0205, 0x0f06]);
            assert_eq!(actual & 255, 255);
            assert!(reads.is_empty());
        }
    }
}

#[test]
fn reader_binding_and_rewrite_refuse_partial_ambiguous_or_mismatched_getter_code() {
    let packed = fixture(true, 0x410600);
    let whole = fixture(false, 0x410600);
    for (template, holes) in [(PACKED, &[43usize, 53][..]), (WHOLE, &[31usize][..])] {
        let original = if template.len() == PACKED.len() {
            &packed
        } else {
            &whole
        };
        for i in 0..template.len() {
            if holes.iter().any(|at| (*at..*at + 3).contains(&i)) {
                continue;
            }
            let mut broken = original.clone();
            broken[0x100 + i] ^= 0x80;
            assert_eq!(observe(&broken), Err(Error::Unresolved), "{i}");
        }
    }
    let mut mismatch = packed.clone();
    mismatch[0x100 + 55] ^= 2;
    assert_eq!(observe(&mismatch), Err(Error::Unresolved));
    let mut duplicate = packed.clone();
    duplicate[0x200..0x200 + PACKED.len()].copy_from_slice(&packed[0x100..0x100 + PACKED.len()]);
    assert_eq!(observe(&duplicate), Err(Error::Unresolved));
    assert_eq!(rewrite(&whole, &packed, None), Err(Error::SpaceRequired));
    for space in [0x301..0x345, 0x300..0x320, 0x100..0x200, 0x300..0x900] {
        assert_eq!(
            rewrite(&whole, &packed, Some(space)),
            Err(Error::InvalidSpace)
        );
    }
}
