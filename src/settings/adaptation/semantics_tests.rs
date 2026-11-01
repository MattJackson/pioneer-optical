//! Bounded instruction-level tests of settings readers and relocated OEM code.
//! These execute the supported H8 subset with mocked reads, not a whole drive.
use super::*;
use h8_asm::{
    isa::{self, Ea, Insn, Operand, Reg, Size},
    Mode, Target,
};
use std::collections::BTreeMap;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("mechanism-fixture.json")).unwrap()
}
fn code(field: &str) -> Vec<u8> {
    hex(fixture()[field].as_str().unwrap()).unwrap()
}
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
                    assert!(matches!(value, 0x54ea7c | 0x55a44e));
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

#[test]
fn calibration_readers_preserve_word_selection_and_reverse_byte_conventions() {
    let native = code("calibration_native");
    let old = instructions(&code("calibration_old"));
    let inverse = registry()
        .unwrap()
        .0
        .iter()
        .find(|p| p.id == "pioneer.ud04-to-ud02-1.00")
        .unwrap();
    let cave = inverse
        .replacements
        .iter()
        .find(|r| r.offset == 0x400)
        .unwrap();
    let cave = hex(&cave.replacement_hex).unwrap();
    let restored = instructions(&cave[0xb8..0xb8 + 66]);
    let mut forward = native.clone();
    assert_eq!(&forward[56..58], &[0x0c, 0x08]);
    forward[56..58].fill(0);
    let forward = instructions(&forward);
    let native = instructions(&native);
    // Exhaust every value of both calibration words, with different values in
    // the two words, across all four valid modes. No unit's calibration is copied.
    for word in 0..=u16::MAX {
        let words = [word, !word];
        for mode in 0..4u8 {
            let index = usize::from(mode / 2);
            let value = words[index];
            let expected = if mode % 2 == 0 {
                value >> 8
            } else {
                value & 255
            };
            let (actual, reads) = Reader::run(&restored, mode, words);
            assert_eq!(actual, expected);
            assert_eq!(reads, [0x112 + index as u16]);
            assert_eq!(Reader::run(&native, mode, words).0, expected);
            assert_eq!(Reader::run(&forward, mode, words).0, value & 255);
            assert_eq!(Reader::run(&old, mode, words).0 & 255, value & 255);
        }
    }
    for mode in 4..=255u8 {
        let (value, reads) = Reader::run(&old, mode, [0x0205, 0x0f06]);
        assert_eq!(value & 255, 255);
        assert!(reads.is_empty());
        for p in [&forward, &native, &restored] {
            assert_eq!(Reader::run(p, mode, [0x0205, 0x0f06]), (255, vec![]));
        }
    }
}

#[test]
fn inverse_uses_native_routines_with_only_reviewed_relocations() {
    let fixture = fixture();
    let inverse = registry()
        .unwrap()
        .0
        .iter()
        .find(|p| p.id == "pioneer.ud04-to-ud02-1.00")
        .unwrap();
    let mut image = vec![0; inverse.input_length];
    for r in &inverse.replacements {
        let bytes = hex(&r.replacement_hex).unwrap();
        image[r.offset..r.offset + bytes.len()].copy_from_slice(&bytes);
    }
    let reloc = BTreeMap::from([
        (0x575990, 0x57cb8e),
        (0x575a00, 0x57cbfe),
        (0x57cf0e, 0x583fb0),
        (0x57cf0c, 0x583fae),
        (0x538c7a, 0x545d1e),
        (0x538b74, 0x545c00),
        (0x531a86, 0x53f538),
        (0x538b0c, 0x545b98),
        (0x54ea7c, 0x55a44e),
        (0x5b5c04, 0x59f088),
        (0x5b5c4c, 0x59f0d0),
    ]);
    for f in fixture["functions"].as_array().unwrap() {
        let entry = f["entry_offset"].as_u64().unwrap() as usize;
        let first = isa::decode_insn(&image[entry..], Target::H8S2600, Mode::Advanced).unwrap();
        let at = if first.insn.mnemonic == "JMP" {
            match first.insn.operands[0] {
                Operand::Address(Ea::Absolute { value, .. }) => value as usize - 0x410000,
                _ => panic!(),
            }
        } else {
            entry
        };
        let reference = hex(f["code"].as_str().unwrap()).unwrap();
        let actual = &image[at..at + reference.len()];
        let expected = instructions(&reference);
        let prepared = instructions(actual);
        assert_eq!(expected.len(), prepared.len());
        for (offset, (mut insn, len)) in expected {
            for operand in &mut insn.operands {
                match operand {
                    Operand::Address(Ea::Absolute { value, .. }) if insn.mnemonic == "JSR" => {
                        *value = reloc[value]
                    }
                    Operand::Immediate { value, .. }
                        if insn.size == Some(Size::Long) && reloc.contains_key(value) =>
                    {
                        *value = reloc[value]
                    }
                    _ => {}
                }
            }
            assert_eq!(
                prepared[&offset],
                (insn, len),
                "entry {entry:x}, instruction {offset:x}"
            );
        }
    }
}
