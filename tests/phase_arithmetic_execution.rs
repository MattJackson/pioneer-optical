//! Execute the held OEM divider instructions against independent Rust results.
#![cfg(feature = "envelope")]
#![cfg(feature = "internals")]
use h8_asm::{
    isa::{decode_insn, Ea, Insn, Operand as O, Reg},
    Mode, Target,
};
use std::collections::BTreeMap;

struct Cpu {
    r: [u32; 8],
    zero: bool,
    negative: bool,
    carry: bool,
    saved: Vec<(u32, u32)>,
    returns: Vec<u32>,
}
impl Cpu {
    fn coordinates(reg: Reg) -> (usize, u32, u32) {
        match reg {
            Reg::Byte(n) => ((n % 8) as usize, if n < 8 { 8 } else { 0 }, 0xff),
            Reg::Word(n) => ((n % 8) as usize, if n < 8 { 0 } else { 16 }, 0xffff),
            Reg::Long(n) => (n as usize, 0, u32::MAX),
            _ => panic!("register {reg:?}"),
        }
    }
    fn get(&self, reg: Reg) -> u32 {
        let (n, shift, mask) = Self::coordinates(reg);
        (self.r[n] >> shift) & mask
    }
    fn set(&mut self, reg: Reg, value: u32) {
        let (n, shift, mask) = Self::coordinates(reg);
        self.r[n] = (self.r[n] & !(mask << shift)) | ((value & mask) << shift);
        self.zero = value & mask == 0;
        self.negative = value & (mask ^ (mask >> 1)) != 0;
    }
    fn value(&self, operand: O) -> u32 {
        match operand {
            O::Register(r) => self.get(r),
            O::Immediate { value, .. } => value,
            _ => panic!("operand {operand:?}"),
        }
    }
    fn run(
        program: &BTreeMap<u32, (Insn, usize)>,
        entry: u32,
        numerator: i32,
        divisor: i32,
        initial_carry: bool,
    ) -> (i32, i32) {
        let mut c = Self {
            r: [0x1357_9bdf; 8],
            zero: false,
            negative: false,
            carry: initial_carry,
            saved: Vec::new(),
            returns: Vec::new(),
        };
        c.r[0] = numerator as u32;
        c.r[1] = divisor as u32;
        c.r[7] = 0x8000;
        let mut pc = entry;
        for _ in 0..256 {
            let (i, len) = program[&pc];
            let [a, b, _] = i.operands;
            pc += len as u32;
            match (i.mnemonic, a, b) {
                ("MOV", O::Register(r), O::Address(Ea::PreDecrement(Reg::Long(7)))) => {
                    let width = if matches!(r, Reg::Long(_)) { 4 } else { 2 };
                    c.saved.push((c.get(r), width));
                    c.r[7] -= width;
                }
                ("MOV", O::Address(Ea::PostIncrement(Reg::Long(7))), O::Register(r)) => {
                    let (v, width) = c.saved.pop().unwrap();
                    c.set(r, v);
                    c.r[7] += width;
                }
                ("STM", O::Registers { first, last }, _) => {
                    for r in first..=last {
                        c.saved.push((c.r[r as usize], 4));
                        c.r[7] -= 4;
                    }
                }
                ("LDM", _, O::Registers { first, last }) => {
                    for r in (first..=last).rev() {
                        let (value, width) = c.saved.pop().unwrap();
                        c.r[r as usize] = value;
                        c.r[7] += width;
                    }
                }
                ("MULXU", O::Register(from), O::Register(Reg::Long(to))) => {
                    c.set(Reg::Long(to), c.get(from) * (c.r[to as usize] & 0xffff));
                }
                ("MOV", a, O::Register(r)) => c.set(r, c.value(a)),
                ("XOR", a, O::Register(r)) => c.set(r, c.get(r) ^ c.value(a)),
                ("NEG", O::Register(r), _) => {
                    let v = c.get(r);
                    c.carry = v != 0;
                    c.set(r, v.wrapping_neg());
                }
                ("EXTU", O::Register(Reg::Long(r)), _) => {
                    c.set(Reg::Long(r), c.r[r as usize] & 0xffff)
                }
                ("NOT", O::Register(r), _) => c.set(r, !c.get(r)),
                ("DEC", a, O::Register(r)) => c.set(r, c.get(r).wrapping_sub(c.value(a))),
                ("SUB", a, O::Register(r)) => {
                    let v = c.get(r);
                    let rhs = c.value(a);
                    c.carry = v < rhs;
                    c.set(r, v.wrapping_sub(rhs));
                }
                ("ADD", a, O::Register(r)) => {
                    let (v, carry) = c.get(r).overflowing_add(c.value(a));
                    c.carry = carry;
                    c.set(r, v);
                }
                ("ROTXL", O::Immediate { value: 1, .. }, O::Register(r)) => {
                    let v = c.get(r);
                    let (_, _, mask) = Self::coordinates(r);
                    let incoming = u32::from(c.carry);
                    c.carry = v & (mask ^ (mask >> 1)) != 0;
                    c.set(r, (v << 1) | incoming);
                }
                ("DIVXU", O::Register(from), O::Register(Reg::Long(to))) => {
                    let n = c.r[to as usize];
                    let d = c.get(from);
                    assert_ne!(d, 0, "excluded divide-by-zero input");
                    assert!(n / d <= 0xffff, "native short division overflow");
                    c.set(Reg::Long(to), ((n % d) << 16) | (n / d));
                }
                ("JSR", O::Address(Ea::Absolute { value, .. }), _) => {
                    c.returns.push(pc);
                    c.r[7] -= 4;
                    pc = value;
                }
                ("RTS", _, _) => {
                    if let Some(ret) = c.returns.pop() {
                        c.r[7] += 4;
                        pc = ret;
                    } else {
                        assert!(c.saved.is_empty());
                        assert_eq!(c.r[7], 0x8000);
                        assert!(c.r[2..7].iter().all(|r| *r == 0x1357_9bdf));
                        return (c.r[0] as i32, c.r[1] as i32);
                    }
                }
                ("BRA" | "BNE" | "BPL" | "BCC", O::Address(Ea::PcRelative { value, .. }), _) => {
                    let take = match i.mnemonic {
                        "BRA" => true,
                        "BNE" => !c.zero,
                        "BPL" => !c.negative,
                        "BCC" => !c.carry,
                        _ => unreachable!(),
                    };
                    if take {
                        pc = pc.wrapping_add_signed(value);
                    }
                }
                other => panic!("unsupported division instruction {other:?}"),
            }
        }
        panic!("native divider did not return")
    }
}

#[test]
fn oem_signed_divider_returns_truncated_quotient_and_signed_remainder() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-native-arithmetic.json")).unwrap();
    for fixture in fixtures.as_array().unwrap() {
        let base = fixture["base"].as_u64().unwrap() as u32;
        let entry = fixture["divide"].as_u64().unwrap() as u32;
        let mut program = BTreeMap::new();
        for span in fixture["spans"].as_array().unwrap() {
            let address = base + span[0].as_u64().unwrap() as u32;
            if address == fixture["multiply"].as_u64().unwrap() as u32 {
                continue;
            }
            let text = span[1].as_str().unwrap();
            let bytes: Vec<_> = (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect();
            let mut at = 0;
            while at < bytes.len() {
                let d = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced).unwrap();
                program.insert(address + at as u32, (d.insn, d.len));
                at += d.len;
            }
        }
        let check = |a: i32, b: i32| {
            if b == 0 || (a == i32::MIN && b == -1) {
                return;
            }
            for carry in [false, true] {
                assert_eq!(
                    Cpu::run(&program, entry, a, b, carry),
                    (a / b, a % b),
                    "{a}/{b}, carry={carry}"
                );
            }
        };
        let edges = [
            i32::MIN,
            i32::MIN + 1,
            -0x10001,
            -0x10000,
            -0xffff,
            -125,
            -3,
            -1,
            0,
            1,
            3,
            125,
            0xffff,
            0x10000,
            0x10001,
            i32::MAX,
        ];
        for a in edges {
            for b in edges {
                check(a, b);
            }
        }
        for a in i16::MIN..=i16::MAX {
            for b in [3, 18, 64, 100, 125, -3, -125] {
                check(i32::from(a), b);
            }
        }
        let mut random = 0x9e37_79b9u32;
        for _ in 0..10000 {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            let a = random as i32;
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            check(a, random as i32);
        }
    }
}

#[test]
fn emitted_services_match_committed_pr1_source_and_native_execution() {
    use pioneer_optical::filters::phase::native::arithmetic;
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-generated-arithmetic.json")).unwrap();
    let source = &fixture[0];
    assert_eq!(
        source["normal"].as_str().unwrap(),
        arithmetic::OEM_SOURCE_SHA256
    );
    let native_entries = [0x623c4a, 0x6238a4, 0x6238ca];
    let emitted = arithmetic::emit(native_entries).unwrap();
    for (i, span) in source["spans"].as_array().unwrap().iter().enumerate() {
        assert_eq!(span[0].as_u64().unwrap(), u64::from(native_entries[i]));
        let hex = span[1].as_str().unwrap();
        let expected: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect();
        assert_eq!(emitted[i], expected);
    }
    for entries in [
        [0x410100, 0x410200, 0x410300],
        [0x410900, 0x410500, 0x410100],
    ] {
        let bodies = arithmetic::emit(entries).unwrap();
        assert_eq!(bodies.each_ref().map(Vec::len), arithmetic::lengths());
        let mut image = vec![0xff; 0x1000];
        let mut program = BTreeMap::new();
        for (entry, body) in entries.into_iter().zip(&bodies) {
            let offset = (entry - 0x410000) as usize;
            image[offset..offset + body.len()].copy_from_slice(body);
            let mut at = 0;
            while at < body.len() {
                let d = decode_insn(&body[at..], Target::H8S2000, Mode::Advanced).unwrap();
                program.insert(entry + at as u32, (d.insn, d.len));
                at += d.len;
            }
        }
        let bound = arithmetic::observe(&image, 0x410000, entries[0], entries[1]).unwrap();
        assert_eq!(
            bound.unsigned_divide.start,
            (entries[2] - 0x410000) as usize
        );
        let check = |a: u32, b: u32| {
            for carry in [false, true] {
                let (product, unchanged) =
                    Cpu::run(&program, entries[0], a as i32, b as i32, carry);
                assert_eq!(product as u32, a.wrapping_mul(b));
                assert_eq!(unchanged as u32, b);
                if b != 0 {
                    let (q, r) = Cpu::run(&program, entries[2], a as i32, b as i32, carry);
                    assert_eq!((q as u32, r as u32), (a / b, a % b));
                    let (a, b) = (a as i32, b as i32);
                    if (a, b) != (i32::MIN, -1) {
                        assert_eq!(Cpu::run(&program, entries[1], a, b, carry), (a / b, a % b));
                    }
                }
            }
        };
        let edges = [
            0, 1, 3, 0xffff, 0x10000, 0x10001, 0x7fffffff, 0x80000000, 0xffffffff,
        ];
        for a in edges {
            for b in edges {
                check(a, b);
            }
        }
        let mut random = 0x9e3779b9u32;
        for _ in 0..10000 {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            let a = random;
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            check(a, random);
        }
    }
}

#[test]
fn arithmetic_emission_rejects_aliases_unaligned_and_overflowing_entries() {
    use pioneer_optical::filters::phase::native::arithmetic;
    for entries in [
        [0x410001, 0x410100, 0x410200],
        [0x410000, 0x410010, 0x410200],
        [0x410000, 0x410100, 0xfffffe],
        [0xfffffffe, 0x410100, 0x410200],
    ] {
        assert!(arithmetic::emit(entries).is_none());
    }
}
