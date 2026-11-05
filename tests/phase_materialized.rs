//! Independently execute native evaluators and their actual Normal arithmetic.
#![cfg(feature = "envelope")]
use h8_asm::{
    isa::{decode_insn, Ea, Insn, Operand as O, Reg, Size},
    Mode, Target,
};
use pioneer_optical::filters::phase::bundle::waveforms::resources::{
    evaluators, materialized, software,
};
use std::collections::BTreeMap;

fn fixture(hash: &str) -> Vec<u8> {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-native-spans.json")).unwrap();
    let fixture = fixtures
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["original_sha256"].as_str() == Some(hash))
        .unwrap();
    let mut image = vec![0xff; fixture["size"].as_u64().unwrap() as usize];
    for span in fixture["spans"].as_array().unwrap() {
        let at = span[0].as_u64().unwrap() as usize;
        let bytes = span[1].as_str().unwrap();
        for i in 0..bytes.len() / 2 {
            image[at + i] = u8::from_str_radix(&bytes[2 * i..2 * i + 2], 16).unwrap();
        }
    }
    for raw in [
        include_str!("fixtures/phase-calibration-reader.json"),
        include_str!("fixtures/phase-materialized-arithmetic.json"),
    ] {
        let extra: serde_json::Value = serde_json::from_str(raw).unwrap();
        if extra["original_sha256"] == hash {
            for span in extra["spans"].as_array().unwrap() {
                let at = span[0].as_u64().unwrap() as usize;
                let hex = span[1].as_str().unwrap();
                for i in 0..hex.len() / 2 {
                    image[at + i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
                }
            }
        }
    }
    image
}
struct Cpu<'a> {
    image: &'a [u8],
    r: [u32; 8],
    stack: Vec<u32>,
    returns: Vec<usize>,
    positive: bool,
    zero: bool,
    carry: bool,
    less_equal: bool,
    calls: Vec<(u32, u32, u32)>,
    binding: evaluators::Binding,
    calibration: [i16; 8],
    variant: bool,
}
impl Cpu<'_> {
    fn coordinates(r: Reg) -> (usize, u32, u32) {
        match r {
            Reg::Byte(n) => ((n % 8) as usize, if n < 8 { 8 } else { 0 }, 255),
            Reg::Word(n) => ((n % 8) as usize, if n < 8 { 0 } else { 16 }, 65535),
            Reg::Long(n) => (n as usize, 0, u32::MAX),
            _ => panic!("register {r:?}"),
        }
    }
    fn get(&self, r: Reg) -> u32 {
        let (n, s, m) = Self::coordinates(r);
        (self.r[n] >> s) & m
    }
    fn set(&mut self, r: Reg, v: u32) {
        let (n, s, m) = Self::coordinates(r);
        self.r[n] = (self.r[n] & !(m << s)) | ((v & m) << s);
        self.zero = v & m == 0;
        self.positive = ((v & m) & ((m >> 1) + 1)) == 0;
        self.less_equal = self.zero || !self.positive;
    }
    fn value(&self, o: O) -> u32 {
        match o {
            O::Register(r) => self.get(r),
            O::Immediate { value, .. } => value,
            _ => panic!("value {o:?}"),
        }
    }
    fn load(&self, address: u32, size: Size) -> u32 {
        let at = address.checked_sub(0x410000).unwrap() as usize;
        match size {
            Size::Word => u16::from_be_bytes(self.image[at..at + 2].try_into().unwrap()).into(),
            Size::Long => u32::from_be_bytes(self.image[at..at + 4].try_into().unwrap()),
            _ => panic!("size {size:?}"),
        }
    }
    fn signed(v: u32, size: Size) -> i64 {
        match size {
            Size::Byte => (v as i8).into(),
            Size::Word => (v as i16).into(),
            Size::Long => (v as i32).into(),
        }
    }
    fn call(&mut self, to: u32) {
        if to == self.binding.calibration_getter {
            let mode = self.get(Reg::Byte(8));
            self.calls.push((to, mode, 0));
            if self.variant {
                // Parameter-backed services may clobber these scratch lanes;
                // the fixed-value leaf does not. Neither evaluator may depend
                // on that difference after consuming the returned word.
                self.r[0] = 0xdead0000;
                self.r[1] = 0x13579bdf;
                self.r[2] = 0x2468ace0;
                self.r[3] = 0x89abcdef;
            }
            self.set(Reg::Word(0), self.calibration[mode as usize] as u16 as u32);
        } else {
            assert!(self.binding.arithmetic.contains(&to));
            let (a, b) = (self.r[0], self.r[1]);
            self.calls.push((to, a, b));
            let (quotient, remainder) =
                arithmetic::execute(self.image, &self.binding, to, a as i32, b as i32);
            self.set(Reg::Long(0), quotient as u32);
            self.r[1] = remainder as u32;
        }
    }
    fn run(
        image: &[u8],
        contract: (&evaluators::Binding, &software::Producer),
        channel: usize,
        row: u8,
        magnitude: u16,
        calibration: [i16; 8],
        variant: bool,
    ) -> (u16, Vec<(u32, u32, u32)>) {
        let (binding, producer) = contract;
        let mut program = BTreeMap::<usize, (Insn, usize)>::new();
        for span in &binding.programs {
            let mut at = span.start;
            while at < span.end {
                let d = decode_insn(&image[at..span.end], Target::H8S2000, Mode::Advanced).unwrap();
                program.insert(at, (d.insn, d.len));
                at += d.len;
            }
        }
        let mut c = Cpu {
            image,
            r: [0xa55a_1357; 8],
            stack: vec![],
            returns: vec![],
            positive: false,
            zero: false,
            carry: false,
            less_equal: false,
            calls: vec![],
            calibration,
            variant,
            binding: binding.clone(),
        };
        c.set(Reg::Word(8), magnitude.into());
        c.set(Reg::Byte(8), row.into());
        let original = c.r;
        let mut pc = producer.evaluators[channel] as usize - 0x410000;
        for _ in 0..5000 {
            let (i, len) = program[&pc];
            pc += len;
            let [a, b, _] = i.operands;
            match (i.mnemonic, a, b) {
                ("MOV", O::Register(r), O::Address(Ea::PreDecrement(Reg::Long(7)))) => {
                    c.stack.push(c.get(r))
                }
                ("MOV", O::Address(Ea::PostIncrement(Reg::Long(7))), O::Register(r)) => {
                    let v = c.stack.pop().unwrap();
                    c.set(r, v);
                }
                ("STM", O::Registers { first, last }, _) => {
                    for r in first..=last {
                        c.stack.push(c.r[r as usize]);
                    }
                }
                ("LDM", _, O::Registers { first, last }) => {
                    for r in (first..=last).rev() {
                        c.r[r as usize] = c.stack.pop().unwrap();
                    }
                }
                ("MOV", O::Address(Ea::Absolute { value, .. }), O::Register(r)) => {
                    c.set(r, c.load(value, i.size.unwrap()))
                }
                ("MOV", O::Address(Ea::Indirect(r)), O::Register(to)) => {
                    c.set(to, c.load(c.get(r), i.size.unwrap()))
                }
                ("MOV", O::Address(Ea::Displacement { base, value, .. }), O::Register(r)) => c.set(
                    r,
                    c.load(c.get(base).wrapping_add(value as u32), i.size.unwrap()),
                ),
                ("MOV", a, O::Register(r)) => c.set(r, c.value(a)),
                ("EXTU", O::Register(Reg::Word(r)), _) => {
                    c.set(Reg::Word(r), c.get(Reg::Word(r)) & 255)
                }
                ("EXTU", O::Register(Reg::Long(r)), _) => {
                    c.set(Reg::Long(r), c.get(Reg::Word(r)));
                }
                ("EXTS", O::Register(Reg::Long(r)), _) => {
                    c.set(Reg::Long(r), c.get(Reg::Word(r)) as i16 as i32 as u32)
                }
                ("SHLL" | "SHAL", a, O::Register(r)) => c.set(r, c.get(r) << c.value(a)),
                ("ADD", a, O::Register(r)) => c.set(r, c.get(r).wrapping_add(c.value(a))),
                ("SUB", a, O::Register(r)) => c.set(r, c.get(r).wrapping_sub(c.value(a))),
                ("AND", a, O::Register(r)) => c.set(r, c.get(r) & c.value(a)),
                ("NEG", O::Register(r), _) => c.set(r, c.get(r).wrapping_neg()),
                ("INC", O::Register(r), _) => c.set(r, c.get(r).wrapping_add(1)),
                ("INC", a, O::Register(r)) => c.set(r, c.get(r).wrapping_add(c.value(a))),
                ("CMP", a, b) => {
                    let a = c.value(a);
                    let b = c.value(b);
                    c.zero = a == b;
                    c.carry = b < a;
                    c.positive =
                        Self::signed(b, i.size.unwrap()) >= Self::signed(a, i.size.unwrap());
                    c.less_equal =
                        Self::signed(b, i.size.unwrap()) <= Self::signed(a, i.size.unwrap());
                }
                (
                    "BRA" | "BNE" | "BEQ" | "BCS" | "BCC" | "BLE" | "BGE" | "BLT",
                    O::Address(Ea::PcRelative { value, .. }),
                    _,
                ) => {
                    let take = match i.mnemonic {
                        "BRA" => true,
                        "BNE" => !c.zero,
                        "BEQ" => c.zero,
                        "BGE" => c.positive,
                        "BLT" => !c.positive,
                        "BCS" => c.carry,
                        "BCC" => !c.carry,
                        "BLE" => c.less_equal,
                        _ => unreachable!(),
                    };
                    if take {
                        pc = pc.checked_add_signed(value as isize).unwrap();
                    }
                }
                ("JMP", O::Address(Ea::Absolute { value, .. }), _) => {
                    pc = value as usize - 0x410000
                }
                ("BSR", O::Address(Ea::PcRelative { value, .. }), _) => {
                    c.returns.push(pc);
                    pc = pc.checked_add_signed(value as isize).unwrap();
                }
                ("JSR", O::Address(Ea::Absolute { value, .. }), _) => c.call(value),
                ("JSR", O::Address(Ea::Indirect(r)), _) => c.call(c.get(r)),
                ("NOP", _, _) => {}
                ("RTS", _, _) => {
                    if let Some(to) = c.returns.pop() {
                        pc = to;
                        continue;
                    }
                    assert!(c.stack.is_empty());
                    assert_eq!(&c.r[4..7], &original[4..7]);
                    return (c.r[0] as u16, c.calls);
                }
                _ => panic!("unsupported native evaluator instruction {i:?}"),
            }
        }
        panic!("native evaluator did not terminate");
    }
}

mod arithmetic {
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
                            let (v, w) = c.saved.pop().unwrap();
                            c.r[r as usize] = v;
                            c.r[7] += w;
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
                    (
                        "BRA" | "BNE" | "BPL" | "BCC",
                        O::Address(Ea::PcRelative { value, .. }),
                        _,
                    ) => {
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

    pub(super) fn execute(
        image: &[u8],
        eval: &super::evaluators::Binding,
        entry: u32,
        a: i32,
        b: i32,
    ) -> (i32, i32) {
        let binding = pioneer_optical::filters::phase::native::arithmetic::observe(
            image,
            0x410000,
            eval.arithmetic[0],
            eval.arithmetic[1],
        )
        .unwrap();
        let mut program = BTreeMap::new();
        for span in [
            binding.multiply,
            binding.signed_divide,
            binding.unsigned_divide,
        ] {
            let mut at = span.start;
            while at < span.end {
                let d = decode_insn(&image[at..span.end], Target::H8S2000, Mode::Advanced).unwrap();
                program.insert(0x410000 + at as u32, (d.insn, d.len));
                at += d.len;
            }
        }
        Cpu::run(&program, entry, a, b, false)
    }
}

#[test]
fn every_materialized_word_equals_executed_native_evaluator_and_primitives() {
    let donor = fixture("8037cdb3ae67e04a82aa3e9b7a0f52202e17f1e39d1f50b894158d9be0cec898");
    let proof = materialized::prove(&donor).unwrap();
    assert_eq!(
        proof.tables.iter().map(|t| t.mode).collect::<Vec<_>>(),
        [Some(1), Some(3), Some(2), None]
    );
    assert_eq!(
        proof.tables.iter().map(|t| t.magnitude).collect::<Vec<_>>(),
        [40, 75, 65, 100]
    );
    assert_eq!(
        proof
            .required_words
            .iter()
            .map(|w| (w.parameter, w.value))
            .collect::<Vec<_>>(),
        (0x30..=0x37).map(|p| (p, 0xffff)).collect::<Vec<_>>()
    );
    // Decode the producer's actual repeated shifts; 0x1050 shifts two bits.
    let bytes = &donor[proof.source.producer.program.clone()];
    let mut shift = 0;
    let at = bytes
        .windows(6)
        .position(|b| b == [0x10, 0x50, 0x10, 0x50, 0x10, 0x50])
        .unwrap();
    for offset in (at..at + 6).step_by(2) {
        let d = decode_insn(&bytes[offset..], Target::H8S2000, Mode::Advanced).unwrap();
        assert_eq!(d.insn.mnemonic, "SHLL");
        let O::Immediate { value, .. } = d.insn.operands[0] else {
            panic!()
        };
        shift += value;
    }
    assert_eq!(shift, 6);
    for table in &proof.tables {
        for row in 0..64 {
            for channel in 0..2 {
                let (result, _) = Cpu::run(
                    &donor,
                    (&proof.source.evaluator, &proof.source.producer),
                    channel,
                    row as u8,
                    table.magnitude,
                    proof.calibration,
                    false,
                );
                let at = row * 4 + channel * 2;
                assert_eq!(
                    &table.bytes[at..at + 2],
                    &result.wrapping_shl(shift).to_be_bytes(),
                    "mode {:?} row {row} channel {channel}",
                    table.mode
                );
            }
        }
    }
    for span in [
        proof.arithmetic.multiply,
        proof.arithmetic.signed_divide,
        proof.arithmetic.unsigned_divide,
    ] {
        let mut broken = donor.clone();
        broken[span.start] ^= 1;
        assert!(materialized::prove(&broken).is_err());
    }
    assert!(materialized::prove(&fixture(
        "99ba77ae1cedc967096c770b21c066d04a5163f1c5a4aa82f27584c6faced796"
    ))
    .is_err());
}

// Execute the complete native producer prelude and all 128 paired-word stores.
// Diagnostic reporting follows the finished table and is not a table producer.
fn produce(image: &[u8], proof: &materialized::Proof, mode: u8) -> (u32, [u8; 256]) {
    let mut r = [0xa55a_1357u32; 8];
    r[0] = (r[0] & !255) | u32::from(mode);
    r[7] = 0x8000;
    let get = |r: &[u32; 8], reg| {
        let (n, s, m) = Cpu::coordinates(reg);
        (r[n] >> s) & m
    };
    let val = |r: &[u32; 8], operand| match operand {
        O::Immediate { value, .. } => value,
        O::Register(reg) => get(r, reg),
        _ => panic!("value {operand:?}"),
    };
    let set = |r: &mut [u32; 8], reg, value| {
        let (n, s, m) = Cpu::coordinates(reg);
        r[n] = (r[n] & !(m << s)) | ((value & m) << s);
    };
    let mut memory = BTreeMap::<u32, u8>::new();
    let mut zero = false;
    let mut carry = false;
    let mut less_equal = false;
    let mut positive = false;
    let mut stores = 0;
    let mut pc = proof.source.producer.program.start;
    let chosen = proof
        .tables
        .iter()
        .find(|t| t.mode == Some(mode))
        .unwrap_or(&proof.tables[3]);
    for _ in 0..10000 {
        let d = decode_insn(
            &image[pc..proof.source.producer.program.end],
            Target::H8S2000,
            Mode::Advanced,
        )
        .unwrap();
        let i = d.insn;
        let [a, b, _] = i.operands;
        pc += d.len;
        let address = |r: &[u32; 8], operand| match operand {
            O::Address(Ea::Indirect(base)) => get(r, base),
            O::Address(Ea::Displacement { base, value, .. }) => {
                get(r, base).wrapping_add(value as u32)
            }
            _ => panic!("address {operand:?}"),
        };
        let mut assignment = None;
        match (i.mnemonic, a, b) {
            ("STM", O::Registers { first, last }, _) => {
                for n in first..=last {
                    r[7] -= 4;
                    for (i, byte) in r[n as usize].to_be_bytes().iter().enumerate() {
                        memory.insert(r[7] + i as u32, *byte);
                    }
                }
            }
            ("MOV", O::Register(reg), O::Address(Ea::PreDecrement(Reg::Long(7)))) => {
                r[7] -= 4;
                for (i, byte) in get(&r, reg).to_be_bytes().iter().enumerate() {
                    memory.insert(r[7] + i as u32, *byte);
                }
            }
            ("MOV", O::Register(reg), O::Address(_)) => {
                let at = address(&r, b);
                let n = match i.size.unwrap() {
                    Size::Byte => 1,
                    Size::Word => 2,
                    Size::Long => 4,
                };
                let value = get(&r, reg).to_be_bytes();
                for i in 0..n {
                    memory.insert(at + i as u32, value[4 - n + i]);
                }
                if (chosen.source..chosen.source + 256).contains(&at) {
                    assert_eq!(n, 2);
                    stores += 1;
                }
            }
            ("MOV", O::Address(_), O::Register(reg)) => {
                let at = address(&r, a);
                let n = match i.size.unwrap() {
                    Size::Byte => 1,
                    Size::Word => 2,
                    Size::Long => 4,
                };
                let value = (0..n).fold(0, |v, j| {
                    (v << 8) | u32::from(*memory.get(&(at + j)).unwrap())
                });
                assignment = Some((reg, value));
            }
            ("MOV", a, O::Register(reg)) => assignment = Some((reg, val(&r, a))),
            ("SUB", a, O::Register(reg)) => {
                assignment = Some((reg, get(&r, reg).wrapping_sub(val(&r, a))))
            }
            ("ADD", a, O::Register(reg)) => {
                assignment = Some((reg, get(&r, reg).wrapping_add(val(&r, a))))
            }
            ("SHLL", a, O::Register(reg)) => {
                assignment = Some((reg, get(&r, reg).wrapping_shl(val(&r, a))))
            }
            ("INC", O::Register(reg), O::None) => {
                assignment = Some((reg, get(&r, reg).wrapping_add(1)))
            }
            ("INC", a, O::Register(reg)) => {
                assignment = Some((reg, get(&r, reg).wrapping_add(val(&r, a))))
            }
            ("CMP", a, b) => {
                let a = val(&r, a);
                let b = val(&r, b);
                zero = a == b;
                carry = b < a;
                less_equal = Cpu::signed(b, i.size.unwrap()) <= Cpu::signed(a, i.size.unwrap());
                positive = Cpu::signed(b, i.size.unwrap()) >= Cpu::signed(a, i.size.unwrap());
            }
            (
                "BRA" | "BNE" | "BEQ" | "BCS" | "BLE" | "BGE",
                O::Address(Ea::PcRelative { value, .. }),
                _,
            ) => {
                let take = match i.mnemonic {
                    "BRA" => true,
                    "BNE" => !zero,
                    "BEQ" => zero,
                    "BCS" => carry,
                    "BLE" => less_equal,
                    "BGE" => positive,
                    _ => unreachable!(),
                };
                if take {
                    pc = pc.checked_add_signed(value as isize).unwrap();
                }
            }
            ("JSR", O::Address(Ea::Absolute { value, .. }), _) => {
                let channel = proof
                    .source
                    .producer
                    .evaluators
                    .iter()
                    .position(|v| *v == value)
                    .unwrap();
                let row = get(&r, Reg::Byte(8)) as u8;
                let magnitude = get(&r, Reg::Word(8)) as u16;
                assert_eq!(magnitude, chosen.magnitude);
                let (word, _) = Cpu::run(
                    image,
                    (&proof.source.evaluator, &proof.source.producer),
                    channel,
                    row,
                    magnitude,
                    proof.calibration,
                    false,
                );
                assignment = Some((Reg::Word(0), u32::from(word)));
            }
            _ => panic!("producer instruction {i:?}"),
        }
        if let Some((reg, value)) = assignment {
            set(&mut r, reg, value);
            let (_, _, mask) = Cpu::coordinates(reg);
            zero = value & mask == 0;
        }
        if stores == 128 {
            assert_eq!(r[6], chosen.source);
            return (
                chosen.source,
                core::array::from_fn(|i| memory[&(chosen.source + i as u32)]),
            );
        }
    }
    panic!("producer failed to produce complete native table")
}

#[test]
fn native_producer_loop_stores_all_four_materialized_tables() {
    let donor = fixture("8037cdb3ae67e04a82aa3e9b7a0f52202e17f1e39d1f50b894158d9be0cec898");
    let proof = materialized::prove(&donor).unwrap();
    for mode in [0, 1, 2, 3, 4, 255] {
        let table = proof
            .tables
            .iter()
            .find(|t| t.mode == Some(mode))
            .unwrap_or(&proof.tables[3]);
        let (address, bytes) = produce(&donor, &proof, mode);
        assert_eq!(address, table.source);
        assert_eq!(bytes, table.bytes, "mode {mode}");
    }
}

#[test]
fn materialization_guards_and_every_emitted_byte_remain_mandatory() {
    use pioneer_optical::filters::prerequisites::{self, OwnedWord};
    let donor = fixture("8037cdb3ae67e04a82aa3e9b7a0f52202e17f1e39d1f50b894158d9be0cec898");
    let proof = materialized::prove(&donor).unwrap();
    materialized::verify(&donor, &proof).unwrap();
    let guards: Vec<_> = proof
        .required_words
        .iter()
        .map(|word| OwnedWord {
            filter: "phase",
            word: *word,
        })
        .collect();
    prerequisites::check(&guards, |_| Ok::<_, ()>(0xffff)).unwrap();
    for changed in 0x30..=0x37 {
        assert!(
            prerequisites::check(&guards, |parameter| Ok::<_, ()>(if parameter == changed {
                0
            } else {
                0xffff
            }))
            .is_err()
        );
    }
    let mut broken = proof.clone();
    broken.required_words.clear();
    assert!(materialized::verify(&donor, &broken).is_err());
    for role in 0..4 {
        let mut broken = proof.clone();
        broken.tables[role].bytes[255] ^= 1;
        assert!(materialized::verify(&donor, &broken).is_err());
    }
}
