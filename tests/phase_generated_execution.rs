//! Execute OEM generated evaluators and compare opaque helper-call traces.
#![cfg(feature = "envelope")]
use h8_asm::{
    isa::{decode_insn, Ea, Insn, Operand as O, Reg, Size},
    Mode, Target,
};
use pioneer_optical::filters::phase::bundle::waveforms::resources::{evaluators, software};
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
            // Two deterministic opaque implementations. The equivalence proof
            // compares complete arguments/order, not an assumed ROM result.
            let value = if self.variant {
                a.rotate_left(7) ^ b.wrapping_mul(31)
            } else if to == self.binding.arithmetic[0] {
                a.wrapping_mul(b)
            } else if b == 0 {
                0
            } else {
                (a as i32).wrapping_div(b as i32) as u32
            };
            self.set(Reg::Long(0), value);
            if to == self.binding.arithmetic[1] {
                self.r[1] = a.rotate_right(3) ^ b;
            }
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

#[test]
fn generated_rotation_preserves_native_evaluator_calls_for_every_row_and_mode() {
    for hash in [
        "8037cdb3ae67e04a82aa3e9b7a0f52202e17f1e39d1f50b894158d9be0cec898",
        "99ba77ae1cedc967096c770b21c066d04a5163f1c5a4aa82f27584c6faced796",
    ] {
        let original = fixture(hash);
        let binding = evaluators::observe(&original).unwrap();
        let producer = software::observe_producer(&original).unwrap();
        let mut changed = original.clone();
        for row in 0..64 {
            let from = binding.basis.start + ((row + 16) % 64) * 4;
            let to = binding.basis.start + row * 4;
            changed[to..to + 4].copy_from_slice(&original[from..from + 4]);
        }
        for channel in 0..2 {
            for row in 0..64 {
                for magnitude in [0, 40, 65, 75, 100, 65535] {
                    for variant in [false, true] {
                        let calibration = [0, 1, -1, 32767, -32768, 1234, -2745, 42];
                        assert_eq!(
                            Cpu::run(
                                &changed,
                                (&binding, &producer),
                                channel,
                                row,
                                magnitude,
                                calibration,
                                variant
                            ),
                            Cpu::run(
                                &original,
                                (&binding, &producer),
                                channel,
                                (row + 16) % 64,
                                magnitude,
                                calibration,
                                variant
                            ),
                            "{hash} channel{channel} row{row} magnitude{magnitude}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn native_split_and_shared_evaluators_have_identical_opaque_call_arguments() {
    let target = fixture("8037cdb3ae67e04a82aa3e9b7a0f52202e17f1e39d1f50b894158d9be0cec898");
    let donor = fixture("99ba77ae1cedc967096c770b21c066d04a5163f1c5a4aa82f27584c6faced796");
    let changed = evaluators::rewrite_basis(&target, &donor).unwrap();
    let a = evaluators::observe(&changed).unwrap();
    let b = evaluators::observe(&donor).unwrap();
    let pa = software::observe_producer(&changed).unwrap();
    let pb = software::observe_producer(&donor).unwrap();
    let normalize = |result: (u16, Vec<(u32, u32, u32)>), binding: &evaluators::Binding| {
        (
            result.0,
            result
                .1
                .into_iter()
                .map(|(address, x, y)| {
                    let role = if address == binding.calibration_getter {
                        2
                    } else {
                        binding
                            .arithmetic
                            .iter()
                            .position(|a| *a == address)
                            .unwrap()
                    };
                    (role, x, y)
                })
                .collect::<Vec<_>>(),
        )
    };
    for channel in 0..2 {
        for row in 0..64 {
            for magnitude in [0, 40, 65, 75, 100, 65535] {
                for variant in [false, true] {
                    let calibration = [675, 1481, -646, -1476, 675, 1476, -657, -1486];
                    assert_eq!(
                        normalize(
                            Cpu::run(
                                &changed,
                                (&a, &pa),
                                channel,
                                row,
                                magnitude,
                                calibration,
                                variant
                            ),
                            &a
                        ),
                        normalize(
                            Cpu::run(
                                &donor,
                                (&b, &pb),
                                channel,
                                row,
                                magnitude,
                                calibration,
                                variant
                            ),
                            &b
                        ),
                        "channel{channel} row{row} magnitude{magnitude}"
                    );
                }
            }
        }
    }
}
