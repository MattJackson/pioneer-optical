//! Execute actual held OEM output callers and leaves over every source word.
#![cfg(feature = "envelope")]
use h8_asm::{
    isa::{decode_insn, Ea, Insn, Operand as O, Reg, Size},
    Mode, Target,
};
use pioneer_optical::filters::phase::native::encoders::{self, Representation};
use std::collections::BTreeMap;
const HASHES: [&str; 3] = [
    "8037cdb3ae67e04a82aa3e9b7a0f52202e17f1e39d1f50b894158d9be0cec898",
    "99ba77ae1cedc967096c770b21c066d04a5163f1c5a4aa82f27584c6faced796",
    "84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750",
];
fn fixture(hash: &str) -> Vec<u8> {
    let all: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-native-spans.json")).unwrap();
    let f = all
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["original_sha256"] == hash)
        .unwrap();
    let mut n = vec![255; f["size"].as_u64().unwrap() as usize];
    let leaves: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-encoder-leaves.json")).unwrap();
    for f in std::iter::once(f).chain(
        leaves
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["original_sha256"] == hash),
    ) {
        for s in f["spans"].as_array().unwrap() {
            let at = s[0].as_u64().unwrap() as usize;
            let h = s[1].as_str().unwrap();
            for i in 0..h.len() / 2 {
                n[at + i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
            }
        }
    }
    n
}
struct Program {
    code: BTreeMap<usize, (Insn, usize)>,
}
impl Program {
    fn new(n: &[u8], entries: &[usize]) -> Self {
        let binding = encoders::observe(n).unwrap();
        let mut code = BTreeMap::new();
        for span in binding
            .programs
            .iter()
            .flatten()
            .cloned()
            .chain([binding.leaf])
        {
            let mut at = span.start;
            while at < span.end {
                let d = decode_insn(&n[at..span.end], Target::H8S2000, Mode::Advanced).unwrap();
                code.insert(at, (d.insn, d.len));
                at += d.len;
            }
        }
        for at in entries {
            let d = decode_insn(&n[*at..], Target::H8S2000, Mode::Advanced).unwrap();
            code.insert(*at, (d.insn, d.len));
        }
        Self { code }
    }
    fn run(&self, entry: usize, word: u16) -> Vec<(u32, u8)> {
        let mut r = [0xa55a_1357u32; 8];
        r[0] = u32::from(word & 63);
        r[1] = 0xa01000;
        let row = r[0];
        let initial = r;
        let mut pc = entry;
        let mut stack = Vec::new();
        let mut returns = Vec::new();
        let mut writes = Vec::new();
        for _ in 0..100 {
            let (i, len) = self.code[&pc];
            pc += len;
            let [a, b, _] = i.operands;
            let value = |o| match o {
                O::Register(reg) => get(&r, reg),
                O::Immediate { value, .. } => value,
                _ => panic!("{o:?}"),
            };
            match (i.mnemonic, a, b) {
                ("MOV", O::Register(reg), O::Address(Ea::PreDecrement(Reg::Long(7)))) => {
                    stack.push(get(&r, reg))
                }
                ("MOV", O::Address(Ea::PostIncrement(Reg::Long(7))), O::Register(reg)) => {
                    set(&mut r, reg, stack.pop().unwrap())
                }
                ("MOV", O::Register(reg), O::Address(Ea::Absolute { value: address, .. })) => {
                    assert_eq!(i.size, Some(Size::Byte));
                    writes.push((address, get(&r, reg) as u8));
                }
                ("MOV", O::Address(ea), O::Register(reg)) => {
                    assert_eq!(i.size, Some(Size::Word));
                    let address = match ea {
                        Ea::Indirect(base) => get(&r, base),
                        Ea::Displacement { base, value, .. } => {
                            get(&r, base).wrapping_add(value as u32)
                        }
                        _ => panic!("{ea:?}"),
                    };
                    let v = match address - (initial[1] + 4 * row) {
                        0 => word,
                        2 => !word,
                        _ => panic!("read outside bound waveform row"),
                    };
                    set(&mut r, reg, u32::from(v));
                }
                ("MOV", a, O::Register(reg)) => {
                    let v = value(a);
                    set(&mut r, reg, v);
                }
                ("ADD" | "SUB" | "AND" | "SHLL" | "ROTL", a, O::Register(reg)) => {
                    let v = value(a);
                    let old = get(&r, reg);
                    let result = match i.mnemonic {
                        "ADD" => old.wrapping_add(v),
                        "SUB" => old.wrapping_sub(v),
                        "AND" => old & v,
                        "SHLL" => old << v,
                        "ROTL" => (old as u8).rotate_left(v) as u32,
                        _ => unreachable!(),
                    };
                    set(&mut r, reg, result);
                }
                ("JSR" | "JMP", O::Address(Ea::Absolute { value, .. }), _) => {
                    if i.mnemonic == "JSR" {
                        returns.push(pc);
                    }
                    pc = value as usize - 0x410000;
                }
                ("RTS", _, _) => {
                    if let Some(ret) = returns.pop() {
                        pc = ret;
                    } else {
                        assert!(stack.is_empty());
                        assert_eq!(r[1], initial[1]);
                        assert_eq!(&r[3..], &initial[3..]);
                        return writes;
                    }
                }
                _ => panic!("unsupported instruction {i:?}"),
            }
        }
        panic!("did not return")
    }
}
fn coordinates(r: Reg) -> (usize, u32, u32) {
    match r {
        Reg::Byte(n) => ((n % 8) as usize, if n < 8 { 8 } else { 0 }, 255),
        Reg::Word(n) => ((n % 8) as usize, if n < 8 { 0 } else { 16 }, 65535),
        Reg::Long(n) => (n as usize, 0, u32::MAX),
        _ => panic!(),
    }
}
fn get(r: &[u32; 8], reg: Reg) -> u32 {
    let (n, s, m) = coordinates(reg);
    (r[n] >> s) & m
}
fn set(r: &mut [u32; 8], reg: Reg, v: u32) {
    let (n, s, m) = coordinates(reg);
    r[n] = (r[n] & !(m << s)) | ((v & m) << s);
}

#[test]
fn held_oem_encoders_have_exact_distinct_control_bit_semantics() {
    for (index, hash) in HASHES.iter().enumerate() {
        let n = fixture(hash);
        let b = encoders::observe(&n).unwrap();
        assert_eq!(
            b.representation,
            if index < 2 {
                Representation::HighByte
            } else {
                Representation::SplitTenBits
            }
        );
        let program = Program::new(&n, &[]);
        for v in 0..=u16::MAX {
            for (channel, &function) in b.pair.functions.iter().enumerate() {
                let w = if channel == 0 { v } else { !v };
                let trace = program.run(function, v);
                assert_eq!(trace.len(), 2);
                assert_eq!(trace[0].1, if index < 2 { 0 } else { ((w >> 6) & 3) as u8 });
                assert_eq!(trace[1].1, (w >> 8) as u8);
            }
        }
    }
}
#[test]
fn actual_cross_representation_oem_transplants_preserve_every_output_trace() {
    let full = fixture(HASHES[2]);
    for hash in &HASHES[..2] {
        let short = fixture(hash);
        for (target, donor) in [(&short, &full), (&full, &short)] {
            let old = encoders::observe(target).unwrap();
            let expected = encoders::observe(donor).unwrap();
            // Explicit synthetic owned code storage in sparse test images only;
            // no claim that erased production bytes establish ownership.
            let reservations = [Some(0x1000..0x1040), Some(0x1040..0x1080)];
            assert!(target[0x1000..0x1080].iter().all(|b| *b == 255));
            let changed = encoders::transplant(target, donor, reservations.clone()).unwrap();
            let actual = encoders::observe(&changed).unwrap();
            assert_eq!(actual.representation, expected.representation);
            assert_eq!(actual.pair.assignment, expected.pair.assignment);
            let emitted = Program::new(&changed, &old.pair.functions);
            let native = Program::new(donor, &[]);
            for v in 0..=u16::MAX {
                for source in 0..2 {
                    assert_eq!(
                        emitted.run(actual.pair.functions[source], v),
                        native.run(expected.pair.functions[source], v)
                    );
                    assert_eq!(
                        emitted.run(old.pair.functions[source], v),
                        native.run(expected.pair.functions[source], v)
                    );
                }
            }
            for (at, (a, b)) in target.iter().zip(&changed).enumerate() {
                assert!(
                    a == b
                        || old.programs.iter().flatten().any(|r| r.contains(&at))
                        || reservations.iter().flatten().any(|r| r.contains(&at))
                );
            }
            assert_eq!(
                encoders::transplant(&changed, donor, [None, None]).unwrap(),
                changed
            );
        }
    }
}
#[test]
fn refuses_unproved_helpers_and_missing_or_overlapping_space() {
    let short = fixture(HASHES[0]);
    let full = fixture(HASHES[2]);
    assert_eq!(
        encoders::transplant(&short, &full, [None, None]),
        Err(encoders::Error::SpaceRequired)
    );
    assert_eq!(
        encoders::transplant(&short, &full, [Some(0x1000..0x1040), Some(0x1000..0x1040)]),
        Err(encoders::Error::InvalidSpace)
    );
    let binding = encoders::observe(&short).unwrap();
    let mut broken = short.clone();
    broken[binding.leaf.start] ^= 1;
    assert!(
        encoders::transplant(&broken, &full, [Some(0x1000..0x1040), Some(0x1040..0x1080)]).is_err()
    );
}
