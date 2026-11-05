//! Actual OEM dispatcher/selector transplantation and opaque coil-call traces.
#![cfg(feature = "envelope")]
use h8_asm::{
    isa::{decode_insn, Ea, Insn, Operand as O, Reg},
    Mode, Target,
};
use pioneer_optical::filters::phase::bundle::waveforms::resources::dispatch_bridge::{
    self as bridge, Binding, Kind,
};
use std::collections::BTreeMap;
const HASHES: [&str; 3] = [
    "84b76c71728dd9c27d27c3cb974f062b55c59a7a26145c858dc45cc1a79db66a",
    "87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1",
    "8037cdb3ae67e04a82aa3e9b7a0f52202e17f1e39d1f50b894158d9be0cec898",
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
    let extra: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-dispatch-callers.json")).unwrap();
    for f in std::iter::once(f).chain(
        extra
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["original_sha256"] == hash),
    ) {
        for span in f["spans"].as_array().unwrap() {
            let at = span[0].as_u64().unwrap() as usize;
            let h = span[1].as_str().unwrap();
            for i in 0..h.len() / 2 {
                n[at + i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
            }
        }
    }
    n
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
fn set(r: &mut [u32; 8], reg: Reg, v: u32) -> bool {
    let (n, s, m) = coordinates(reg);
    r[n] = (r[n] & !(m << s)) | ((v & m) << s);
    v & m == 0
}
struct Program {
    code: BTreeMap<usize, (Insn, usize)>,
    coils: Vec<u32>,
    binding: Binding,
    tables: Vec<(u32, u32)>,
}
#[derive(Debug, PartialEq, Eq)]
struct Trace {
    calls: Vec<(usize, u8, u32)>,
    writes: Vec<(usize, u32)>,
    returned: u8,
}
impl Program {
    fn new(n: &[u8], entries: [usize; 2], tables: Vec<(u32, u32)>) -> Self {
        let binding = bridge::observe(n).unwrap();
        let mut code = BTreeMap::new();
        let mut coils = Vec::new();
        for range in [&binding.dispatch, &binding.selector] {
            let mut at = range.start;
            while at < range.end {
                let d = decode_insn(&n[at..range.end], Target::H8S2000, Mode::Advanced).unwrap();
                if d.insn.mnemonic == "JSR" {
                    let O::Address(Ea::Absolute { value, .. }) = d.insn.operands[0] else {
                        panic!()
                    };
                    if !coils.contains(&value) {
                        coils.push(value);
                    }
                }
                code.insert(at, (d.insn, d.len));
                at += d.len;
            }
        }
        for at in entries {
            let d = decode_insn(&n[at..], Target::H8S2000, Mode::Advanced).unwrap();
            code.insert(at, (d.insn, d.len));
        }
        Self {
            code,
            coils,
            binding,
            tables,
        }
    }
    fn canonical(&self, address: u32) -> u32 {
        self.tables
            .iter()
            .find(|(from, _)| *from == address)
            .unwrap()
            .1
    }
    fn run(&self, entries: [usize; 2], row: u8, argument: u8, step: u8, mode: u8) -> Trace {
        let mut r = [0x55aa_1357; 8];
        let saved = r;
        let mut memory = BTreeMap::from([
            (self.binding.state[0], u32::from(step)),
            (self.binding.state[1], 0),
            (self.binding.state[2], 0),
        ]);
        let mut stack = Vec::new();
        let mut zero = false;
        let mut carry = false;
        let mut trace = Trace {
            calls: Vec::new(),
            writes: Vec::new(),
            returned: 0,
        };
        for (pass, entry) in [entries[1], entries[0]].into_iter().enumerate() {
            r[0] = if pass == 0 {
                u32::from(mode)
            } else {
                (u32::from(row) << 8) | u32::from(argument)
            };
            let mut pc = entry;
            let mut done = false;
            for _ in 0..200 {
                let (i, len) = self.code[&pc];
                pc += len;
                let [a, b, _] = i.operands;
                let val = |o| match o {
                    O::Register(reg) => get(&r, reg),
                    O::Immediate { value, .. } => value,
                    _ => panic!("operand {o:?}"),
                };
                match (i.mnemonic, a, b) {
                    ("STM", O::Registers { first, last }, _) => {
                        for reg in first..=last {
                            stack.push(r[reg as usize]);
                        }
                    }
                    ("LDM", _, O::Registers { first, last }) => {
                        for reg in (first..=last).rev() {
                            r[reg as usize] = stack.pop().unwrap();
                        }
                    }
                    ("MOV", O::Register(reg), O::Address(Ea::Absolute { value, .. })) => {
                        let v = get(&r, reg);
                        memory.insert(value, v);
                        let role = self.binding.state.iter().position(|a| *a == value).unwrap();
                        assert!(role == 1 || role == 2);
                        trace
                            .writes
                            .push((role, if role == 2 { self.canonical(v) } else { v }));
                        zero = v == 0;
                    }
                    ("MOV", O::Address(ea), O::Register(reg)) => {
                        let address = match ea {
                            Ea::Absolute { value, .. } => value,
                            Ea::Indirect(base) => get(&r, base),
                            _ => panic!("address {ea:?}"),
                        };
                        let v = memory[&address];
                        zero = set(&mut r, reg, v);
                    }
                    ("MOV", a, O::Register(reg)) => {
                        let v = val(a);
                        zero = set(&mut r, reg, v);
                    }
                    ("AND" | "ADD" | "SUB", a, O::Register(reg)) => {
                        let v = val(a);
                        let old = get(&r, reg);
                        let result = match i.mnemonic {
                            "AND" => old & v,
                            "ADD" => old.wrapping_add(v),
                            "SUB" => old.wrapping_sub(v),
                            _ => unreachable!(),
                        };
                        zero = set(&mut r, reg, result);
                    }
                    ("CMP", a, b) => {
                        let a = val(a);
                        let b = val(b);
                        zero = a == b;
                        carry = b < a;
                    }
                    (
                        "BRA" | "BEQ" | "BNE" | "BCC",
                        O::Address(Ea::PcRelative { value, .. }),
                        _,
                    ) => {
                        if match i.mnemonic {
                            "BRA" => true,
                            "BEQ" => zero,
                            "BNE" => !zero,
                            "BCC" => !carry,
                            _ => unreachable!(),
                        } {
                            pc = pc.wrapping_add_signed(value as isize);
                        }
                    }
                    ("JMP", O::Address(Ea::Absolute { value, .. }), _) => {
                        pc = value as usize - 0x410000
                    }
                    ("JSR", O::Address(Ea::Absolute { value, .. }), _) => {
                        let channel = self.coils.iter().position(|a| *a == value).unwrap();
                        let row = get(&r, Reg::Byte(8)) as u8;
                        let table = self.canonical(r[1]);
                        trace.calls.push((channel, row, table));
                        // Arbitrary identical opaque response for identical arguments.
                        // Equivalence depends on the full trace, not helper semantics.
                        r[0] = (table ^ u32::from(row)).rotate_left(7);
                        r[1] = !table;
                        zero = false;
                        carry = true;
                    }
                    ("RTS", _, _) => {
                        done = true;
                        break;
                    }
                    _ => panic!("unsupported {i:?}"),
                }
            }
            assert!(done);
            assert!(stack.is_empty());
            assert_eq!(&r[3..], &saved[3..]);
        }
        trace.returned = get(&r, Reg::Byte(8)) as u8;
        assert_eq!(trace.returned, row & 63);
        trace
    }
}
#[test]
fn actual_literal_and_generated_dispatch_graphs_preserve_native_traces() {
    let normals = HASHES.map(fixture);
    for (target, donor) in [(&normals[0], &normals[1]), (&normals[1], &normals[0])] {
        let old = bridge::observe(target).unwrap();
        let wanted = bridge::observe(donor).unwrap();
        let resources = wanted
            .tables
            .iter()
            .enumerate()
            .map(|(i, from)| (*from, 0xa10000 + i as u32 * 256))
            .collect::<Vec<_>>();
        // These are explicit stage-test reservations; production ownership and
        // actual buffer initialization remain the composing operation's proof.
        let spaces = [Some(0x1000..0x1100), Some(0x1100..0x1180)];
        assert!(target[0x1000..0x1180].iter().all(|b| *b == 255));
        let changed = bridge::transplant(target, donor, &resources, spaces.clone()).unwrap();
        let actual = bridge::observe(&changed).unwrap();
        assert_eq!(actual.kind, wanted.kind);
        assert_eq!(actual.state, old.state);
        assert_eq!(actual.callers, old.callers);
        let emitted_entries = [old.dispatch.start, old.selector.start];
        let donor_entries = [wanted.dispatch.start, wanted.selector.start];
        let emitted = Program::new(
            &changed,
            emitted_entries,
            resources.iter().map(|(from, to)| (*to, *from)).collect(),
        );
        let native = Program::new(
            donor,
            donor_entries,
            wanted.tables.iter().map(|a| (*a, *a)).collect(),
        );
        // All row/selector bytes, and every branch partition of step/input state.
        for row in 0..=255 {
            for mode in 0..=255 {
                for step in [0, 1, 2, 3, 255] {
                    for argument in [0, 1, 255] {
                        assert_eq!(
                            emitted.run(emitted_entries, row, argument, step, mode),
                            native.run(donor_entries, row, argument, step, mode)
                        );
                    }
                }
            }
        }
        for (at, (a, b)) in target.iter().zip(&changed).enumerate() {
            assert!(
                a == b
                    || old.dispatch.contains(&at)
                    || old.selector.contains(&at)
                    || spaces.iter().flatten().any(|s| s.contains(&at))
            );
        }
    }
}
#[test]
fn caller_and_resource_contracts_are_enforced() {
    let target = fixture(HASHES[0]);
    let donor = fixture(HASHES[1]);
    let before = bridge::observe(&target).unwrap();
    assert_eq!(before.kind, Kind::Software);
    let wanted = bridge::observe(&donor).unwrap();
    let resources = wanted
        .tables
        .iter()
        .enumerate()
        .map(|(i, from)| (*from, 0xa10000 + i as u32 * 256))
        .collect::<Vec<_>>();
    assert_eq!(
        bridge::transplant(&target, &donor, &resources, [None, None]),
        Err(bridge::Failure::SpaceRequired)
    );
    assert_eq!(
        bridge::transplant(&target, &donor, &[], [Some(0x1000..0x1100), None]),
        Err(bridge::Failure::Resources)
    );
    let mut bad = target.clone();
    bad[before.callers[0][0].start - 1] ^= 1;
    assert_eq!(bridge::observe(&bad), Err(bridge::Failure::CallerContract));
}

#[test]
fn relocated_entries_retarget_callers_and_release_only_complete_old_bodies() {
    let normals = HASHES.map(fixture);
    assert_eq!(
        bridge::observe(&normals[2]).unwrap().argument,
        bridge::Argument::Zero
    );
    for (target, donor) in [
        (&normals[0], &normals[1]),
        (&normals[1], &normals[0]),
        (&normals[1], &normals[2]),
    ] {
        let before = bridge::observe(target).unwrap();
        let source = bridge::observe(donor).unwrap();
        let resources = source
            .tables
            .iter()
            .enumerate()
            .map(|(i, a)| (*a, 0xa10000 + i as u32 * 256))
            .collect::<Vec<_>>();
        let ranges = [0x1000..0x1100, 0x1100..0x1180];
        let changed = bridge::transplant_relocating_entries(
            target,
            donor,
            &resources,
            ranges[0].clone(),
            ranges[1].clone(),
        )
        .unwrap();
        let actual = bridge::observe(&changed).unwrap();
        assert!(changed[before.dispatch.clone()].iter().all(|b| *b == 255));
        assert!(changed[before.selector.clone()].iter().all(|b| *b == 255));
        for (index, calls) in before.callers.iter().enumerate() {
            for call in calls {
                let d =
                    decode_insn(&changed[call.clone()], Target::H8S2000, Mode::Advanced).unwrap();
                assert_eq!(d.insn.mnemonic, "JSR");
                assert_eq!(
                    d.insn.operands[0],
                    O::Address(Ea::Absolute {
                        value: 0x410000 + ranges[index].start as u32,
                        bits: 24
                    })
                );
            }
        }
        let emitted_entries = [actual.dispatch.start, actual.selector.start];
        let donor_entries = [source.dispatch.start, source.selector.start];
        let emitted = Program::new(
            &changed,
            emitted_entries,
            resources.iter().map(|(a, b)| (*b, *a)).collect(),
        );
        let native = Program::new(
            donor,
            donor_entries,
            source.tables.iter().map(|a| (*a, *a)).collect(),
        );
        for row in 0..=255 {
            for mode in 0..=255 {
                for step in [0, 2] {
                    for argument in [0, 1] {
                        assert_eq!(
                            emitted.run(emitted_entries, row, argument, step, mode),
                            native.run(donor_entries, row, argument, step, mode)
                        );
                    }
                }
            }
        }
        for (at, (a, b)) in target.iter().zip(&changed).enumerate() {
            assert!(
                a == b
                    || before.dispatch.contains(&at)
                    || before.selector.contains(&at)
                    || ranges.iter().any(|r| r.contains(&at))
                    || before.callers.iter().flatten().any(|r| r.contains(&at))
            );
        }
    }
}
