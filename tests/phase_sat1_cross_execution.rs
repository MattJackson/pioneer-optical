//! Execute the original byte command, its explicit physical slice and the complete target adapter.
#![cfg(feature = "envelope")]
use h8_asm::{
    isa::{decode_insn, Ea, Operand as O, Reg, Size},
    Mode, Target,
};
use pioneer_optical::filters::phase::native::sat1;
use std::collections::BTreeMap;

struct Cpu<'a> {
    normal: &'a [u8],
    kernel: &'a [u8],
    binding: &'a sat1::Binding,
    r: [u32; 8],
    ram: BTreeMap<u32, u8>,
    stack: Vec<u32>,
    returns: Vec<u32>,
    z: bool,
    n: bool,
    v: bool,
    c: bool,
    trace: Vec<(u32, u8)>,
    auxiliary: usize,
    allowed: Vec<std::ops::Range<usize>>,
    events: Vec<Event>,
}
impl Cpu<'_> {
    fn coords(r: Reg) -> (usize, u32, u32) {
        match r {
            Reg::Byte(n) => ((n % 8) as usize, if n < 8 { 8 } else { 0 }, 255),
            Reg::Word(n) => ((n % 8) as usize, if n < 8 { 0 } else { 16 }, 65535),
            Reg::Long(n) => (n as usize, 0, u32::MAX),
            _ => panic!("register {r:?}"),
        }
    }
    fn get(&self, r: Reg) -> u32 {
        let (n, s, m) = Self::coords(r);
        (self.r[n] >> s) & m
    }
    fn set(&mut self, r: Reg, v: u32) {
        let (n, s, m) = Self::coords(r);
        self.r[n] = (self.r[n] & !(m << s)) | ((v & m) << s);
        self.z = v & m == 0;
        self.n = v & (m ^ (m >> 1)) != 0;
        self.v = false;
    }
    fn value(&self, o: O) -> u32 {
        match o {
            O::Register(r) => self.get(r),
            O::Immediate { value, .. } => value,
            _ => panic!("value {o:?}"),
        }
    }
    fn addr(&self, e: Ea) -> u32 {
        match e {
            Ea::Absolute { value, bits } => {
                if bits == 16 && value & 0x8000 != 0 {
                    0xffff0000 | value
                } else {
                    value
                }
            }
            Ea::Indirect(r) => self.get(r),
            Ea::Displacement { base, value, .. } => self.get(base).wrapping_add(value as u32),
            _ => panic!("address {e:?}"),
        }
    }
    fn width(s: Size) -> u32 {
        match s {
            Size::Byte => 1,
            Size::Word => 2,
            Size::Long => 4,
        }
    }
    fn load(&self, a: u32, s: Size) -> u32 {
        (0..Self::width(s)).fold(0, |v, i| {
            let a = a + i;
            let b = if (0x410000..0x410000 + self.normal.len() as u32).contains(&a) {
                self.normal[(a - 0x410000) as usize]
            } else {
                *self
                    .ram
                    .get(&a)
                    .unwrap_or_else(|| panic!("uninitialized read {a:x}"))
            };
            (v << 8) | u32::from(b)
        })
    }
    fn store(&mut self, a: u32, s: Size, v: u32) {
        let w = Self::width(s);
        for i in 0..w {
            let b = (v >> ((w - 1 - i) * 8)) as u8;
            if (0xfffff908..=0xfffff913).contains(&(a + i)) {
                self.trace.push((a + i, b));
            } else {
                assert!((a + i) < 0x410000, "unexpected write {a:x}");
                self.ram.insert(a + i, b);
                self.events.push(Event::Write(a + i, b));
            }
        }
    }
    fn run(&mut self, entry: usize) {
        let initial = self.r;
        let mut pc = 0x410000 + entry as u32;
        for _ in 0..2000 {
            let code = if pc >= 0x410000 {
                let at = (pc - 0x410000) as usize;
                assert!(
                    [
                        &self.binding.command,
                        &self.binding.caller,
                        &self.binding.output,
                        &self.binding.zero,
                        &self.binding.mode_getter
                    ]
                    .iter()
                    .any(|r| r.contains(&at))
                        || self.allowed.iter().any(|r| r.contains(&at)),
                    "unexpected code {pc:x}"
                );
                &self.normal[at..]
            } else {
                assert!((self.binding.encoders[0]..self.binding.encoders[0] + 6).contains(&pc));
                &self.kernel[(pc - 0x400000) as usize..]
            };
            let d = decode_insn(code, Target::H8S2000, Mode::Advanced).unwrap();
            let i = d.insn;
            let [a, b, _] = i.operands;
            pc += d.len as u32;
            match (i.mnemonic, a, b) {
                ("STM", O::Registers { first, last }, _) => {
                    for r in first..=last {
                        self.stack.push(self.r[r as usize]);
                    }
                }
                ("LDM", _, O::Registers { first, last }) => {
                    for r in (first..=last).rev() {
                        self.r[r as usize] = self.stack.pop().unwrap();
                    }
                }
                ("MOV", O::Register(r), O::Address(Ea::PreDecrement(Reg::Long(7)))) => {
                    self.stack.push(self.get(r))
                }
                ("MOV", O::Address(Ea::PostIncrement(Reg::Long(7))), O::Register(r)) => {
                    let v = self.stack.pop().unwrap();
                    self.set(r, v)
                }
                ("MOV", O::Address(e), O::Register(r)) => {
                    self.set(r, self.load(self.addr(e), i.size.unwrap()))
                }
                ("MOV", a, O::Address(e)) => {
                    let v = self.value(a);
                    self.store(self.addr(e), i.size.unwrap(), v);
                    self.z = v == 0;
                    self.n = v & (1 << (Self::width(i.size.unwrap()) * 8 - 1)) != 0;
                    self.v = false;
                }
                ("MOV", a, O::Register(r)) => self.set(r, self.value(a)),
                ("ORC", O::Immediate { value: 1, .. }, O::Register(Reg::Ccr)) => {
                    self.c = true;
                }
                ("STC", O::Register(Reg::Ccr), O::Register(r)) => {
                    let value = u32::from(self.c)
                        | (u32::from(self.v) << 1)
                        | (u32::from(self.z) << 2)
                        | (u32::from(self.n) << 3);
                    let (n, shift, mask) = Self::coords(r);
                    self.r[n] = (self.r[n] & !(mask << shift)) | ((value & mask) << shift);
                }
                ("EXTU", O::Register(Reg::Word(r)), _) => {
                    self.set(Reg::Word(r), self.get(Reg::Word(r)) & 255)
                }
                ("EXTU", O::Register(Reg::Long(r)), _) => {
                    self.set(Reg::Long(r), self.get(Reg::Word(r)))
                }
                ("EXTS", O::Register(Reg::Word(r)), _) => {
                    self.set(Reg::Word(r), self.get(Reg::Byte(r + 8)) as i8 as i32 as u32)
                }
                ("EXTS", O::Register(Reg::Long(r)), _) => {
                    self.set(Reg::Long(r), self.get(Reg::Word(r)) as i16 as i32 as u32)
                }
                ("XOR" | "AND" | "OR", a, O::Register(r)) => {
                    let x = self.get(r);
                    let y = self.value(a);
                    self.set(
                        r,
                        match i.mnemonic {
                            "XOR" => x ^ y,
                            "AND" => x & y,
                            _ => x | y,
                        },
                    );
                }
                ("ADD" | "SUB" | "CMP", a, O::Register(r)) => {
                    let x = self.get(r);
                    let y = self.value(a);
                    let (_, _, mask) = Self::coords(r);
                    let sign = mask ^ (mask >> 1);
                    let sub = i.mnemonic != "ADD";
                    let result = if sub {
                        x.wrapping_sub(y)
                    } else {
                        x.wrapping_add(y)
                    };
                    let carry = if sub {
                        x < y
                    } else {
                        u64::from(x) + u64::from(y) > u64::from(mask)
                    };
                    let overflow = if sub {
                        (x ^ y) & (x ^ result) & sign != 0
                    } else {
                        (!(x ^ y)) & (x ^ result) & sign != 0
                    };
                    if i.mnemonic != "CMP" {
                        self.set(r, result);
                    }
                    self.z = result & mask == 0;
                    self.n = result & sign != 0;
                    self.v = overflow;
                    self.c = carry;
                }
                ("ROTL", a, O::Register(r)) => {
                    let x = self.get(r);
                    let shift = self.value(a);
                    let (_, _, mask) = Self::coords(r);
                    let width = mask.count_ones();
                    self.set(r, (x << shift) | (x >> (width - shift)));
                }
                ("SHLL" | "SHAL" | "SHLR" | "SHAR", a, O::Register(r)) => {
                    let shift = self.value(a);
                    let x = self.get(r);
                    let (_, _, mask) = Self::coords(r);
                    let width = mask.count_ones();
                    let value = match i.mnemonic {
                        "SHLL" | "SHAL" => x << shift,
                        "SHLR" => x >> shift,
                        _ => (((x << (32 - width)) as i32) >> (32 - width + shift)) as u32,
                    };
                    self.set(r, value);
                }
                (
                    "BRA" | "BNE" | "BEQ" | "BHI" | "BLS" | "BCC" | "BCS" | "BGE" | "BGT" | "BLE"
                    | "BLT",
                    O::Address(Ea::PcRelative { value, .. }),
                    _,
                ) => {
                    let take = match i.mnemonic {
                        "BRA" => true,
                        "BNE" => !self.z,
                        "BEQ" => self.z,
                        "BHI" => !self.c && !self.z,
                        "BLS" => self.c || self.z,
                        "BCC" => !self.c,
                        "BCS" => self.c,
                        "BGE" => self.n == self.v,
                        "BGT" => !self.z && self.n == self.v,
                        "BLE" => self.z || self.n != self.v,
                        _ => self.n != self.v,
                    };
                    if take {
                        pc = pc.wrapping_add_signed(value);
                    }
                }
                ("BSR", O::Address(Ea::PcRelative { value, .. }), _) => {
                    self.returns.push(pc);
                    pc = pc.wrapping_add_signed(value);
                }
                ("JSR", O::Address(e), _) => {
                    let to = self.addr(e);
                    // This retained service is opaque: compare invocation count.
                    // Its implementation and hardware effects are outside this proof.
                    if to == self.binding.helpers[1] {
                        self.auxiliary += 1;
                        self.events.push(Event::Aux(
                            self.ram.clone(),
                            self.r[..4].try_into().unwrap(),
                        ));
                        // Exercise the full caller-scratch ABI, not a benevolent no-op.
                        self.r[..4]
                            .copy_from_slice(&[0x12345678, 0x87654321, 0xfeedcafe, 0xbadc0ffe]);
                    } else {
                        self.returns.push(pc);
                        pc = to;
                    }
                }
                ("JMP", O::Address(e), _) => pc = self.addr(e),
                ("NOP", _, _) => {}
                ("RTS", _, _) => {
                    if let Some(to) = self.returns.pop() {
                        pc = to;
                    } else {
                        assert!(self.stack.is_empty());
                        assert_eq!(&self.r[4..7], &initial[4..7]);
                        return;
                    }
                }
                _ => panic!("unsupported at {:x}: {i:?}", pc - d.len as u32),
            }
        }
        panic!("nonterminating SAT1 command")
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Write(u32, u8),
    Aux(BTreeMap<u32, u8>, [u32; 4]),
}
fn load_fixture(text: &str) -> (Vec<u8>, Vec<u8>) {
    let fixture: serde_json::Value = serde_json::from_str(text).unwrap();
    let fixture = if fixture.is_array() {
        &fixture[0]
    } else {
        &fixture
    };
    let mut normal = vec![255; fixture["normal_len"].as_u64().unwrap() as usize];
    let mut kernel = vec![255; 65536];
    for span in fixture["spans"].as_array().unwrap() {
        let address = span[0].as_u64().unwrap() as usize;
        let hex = span[1].as_str().unwrap();
        let (destination, base) = if address >= 0x410000 {
            (&mut normal, 0x410000)
        } else {
            (&mut kernel, 0x400000)
        };
        for i in 0..hex.len() / 2 {
            destination[address - base + i] =
                u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
    }
    (normal, kernel)
}
fn cpu<'a>(
    normal: &'a [u8],
    kernel: &'a [u8],
    binding: &'a sat1::Binding,
    allowed: Vec<std::ops::Range<usize>>,
    seed: u32,
) -> Cpu<'a> {
    Cpu {
        normal,
        kernel,
        binding,
        allowed,
        r: [seed; 8],
        ram: BTreeMap::new(),
        stack: vec![],
        returns: vec![],
        z: false,
        n: false,
        v: false,
        c: false,
        trace: vec![],
        auxiliary: 0,
        events: vec![],
    }
}
fn input(cpu: &mut Cpu<'_>, mode: u8, phase: u8, argument: u8) {
    cpu.set(Reg::Byte(0), mode.into());
    cpu.set(Reg::Byte(8), phase.into());
    cpu.set(Reg::Byte(9), argument.into());
}
#[test]
fn byte_slice_preserves_physical_output_and_target_state_lifecycle() {
    check_fixture(include_str!("fixtures/phase-sat1-byte0-native.json"));
    check_fixture(include_str!("fixtures/phase-sat1-byte1-native.json"));
    check_fixture(include_str!("fixtures/phase-sat1-byte2-native.json"));
}
fn check_fixture(fixture: &str) {
    let (target, kernel) = load_fixture(include_str!("fixtures/phase-sat1-native.json"));
    let (donor, _) = load_fixture(fixture);
    let before = sat1::observe(&target, &kernel).unwrap();
    let donor_binding = sat1::byte_pair::observe_normal(&donor).unwrap();
    let changed = sat1::cross_interface::transplant(&target, &kernel, &donor).unwrap();
    let adapted = sat1::cross_interface::observe_normal(&changed).unwrap();
    assert_eq!(
        &changed[before.command.clone()],
        &target[before.command.clone()]
    );
    if matches!(donor_binding.shape, 2 | 6) {
        // The retained output reads direction. Prove the target's complete
        // native inference agrees with the donor for every old phase byte,
        // including the equal-phase path that retains the previous flag.
        for previous in 0..=255u8 {
            for phase in 0..64u8 {
                let mut source = cpu(
                    &donor,
                    &kernel,
                    &before,
                    vec![donor_binding.body.clone()],
                    0xa55a1357,
                );
                let offset = if donor_binding.shape == 2 { 14 } else { 12 };
                source.ram.insert(donor_binding.state[0] + offset, previous);
                source.ram.insert(donor_binding.state[0] + offset + 2, 40);
                source.ram.insert(donor_binding.state[0] + offset + 3, 100);
                source.ram.insert(donor_binding.state[1], 1);
                input(&mut source, 0, phase, 0);
                source.run(donor_binding.body.start);
                let mut destination = cpu(
                    &changed,
                    &kernel,
                    &before,
                    vec![adapted.driver.clone()],
                    0xa55a1357,
                );
                destination.ram.insert(before.state[0] + 13, 0);
                destination.ram.insert(before.state[0] + 14, previous);
                destination.ram.insert(before.state[0] + 16, 40);
                destination.ram.insert(before.state[0] + 17, 100);
                destination.ram.insert(before.state[1], 1);
                destination.ram.insert(before.state[2], 0);
                input(&mut destination, 0, phase, 0);
                destination.run(before.command.start);
                assert_eq!(
                    source.ram[&donor_binding.state[1]], destination.ram[&before.state[1]],
                    "direction previous{previous} phase{phase}"
                );
                assert_eq!(source.trace, destination.trace);
            }
        }
    }
    for mode in 0..=255u8 {
        for phase in 0..64u8 {
            for argument in [0, 255u8] {
                for (seed, accumulator, limit, previous) in [
                    (0, 0, 0, 0),
                    (0xa55a1357, 40, 100, 63),
                    (0xffff0000, 255, 255, 255),
                ] {
                    let mut original = cpu(
                        &donor,
                        &kernel,
                        &before,
                        vec![donor_binding.body.clone()],
                        seed,
                    );
                    match donor_binding.shape {
                        0 => {
                            original
                                .ram
                                .insert(donor_binding.state[0] + 39, accumulator);
                            original.ram.insert(donor_binding.state[1], previous);
                            original.ram.insert(donor_binding.state[2], limit);
                        }
                        1 => {
                            original.ram.insert(donor_binding.state[0] + 12, previous);
                            original
                                .ram
                                .insert(donor_binding.state[0] + 14, accumulator);
                            original.ram.insert(donor_binding.state[0] + 15, limit);
                        }
                        2 | 6 => {
                            let previous_offset = if donor_binding.shape == 2 { 14 } else { 12 };
                            original
                                .ram
                                .insert(donor_binding.state[0] + previous_offset, previous);
                            original
                                .ram
                                .insert(donor_binding.state[0] + previous_offset + 2, accumulator);
                            original
                                .ram
                                .insert(donor_binding.state[0] + previous_offset + 3, limit);
                            original.ram.insert(donor_binding.state[1], 0);
                        }
                        _ => panic!(),
                    }
                    input(&mut original, mode, phase, argument);
                    original.run(donor_binding.body.start);
                    let mut physical = cpu(
                        &changed,
                        &kernel,
                        &before,
                        vec![adapted.driver.clone()],
                        !seed,
                    );
                    if matches!(donor_binding.shape, 2 | 6) {
                        physical
                            .ram
                            .insert(before.state[1], original.ram[&donor_binding.state[1]]);
                    }
                    input(&mut physical, mode, phase, argument);
                    physical.run(adapted.driver.start);
                    assert_eq!(
                        original.trace, physical.trace,
                        "mode{mode} phase{phase} arg{argument} seed{seed}"
                    );
                    assert!(
                        physical.events.is_empty(),
                        "physical slice must not touch software RAM"
                    );
                }
                let seed = 0xa55a1357u32.rotate_left(u32::from(phase));
                let mut original = cpu(&target, &kernel, &before, vec![], seed);
                let mut replacement = cpu(
                    &changed,
                    &kernel,
                    &before,
                    vec![adapted.driver.clone()],
                    seed,
                );
                for current in [&mut original, &mut replacement] {
                    current
                        .ram
                        .insert(before.state[0] + 13, if phase & 1 == 0 { 3 } else { 0 });
                    current.ram.insert(
                        before.state[0] + 14,
                        phase.wrapping_sub(if mode & 1 == 0 { 17 } else { 1 }) & 63,
                    );
                    current.ram.insert(before.state[0] + 16, mode);
                    current.ram.insert(before.state[0] + 17, 100);
                    current.ram.insert(before.state[1], 0);
                    current.ram.insert(before.state[2], 0);
                    input(current, mode, phase, argument);
                    current.run(before.command.start);
                }
                assert_eq!(
                    original.events, replacement.events,
                    "target lifecycle mode{mode} phase{phase} arg{argument}"
                );
                assert_eq!(original.ram, replacement.ram);
                let mut physical = cpu(
                    &changed,
                    &kernel,
                    &before,
                    vec![adapted.driver.clone()],
                    seed,
                );
                if matches!(donor_binding.shape, 2 | 6) {
                    physical
                        .ram
                        .insert(before.state[1], replacement.ram[&before.state[1]]);
                }
                input(&mut physical, mode, phase, argument);
                physical.run(adapted.driver.start);
                assert_eq!(
                    replacement.trace, physical.trace,
                    "complete adapter mode{mode} phase{phase} arg{argument}"
                );
            }
        }
    }
    // The public zero entry changes to the donor's original two-store zero leaf.
    let mut zero = cpu(&changed, &kernel, &before, vec![], 0xa55a1357);
    zero.run(adapted.zero.start);
    let mut donor_zero = cpu(
        &donor,
        &kernel,
        &before,
        vec![donor_binding.body.end..donor_binding.body.end + 12],
        0xdeadbeef,
    );
    donor_zero.run(donor_binding.body.end);
    assert_eq!(zero.trace, donor_zero.trace);
    assert_eq!(zero.trace, vec![(0xfffff908, 0), (0xfffff909, 0)]);
    assert!(zero.events.is_empty());
    sat1::cross_interface::verify(&target, &kernel, &donor, &changed).unwrap();
}
