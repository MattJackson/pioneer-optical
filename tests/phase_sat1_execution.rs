//! Execute complete OEM SAT1 commands, selectors and output code, including Kernel leaves.
#![cfg(feature = "envelope")]
#![cfg(feature = "internals")]
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
                if bits == 16 {
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
            if (0xfffff910..=0xfffff913).contains(&(a + i)) {
                self.trace.push((a + i, b));
            } else {
                assert!((a + i) < 0x410000, "unexpected write {a:x}");
                self.ram.insert(a + i, b);
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
                    .any(|r| r.contains(&at)),
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
#[allow(clippy::too_many_arguments)]
fn execute(
    normal: &[u8],
    kernel: &[u8],
    b: &sat1::Binding,
    phase: u8,
    mode: u8,
    direction: u8,
    command: bool,
    output_mode: u8,
    enabled: bool,
) -> (Vec<(u32, u8)>, usize, [u8; 4]) {
    let mut c = Cpu {
        normal,
        kernel,
        binding: b,
        r: [0xa55a1357; 8],
        ram: BTreeMap::new(),
        stack: vec![],
        returns: vec![],
        z: false,
        n: false,
        v: false,
        c: false,
        trace: vec![],
        auxiliary: 0,
    };
    for i in 0..32 {
        c.ram.insert(b.state[0] + i, 0);
    }
    c.ram.insert(b.state[0] + 13, if enabled { 3 } else { 0 });
    c.ram.insert(
        b.state[0] + 14,
        if direction == 0 {
            phase.wrapping_sub(1) & 63
        } else {
            phase.wrapping_add(1) & 63
        },
    );
    c.ram.insert(b.state[0] + 16, 40);
    c.ram.insert(b.state[0] + 17, 100);
    c.ram.insert(b.state[1], direction);
    c.ram.insert(b.state[2], 0);
    c.set(Reg::Byte(0), mode.into());
    c.set(Reg::Byte(8), phase.into());
    c.set(Reg::Byte(9), output_mode.into());
    c.set(Reg::Byte(1), direction.into());
    c.run(if command {
        b.command.start
    } else {
        b.caller.start
    });
    let state = [
        c.ram[&(b.state[0] + 14)],
        c.ram[&(b.state[0] + 16)],
        c.ram[&b.state[1]],
        c.ram[&b.state[2]],
    ];
    (c.trace, c.auxiliary, state)
}
fn images() -> Vec<(Vec<u8>, Vec<u8>)> {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-sat1-native.json")).unwrap();
    fixtures
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            let mut n = vec![255; f["normal_len"].as_u64().unwrap() as usize];
            let mut k = vec![255; 65536];
            for span in f["spans"].as_array().unwrap() {
                let a = span[0].as_u64().unwrap() as usize;
                let hex = span[1].as_str().unwrap();
                let (image, base) = if a >= 0x410000 {
                    (&mut n, 0x410000)
                } else {
                    (&mut k, 0x400000)
                };
                for i in 0..hex.len() / 2 {
                    image[a - base + i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
                }
            }
            (n, k)
        })
        .collect()
}
#[test]
fn complete_native_sat1_transplant_matches_donor_execution() {
    let images = images();
    for (target, donor) in [(&images[0], &images[1]), (&images[1], &images[0])] {
        let changed = sat1::transplant(&target.0, &target.1, &donor.0, &donor.1).unwrap();
        let a = sat1::observe(&changed, &target.1).unwrap();
        let b = sat1::observe(&donor.0, &donor.1).unwrap();

        // The donor is an independent OEM program, and this fixture must expose
        // a real difference before correction rather than compare two no-ops.
        let before = sat1::observe(&target.0, &target.1).unwrap();
        assert_ne!(
            execute(&target.0, &target.1, &before, 1, 2, 0, false, 1, true).0,
            execute(&donor.0, &donor.1, &b, 1, 2, 0, false, 1, true).0
        );
        // Output mode two quantizes phase; exercise that actual native path
        // separately from the full-resolution table read in output mode one.
        let q0 = execute(&donor.0, &donor.1, &b, 0, 2, 0, false, 2, true).0;
        let q1 = execute(&donor.0, &donor.1, &b, 1, 2, 0, false, 2, true).0;
        assert_eq!(q0.len(), 4);
        assert_eq!(q0, q1);
        assert_ne!(
            q1,
            execute(&donor.0, &donor.1, &b, 1, 2, 0, false, 1, true).0
        );

        for command in [false, true] {
            for phase in 0..64 {
                for mode in [0, 1, 2, 3, 4, 5, 6, 127, 128, 129, 254, 255] {
                    for direction in 0..2 {
                        for output_mode in [0, 1, 2, 3, 255] {
                            for enabled in [false, true] {
                                assert_eq!(execute(&changed,&target.1,&a,phase,mode,direction,command,output_mode,enabled),execute(&donor.0,&donor.1,&b,phase,mode,direction,command,output_mode,enabled),"command{command} phase{phase} mode{mode} direction{direction} outputmode{output_mode} enabled{enabled}");
                            }
                        }
                    }
                }
            }
        }
    }
}
