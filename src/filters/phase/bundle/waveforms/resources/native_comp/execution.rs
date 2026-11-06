//! Bounded instruction execution of the held OEM zlib inflater.
//!
//! Executes captured H8S instructions, including the allocator, memcpy, free and
//! transplanted OEM arithmetic; no decompression or allocator operation is stubbed.
//! NZVC are the only CCR bits read by this closed instruction graph. Stack bytes
//! begin unknown: MOV may carry packed-structure padding, but unknown bits cannot
//! reach arithmetic, control flow, addresses or observable output. Native scratch
//! tables may differ between encodings; only their bounded effects are asserted.
//! Instruction semantics: Renesas H8S/2600, H8S/2000 Software Manual (REJ09B0139),
//! https://www.renesas.com/en/document/mah/h8s2600-series-h8s2000-series-software-manual
use super::Binding;
use h8_asm::{
    isa::{decode_insn, Ea, Insn, Operand as O, Reg, Size},
    Mode, Target,
};
use std::{cell::Cell, collections::BTreeMap, ops::Range};

macro_rules! require {
    ($condition:expr $(,$message:expr)* $(,)?) => {
        if !$condition {
            return None;
        }
    };
}
macro_rules! require_eq {
    ($a:expr,$b:expr $(,$message:expr)* $(,)?) => {
        require!($a == $b);
    };
}
macro_rules! require_ne {
    ($a:expr,$b:expr $(,$message:expr)* $(,)?) => {
        require!($a != $b);
    };
}

const BASE: u32 = 0x410000;
const ENTRY: u32 = 0x57ae64;
const STACK: u32 = 0x900000;
const OUTPUT: u32 = 0x700000;
const INPUT: u32 = 0x600000;
const LENGTH: u32 = 0x8f0000;
const SCRATCH: std::ops::Range<u32> = 0xa0be86..0xa15a50;

struct Cpu {
    mem: Vec<u8>,
    initialized: Vec<bool>,
    output_end: u32,
    stack: Range<u32>,
    scratch: Range<u32>,
    length: Range<u32>,
    r: [u32; 8],
    known: [u32; 8],
    zn_known: bool,
    z: bool,
    n: bool,
    v: bool,
    c: bool,
    code: BTreeMap<u32, (Insn, usize)>,
    frames: Vec<(u32, [u32; 8])>,
    free_calls: usize,
    free: u32,
    entries: [u32; 3],
    fault: Cell<bool>,
}
impl Cpu {
    fn coords(r: Reg) -> (usize, u32, u32) {
        match r {
            Reg::Byte(n) => ((n % 8) as usize, if n < 8 { 8 } else { 0 }, 255),
            Reg::Word(n) => ((n % 8) as usize, if n < 8 { 0 } else { 16 }, 65535),
            Reg::Long(n) => (n as usize, 0, u32::MAX),
            _ => (0, 0, 0), // Rejected by the decoded-operand gate before execution.
        }
    }
    fn get(&self, r: Reg) -> u32 {
        let (n, s, m) = Self::coords(r);
        (self.r[n] >> s) & m
    }
    fn known(&self, r: Reg) -> u32 {
        let (n, s, m) = Self::coords(r);
        (self.known[n] >> s) & m
    }
    fn mark(&mut self, r: Reg, v: u32) {
        let (n, s, m) = Self::coords(r);
        self.known[n] = (self.known[n] & !(m << s)) | ((v & m) << s);
    }
    fn put(&mut self, r: Reg, v: u32) {
        self.mark(r, u32::MAX);
        let (n, s, m) = Self::coords(r);
        self.r[n] = (self.r[n] & !(m << s)) | ((v & m) << s);
    }
    fn set(&mut self, r: Reg, v: u32) {
        self.put(r, v);
        let (_, _, m) = Self::coords(r);
        self.zn_known = true;
        self.z = v & m == 0;
        self.n = v & (m ^ (m >> 1)) != 0;
        self.v = false;
    }
    fn val(&self, o: O) -> u32 {
        match o {
            O::Register(r) => self.get(r),
            O::Immediate { value, .. } => value,
            _ => {
                self.fault.set(true);
                0
            }
        }
    }
    fn width(s: Size) -> u32 {
        match s {
            Size::Byte => 1,
            Size::Word => 2,
            Size::Long => 4,
        }
    }
    fn addr(&mut self, e: Ea, s: Size) -> u32 {
        match e {
            Ea::Absolute { value, bits } => {
                if bits == 16 {
                    0xff0000 | value
                } else {
                    value
                }
            }
            Ea::Indirect(r)
            | Ea::Displacement { base: r, .. }
            | Ea::PreDecrement(r)
            | Ea::PostIncrement(r) => {
                if self.known(r) != u32::MAX {
                    self.fault.set(true);
                    return 0;
                }
                let value = self.get(r);
                match e {
                    Ea::Displacement { value: offset, .. } => {
                        value.wrapping_add_signed(offset) & 0xffffff
                    }
                    Ea::PreDecrement(_) => {
                        let a = value.wrapping_sub(Self::width(s));
                        self.put(r, a);
                        a & 0xffffff
                    }
                    Ea::PostIncrement(_) => {
                        self.put(r, value.wrapping_add(Self::width(s)));
                        value & 0xffffff
                    }
                    _ => value & 0xffffff,
                }
            }
            _ => {
                self.fault.set(true);
                0
            }
        }
    }
    fn valid_memory(&self, a: u32, s: Size) -> bool {
        let valid = a
            .checked_add(Self::width(s))
            .is_some_and(|end| end as usize <= self.mem.len());
        if !valid {
            self.fault.set(true);
        }
        valid
    }
    fn memory_known(&self, a: u32, s: Size) -> u32 {
        if !self.valid_memory(a, s) {
            return 0;
        }
        (0..Self::width(s)).fold(0, |v, i| {
            (v << 8)
                | if self.initialized[(a + i) as usize] {
                    255
                } else {
                    0
                }
        })
    }
    fn load(&self, a: u32, s: Size) -> u32 {
        if !self.valid_memory(a, s) {
            return 0;
        }
        (0..Self::width(s)).fold(0, |v, i| {
            if !self.initialized[(a + i) as usize] && !self.stack.contains(&(a + i)) {
                self.fault.set(true);
            }
            (v << 8) | u32::from(self.mem[(a + i) as usize])
        })
    }
    fn store(&mut self, a: u32, s: Size, v: u32) {
        if !self.valid_memory(a, s) {
            return;
        }
        let w = Self::width(s);
        for i in 0..w {
            let address = a + i;
            if !((OUTPUT..self.output_end).contains(&address)
                || self.stack.contains(&address)
                || self.scratch.contains(&address)
                || self.length.contains(&address))
            {
                self.fault.set(true);
                return;
            }
            self.mem[address as usize] = (v >> ((w - 1 - i) * 8)) as u8;
            self.initialized[address as usize] = true;
        }
    }
    fn push(&mut self, v: u32) {
        self.r[7] = self.r[7].wrapping_sub(4);
        self.store(self.r[7], Size::Long, v);
    }
    fn pop(&mut self) -> u32 {
        let v = self.load(self.r[7], Size::Long);
        self.r[7] = self.r[7].wrapping_add(4);
        v
    }
    fn run(&mut self, entry: u32, budget: &mut usize) -> Option<()> {
        let mut pc = entry;
        for _ in 0..25_000_000 {
            require!(!self.fault.get() && *budget > 0);
            *budget -= 1;
            if pc == 0 {
                return Some(());
            }
            let (i, len) = *self.code.get(&pc)?;
            pc += len as u32;
            let [mut a, mut b, _] = i.operands;
            if matches!(i.mnemonic, "INC" | "DEC") && b == O::None {
                b = a;
                a = O::Immediate { value: 1, bits: 0 };
            }
            if !matches!(i.mnemonic, "MOV" | "STM" | "LDM") {
                for operand in [a, b] {
                    if let O::Register(r) = operand {
                        let mask = if i.mnemonic == "EXTU" || i.mnemonic == "EXTS" {
                            if matches!(r, Reg::Long(_)) {
                                65535
                            } else {
                                255
                            }
                        } else {
                            Self::coords(r).2
                        };
                        if !(matches!(i.mnemonic, "SUB" | "XOR") && a == b) {
                            require_eq!(
                                self.known(r) & mask,
                                mask,
                                "unknown operand at {here:x}: {i:?}"
                            );
                        }
                    }
                }
                if matches!(
                    i.mnemonic,
                    "BNE" | "BEQ" | "BHI" | "BLS" | "BGE" | "BGT" | "BLE" | "BLT" | "BPL" | "BMI"
                ) {
                    require!(self.zn_known, "unknown branch flags {here:x}");
                }
            }
            match (i.mnemonic, a, b) {
                ("STM", O::Registers { first, last }, _) => {
                    for r in first..=last {
                        let known = self.known[r as usize];
                        self.push(self.r[r as usize]);
                        require!(!self.fault.get());
                        for j in 0..4 {
                            self.initialized[(self.r[7] + j) as usize] =
                                known & (255 << ((3 - j) * 8)) == 255 << ((3 - j) * 8);
                        }
                    }
                }
                ("LDM", _, O::Registers { first, last }) => {
                    for r in (first..=last).rev() {
                        let known = self.memory_known(self.r[7], Size::Long);
                        self.r[r as usize] = self.pop();
                        self.known[r as usize] = known;
                    }
                }
                ("MOV", O::Address(e), O::Register(r)) => {
                    let a = self.addr(e, i.size?);
                    let known = self.memory_known(a, i.size?);
                    self.set(r, self.load(a, i.size?));
                    self.mark(r, known);
                    self.zn_known = known == Self::coords(r).2;
                }
                ("MOV", a, O::Address(e)) => {
                    let known = match a {
                        O::Register(r) => self.known(r),
                        _ => u32::MAX,
                    };
                    let v = self.val(a);
                    let s = i.size?;
                    let a = self.addr(e, s);
                    if (OUTPUT..self.output_end).contains(&a) || self.length.contains(&a) {
                        let mask = (u64::MAX >> (64 - Self::width(s) * 8)) as u32;
                        require_eq!(known & mask, mask, "unknown observable store {here:x}");
                    }
                    self.store(a, s, v);
                    require!(!self.fault.get());
                    for j in 0..Self::width(s) {
                        self.initialized[(a + j) as usize] = known
                            & (255 << ((Self::width(s) - 1 - j) * 8))
                            == 255 << ((Self::width(s) - 1 - j) * 8);
                    }
                    self.zn_known = known & ((u64::MAX >> (64 - Self::width(s) * 8)) as u32)
                        == ((u64::MAX >> (64 - Self::width(s) * 8)) as u32);
                    let sign = 1 << (Self::width(s) * 8 - 1);
                    self.z = v == 0;
                    self.n = v & sign != 0;
                    self.v = false;
                }
                ("MOV", a, O::Register(r)) => {
                    let known = match a {
                        O::Register(r) => self.known(r),
                        _ => u32::MAX,
                    };
                    self.set(r, self.val(a));
                    self.mark(r, known);
                    self.zn_known = known & Self::coords(r).2 == Self::coords(r).2;
                }
                ("EXTU", O::Register(r), _) => {
                    let m = if matches!(r, Reg::Long(_)) {
                        65535
                    } else {
                        255
                    };
                    self.set(r, self.get(r) & m)
                }
                ("EXTS", O::Register(r), _) => {
                    let v = self.get(r);
                    self.set(
                        r,
                        if matches!(r, Reg::Long(_)) {
                            v as i16 as i32 as u32
                        } else {
                            v as i8 as i32 as u32
                        },
                    )
                }
                ("AND" | "OR" | "XOR", a, O::Register(r)) => {
                    let x = self.get(r);
                    let y = self.val(a);
                    self.set(
                        r,
                        match i.mnemonic {
                            "AND" => x & y,
                            "OR" => x | y,
                            _ => x ^ y,
                        },
                    )
                }
                ("ADD" | "SUB" | "CMP" | "INC" | "DEC", a, O::Register(r)) => {
                    let x = self.get(r);
                    let y = self.val(a);
                    let (_, _, mask) = Self::coords(r);
                    let sign = mask ^ (mask >> 1);
                    let sub = matches!(i.mnemonic, "SUB" | "CMP" | "DEC");
                    let v = if sub {
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
                        (x ^ y) & (x ^ v) & sign != 0
                    } else {
                        (!(x ^ y)) & (x ^ v) & sign != 0
                    };
                    if i.mnemonic != "CMP" {
                        self.put(r, v)
                    }
                    self.zn_known = true;
                    self.z = v & mask == 0;
                    self.n = v & sign != 0;
                    self.v = overflow;
                    if !matches!(i.mnemonic, "INC" | "DEC") {
                        self.c = carry
                    }
                }
                ("ADDS" | "SUBS", a, O::Register(r)) => {
                    let x = self.get(r);
                    let y = self.val(a);
                    self.put(
                        r,
                        if i.mnemonic == "ADDS" {
                            x.wrapping_add(y)
                        } else {
                            x.wrapping_sub(y)
                        },
                    )
                }
                ("NEG", O::Register(r), _) => {
                    let x = self.get(r);
                    let (_, _, mask) = Self::coords(r);
                    self.set(r, x.wrapping_neg());
                    self.c = x != 0;
                    self.v = x == mask ^ (mask >> 1);
                }
                ("NOT", O::Register(r), _) => self.set(r, !self.get(r)),
                (
                    "SHLL" | "SHAL" | "SHLR" | "SHAR" | "ROTL" | "ROTR" | "ROTXL" | "ROTXR",
                    a,
                    O::Register(r),
                ) => {
                    let count = self.val(a);
                    require!((1..=2).contains(&count));
                    let (_, _, m) = Self::coords(r);
                    let sign = m ^ (m >> 1);
                    let mut x = self.get(r);
                    let old = x;
                    for _ in 0..count {
                        let carry = self.c;
                        self.c = if matches!(i.mnemonic, "SHLL" | "SHAL" | "ROTL" | "ROTXL") {
                            x & sign != 0
                        } else {
                            x & 1 != 0
                        };
                        x = match i.mnemonic {
                            "SHLL" | "SHAL" => x << 1,
                            "SHLR" => x >> 1,
                            "SHAR" => (x >> 1) | (x & sign),
                            "ROTL" => (x << 1) | u32::from(self.c),
                            "ROTR" => (x >> 1) | if self.c { sign } else { 0 },
                            "ROTXL" => (x << 1) | u32::from(carry),
                            _ => (x >> 1) | if carry { sign } else { 0 },
                        } & m;
                    }
                    self.set(r, x);
                    if i.mnemonic == "SHAL" {
                        self.v = (old ^ x) & sign != 0;
                    }
                }
                ("MULXU", O::Register(from), O::Register(to)) => {
                    let m = Self::coords(from).2;
                    self.put(to, self.get(from).wrapping_mul(self.get(to) & m));
                }
                ("DIVXU", O::Register(from), O::Register(to)) => {
                    let d = self.get(from);
                    let n = self.get(to);
                    let bits = Self::coords(from).2.count_ones();
                    require!(bits == 8 || bits == 16);
                    require_ne!(d, 0);
                    require!(n / d < 1 << bits);
                    self.put(to, ((n % d) << bits) | (n / d));
                    self.z = false;
                    self.n = d & (1 << (bits - 1)) != 0;
                }
                ("BTST", a, O::Register(r)) => self.z = self.get(r) & (1 << (self.val(a) & 7)) == 0,
                ("BSET" | "BCLR" | "BNOT", a, O::Register(r)) => {
                    let x = self.get(r);
                    let mask = 1 << (self.val(a) & 7);
                    self.put(
                        r,
                        match i.mnemonic {
                            "BSET" => x | mask,
                            "BCLR" => x & !mask,
                            _ => x ^ mask,
                        },
                    )
                }
                (
                    "BRA" | "BNE" | "BEQ" | "BHI" | "BLS" | "BCC" | "BCS" | "BGE" | "BGT" | "BLE"
                    | "BLT" | "BPL" | "BMI" | "BVC" | "BVS",
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
                        "BLT" => self.n != self.v,
                        "BPL" => !self.n,
                        "BMI" => self.n,
                        "BVC" => !self.v,
                        _ => self.v,
                    };
                    if take {
                        pc = pc.wrapping_add_signed(value)
                    }
                }
                ("BSR", O::Address(Ea::PcRelative { value, .. }), _) => {
                    let to = pc.wrapping_add_signed(value);
                    self.frames.push((to, self.r));
                    self.push(pc);
                    pc = to
                }
                ("JSR", O::Address(e), _) => {
                    let to = self.addr(e, Size::Long);
                    self.frames.push((to, self.r));
                    if to == self.free {
                        self.free_calls += 1;
                    }
                    self.push(pc);
                    pc = to
                }
                ("JMP", O::Address(e), _) => pc = self.addr(e, Size::Long),
                ("RTS", _, _) => {
                    if let Some((entry, initial)) = self.frames.pop() {
                        if self.entries.contains(&entry) {
                            require_eq!(
                                &self.r[2..7],
                                &initial[2..7],
                                "arithmetic preserved registers"
                            );
                            require_eq!(
                                self.r[7].wrapping_add(4),
                                initial[7],
                                "arithmetic balanced stack"
                            );
                            let (a, b) = (initial[0], initial[1]);
                            match self.entries.iter().position(|a| *a == entry)? {
                                0 => {
                                    require_eq!(self.r[0], a.wrapping_mul(b));
                                    require_eq!(self.r[1], b);
                                }
                                1 => {
                                    let (a, b) = (a as i32, b as i32);
                                    require!(b != 0 && !(a == i32::MIN && b == -1));
                                    require_eq!(self.r[0] as i32, a / b);
                                    require_eq!(self.r[1] as i32, a % b);
                                }
                                _ => {
                                    require_ne!(b, 0);
                                    require_eq!(self.r[0], a / b);
                                    require_eq!(self.r[1], a % b);
                                }
                            }
                        }
                    }
                    require_eq!(self.memory_known(self.r[7], Size::Long), u32::MAX);
                    pc = self.pop()
                }
                ("NOP", _, _) => {}
                _ => return None,
            }
        }
        None
    }
}

fn execute(
    image: &[u8],
    binding: &Binding,
    programs: &[Range<u32>],
    entries: [u32; 3],
    compressed: &[u8],
    expected: &[u8],
    budget: &mut usize,
) -> Option<()> {
    require!(!compressed.is_empty() && compressed.len() <= 0x100000);
    require!(!expected.is_empty() && expected.len() <= 0x100000);
    let mut cpu = Cpu {
        mem: vec![0xa5; 0x1000000],
        initialized: vec![false; 0x1000000],
        output_end: OUTPUT + expected.len() as u32,
        stack: STACK - 0x10000..STACK + 8,
        scratch: SCRATCH,
        length: LENGTH..LENGTH + 4,
        r: [0x13579bdf; 8],
        known: [u32::MAX; 8],
        zn_known: true,
        z: false,
        n: false,
        v: false,
        c: false,
        code: BTreeMap::new(),
        frames: Vec::new(),
        free_calls: 0,
        free: binding.free,
        entries,
        fault: Cell::new(false),
    };
    let data = BASE + binding.data.start as u32..BASE + binding.data.end as u32;
    for range in programs.iter().chain([&data]) {
        require!(range.start >= BASE && range.end <= INPUT && range.start < range.end);
        let bytes = image.get((range.start - BASE) as usize..(range.end - BASE) as usize)?;
        cpu.mem[range.start as usize..range.end as usize].copy_from_slice(bytes);
        cpu.initialized[range.start as usize..range.end as usize].fill(true);
    }
    // Decode complete bound bodies first; execution may only enter genuine
    // instruction boundaries, including validated jump-table destinations.
    for range in programs {
        let mut pc = range.start;
        while pc < range.end {
            let d = decode_insn(
                cpu.mem.get(pc as usize..range.end as usize)?,
                Target::H8S2000,
                Mode::Advanced,
            )
            .ok()?;
            for operand in d.insn.operands {
                let reg = match operand {
                    O::Register(r)
                    | O::Address(
                        Ea::Indirect(r)
                        | Ea::PreDecrement(r)
                        | Ea::PostIncrement(r)
                        | Ea::Displacement { base: r, .. },
                    ) => Some(r),
                    O::Registers { first, last } => {
                        require!(first <= last && last < 7);
                        None
                    }
                    _ => None,
                };
                if let Some(reg) = reg {
                    require!(matches!(
                        reg,
                        Reg::Byte(0..=15) | Reg::Word(0..=15) | Reg::Long(0..=7)
                    ));
                }
            }
            require!(d.len > 0);
            cpu.code.insert(pc, (d.insn, d.len));
            pc += d.len as u32;
        }
    }
    cpu.mem[INPUT as usize..INPUT as usize + compressed.len()].copy_from_slice(compressed);
    cpu.initialized[INPUT as usize..INPUT as usize + compressed.len()].fill(true);
    cpu.r[0] = OUTPUT;
    cpu.r[1] = LENGTH;
    cpu.r[2] = INPUT;
    cpu.r[7] = STACK;
    cpu.store(STACK, Size::Long, compressed.len() as u32);
    cpu.store(STACK + 4, Size::Long, expected.len() as u32);
    cpu.push(0);
    cpu.run(ENTRY, budget)?;
    require!(!cpu.fault.get() && cpu.frames.is_empty());
    require_eq!(cpu.r[0], 0);
    require_eq!(cpu.r[7], STACK);
    require_eq!(&cpu.r[4..7], &[0x13579bdf; 3]);
    require_eq!(cpu.load(LENGTH, Size::Long), expected.len() as u32);
    require_eq!(
        cpu.load(STACK - 66 + 8, Size::Long),
        compressed.len() as u32
    );
    require_eq!(cpu.load(STACK - 66 + 4, Size::Long), 0);
    require_eq!(
        cpu.load(STACK - 66, Size::Long),
        INPUT + compressed.len() as u32
    );
    require_eq!(
        cpu.load(STACK - 66 + 12, Size::Long),
        OUTPUT + expected.len() as u32
    );
    require_eq!(cpu.load(STACK - 66 + 16, Size::Long), 0);
    require_eq!(cpu.load(STACK, Size::Long), compressed.len() as u32);
    require_eq!(cpu.load(STACK + 4, Size::Long), expected.len() as u32);
    require_eq!(cpu.free_calls, 1);
    require!(cpu.initialized[OUTPUT as usize..cpu.output_end as usize]
        .iter()
        .all(|v| *v));
    require_eq!(&cpu.mem[OUTPUT as usize..cpu.output_end as usize], expected);
    require!(!cpu.fault.get());
    Some(())
}

/// Validate the actual streams of a proposed COMP repack using the exact bound
/// OEM inflater and caller-supplied, placed OEM arithmetic. No firmware bytes
/// are written. Both encodings execute in isolated memory; input is relocated
/// so the original stream can coexist with arithmetic placed in reclaimed space.
/// Unsupported instructions, unknown reads, outside effects, ABI mismatch,
/// stream mismatch, and finite execution/resource exhaustion all refuse.
///
/// This proves the streams and decoder execution, not ownership of reclaimed
/// flash, flash loading, or reference closure; callers must establish those.
pub fn validate(
    original: &[u8],
    changed: &[u8],
    binding: &Binding,
    entries: [u32; 3],
) -> Option<()> {
    require!(original.len() <= (INPUT - BASE) as usize && changed.len() <= (INPUT - BASE) as usize);
    let cap = 4 * 1024 * 1024;
    let (old_base, old) = crate::comp_streams::read(original, cap, &mut || true).ok()??;
    let (new_base, new) = crate::comp_streams::read(changed, cap, &mut || true).ok()??;
    require_eq!(old_base, BASE);
    require_eq!(new_base, BASE);
    require_eq!(old.len(), new.len());
    require!(!old.is_empty());
    require_eq!(super::observe(original)?, *binding);
    let arithmetic =
        crate::filters::phase::native::arithmetic::observe(changed, BASE, entries[0], entries[1])?;
    require_eq!(BASE + arithmetic.unsigned_divide.start as u32, entries[2]);
    let arithmetic = [
        arithmetic.multiply,
        arithmetic.signed_divide,
        arithmetic.unsigned_divide,
    ];
    for (i, range) in arithmetic.iter().enumerate() {
        require!(arithmetic
            .iter()
            .enumerate()
            .all(|(j, r)| i == j || range.start >= r.end || r.start >= range.end));
        require!(binding
            .programs
            .iter()
            .chain([&binding.data, &binding.loader, &binding.boundary_program])
            .all(|r| range.start >= r.end || r.start >= range.end));
    }
    // Compare every bound instruction, permitting only the decoded JSR operand
    // substitutions. Constants, loader and unused adjacent boundary stay exact.
    for range in &binding.programs {
        let mut expected = original.get(range.clone())?.to_vec();
        for call in &binding.calls {
            if range.contains(&call.offset) {
                let offset = call.offset - range.start;
                expected
                    .get_mut(offset + 1..offset + 4)?
                    .copy_from_slice(&entries[call.role].to_be_bytes()[1..]);
            }
        }
        require_eq!(changed.get(range.clone())?, expected);
    }
    for range in [&binding.data, &binding.loader, &binding.boundary_program] {
        require_eq!(original.get(range.clone())?, changed.get(range.clone())?);
    }
    let regions = crate::image::regions(changed)?;
    for range in &arithmetic {
        require!(regions.stored.iter().any(|s| {
            let at = s.as_ptr() as usize - changed.as_ptr() as usize;
            at <= range.start && range.end <= at + s.len()
        }));
    }
    let programs: Vec<_> = binding
        .programs
        .iter()
        .chain(arithmetic.iter())
        .map(|r| BASE + r.start as u32..BASE + r.end as u32)
        .collect();
    let mut budget = 150_000_000;
    for (old, new) in old.iter().zip(&new) {
        require_eq!(old.image_offset, new.image_offset);
        require_eq!(old.expanded, new.expanded);
        for (image, stream) in [(original, old), (changed, new)] {
            let start = stream.image_offset.checked_add(4)?;
            let compressed = image.get(start..start.checked_add(stream.compressed_size)?)?;
            execute(
                changed,
                binding,
                &programs,
                entries,
                compressed,
                &old.expanded,
                &mut budget,
            )?;
        }
    }
    Some(())
}

#[cfg(test)]
#[path = "transform_tests.rs"]
mod transform_tests;
