//! Small fail-closed H8 executor for the captured pointer graph. Coil routines
//! remain opaque: compare their complete argument trace and clobber scratch
//! registers/flags on every call. This does not certify DSP or coil arithmetic.
use h8_asm::{
    isa::{decode_insn, Ea, Insn, Operand as O, Reg},
    Mode, Target,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

pub const BASE: u32 = 0x410000;
pub const OBJECT: u32 = 0xa01000;
fn coordinates(reg: Reg) -> (usize, u32, u32) {
    match reg {
        Reg::Byte(n) => ((n % 8) as usize, if n < 8 { 8 } else { 0 }, 255),
        Reg::Word(n) => ((n % 8) as usize, if n < 8 { 0 } else { 16 }, 65535),
        Reg::Long(n) => (n as usize, 0, u32::MAX),
        _ => panic!("unsupported register {reg:?}"),
    }
}
fn get(r: &[u32; 8], reg: Reg) -> u32 {
    let (n, s, m) = coordinates(reg);
    (r[n] >> s) & m
}
fn set(r: &mut [u32; 8], reg: Reg, value: u32) -> bool {
    let (n, s, m) = coordinates(reg);
    r[n] = (r[n] & !(m << s)) | ((value & m) << s);
    value & m == 0
}
fn width(reg: Reg) -> usize {
    match reg {
        Reg::Byte(_) => 1,
        Reg::Word(_) => 2,
        Reg::Long(_) => 4,
        _ => panic!(),
    }
}
fn value(r: &[u32; 8], operand: O) -> u32 {
    match operand {
        O::Register(reg) => get(r, reg),
        O::Immediate { value, .. } => value,
        _ => panic!("value {operand:?}"),
    }
}
fn address(r: &[u32; 8], ea: Ea) -> u32 {
    match ea {
        Ea::Absolute { value, .. } => value,
        Ea::Indirect(reg) => get(r, reg),
        Ea::Displacement { base, value, .. } => get(r, base).wrapping_add_signed(value),
        _ => panic!("address {ea:?}"),
    }
}

#[derive(Clone)]
pub struct Program<'a> {
    image: &'a [u8],
    code: BTreeMap<u32, (Insn, usize)>,
    coils: [u32; 2],
    tables: Vec<(u32, u32)>,
    pub reader: Option<u32>,
    pub readonly: Vec<Range<u32>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoilCall {
    pub channel: usize,
    pub row: u8,
    pub table_role: u32,
    pub words: [u16; 2],
}
impl<'a> Program<'a> {
    pub fn new(image: &'a [u8], coils: [u32; 2], tables: Vec<(u32, u32)>) -> Self {
        Self {
            image,
            code: BTreeMap::new(),
            coils,
            tables,
            reader: None,
            readonly: Vec::new(),
        }
    }
    pub fn add(&mut self, start: u32, bytes: &[u8]) {
        let mut at = 0;
        while at < bytes.len() {
            let d = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced).unwrap();
            assert!(at + d.len <= bytes.len());
            assert!(self
                .code
                .insert(start + at as u32, (d.insn, d.len))
                .is_none());
            at += d.len;
        }
    }
    pub fn role(&self, table: u32) -> u32 {
        self.tables
            .iter()
            .find(|(physical, _)| *physical == table)
            .unwrap_or_else(|| panic!("unknown table {table:x}"))
            .1
    }
    pub fn all_conditional_edges_seen(&self, edges: &BTreeSet<(u32, bool)>, ranges: &[Range<u32>]) {
        for (&pc, (i, _)) in &self.code {
            if ranges.iter().any(|r| r.contains(&pc)) && matches!(i.mnemonic, "BEQ" | "BNE" | "BCC")
            {
                assert!(edges.contains(&(pc, false)), "untaken branch {pc:x}: {i:?}");
                assert!(
                    edges.contains(&(pc, true)),
                    "unexercised branch {pc:x}: {i:?}"
                );
            }
        }
    }
}
#[derive(Clone)]
pub struct Machine {
    pub r: [u32; 8],
    pub ram: BTreeMap<u32, u8>,
    stack: Vec<u32>,
    zero: bool,
    carry: bool,
    pub calls: Vec<CoilCall>,
    pub writes: Vec<(u32, usize, u32)>,
    pub parameter_reads: Vec<u16>,
    pub word: u16,
}
impl Machine {
    pub fn new() -> Self {
        Self {
            r: [
                0xdead_beef,
                0x1234_5678,
                0x89ab_cdef,
                0x1357_2468,
                0x2345_6789,
                0x3456_789a,
                0x4567_89ab,
                0x00af_ff00,
            ],
            ram: BTreeMap::new(),
            stack: Vec::new(),
            zero: false,
            carry: true,
            calls: Vec::new(),
            writes: Vec::new(),
            parameter_reads: Vec::new(),
            word: 1,
        }
    }
    pub fn put(&mut self, address: u32, size: usize, value: u32) {
        for i in 0..size {
            self.ram
                .insert(address + i as u32, (value >> ((size - 1 - i) * 8)) as u8);
        }
    }
    pub fn read(&self, p: &Program<'_>, address: u32, size: usize) -> u32 {
        (0..size).fold(0, |v, i| {
            let a = address + i as u32;
            let byte = self
                .ram
                .get(&a)
                .copied()
                .or_else(|| {
                    a.checked_sub(BASE)
                        .and_then(|at| p.image.get(at as usize).copied())
                })
                .unwrap_or_else(|| panic!("uninitialized read {a:x}"));
            (v << 8) | u32::from(byte)
        })
    }
    pub fn row(&self) -> u8 {
        get(&self.r, Reg::Byte(8)) as u8
    }
    pub fn run(
        &mut self,
        p: &Program<'_>,
        entry: u32,
        end: Option<u32>,
        edges: &mut BTreeSet<(u32, bool)>,
    ) {
        let saved = self.r;
        let initial_depth = self.stack.len();
        let mut pc = entry;
        for _ in 0..256 {
            if end == Some(pc) {
                assert_eq!(self.stack.len(), initial_depth);
                assert_eq!(&self.r[3..], &saved[3..]);
                return;
            }
            let at = pc;
            let (i, len) = *p
                .code
                .get(&pc)
                .unwrap_or_else(|| panic!("missing code {pc:x}"));
            pc += len as u32;
            let [a, b, _] = i.operands;
            match (i.mnemonic, a, b) {
                ("NOP", _, _) => {}
                ("STM", O::Registers { first, last }, _) => {
                    for reg in first..=last {
                        self.stack.push(self.r[reg as usize]);
                        self.r[7] -= 4;
                    }
                }
                ("LDM", _, O::Registers { first, last }) => {
                    for reg in (first..=last).rev() {
                        self.r[reg as usize] = self.stack.pop().unwrap();
                        self.r[7] += 4;
                    }
                }
                ("MOV", O::Register(reg), O::Address(ea)) => {
                    let a = address(&self.r, ea);
                    let v = get(&self.r, reg);
                    let size = width(reg);
                    assert!(
                        !p.readonly
                            .iter()
                            .any(|r| a < r.end && r.start < a + size as u32),
                        "write to immutable cell {a:x}"
                    );
                    self.put(a, size, v);
                    self.writes.push((a, size, v));
                    self.zero = v == 0;
                }
                ("MOV", O::Address(ea), O::Register(reg)) => {
                    let v = self.read(p, address(&self.r, ea), width(reg));
                    self.zero = set(&mut self.r, reg, v);
                }
                ("MOV", a, O::Register(reg)) => {
                    let v = value(&self.r, a);
                    self.zero = set(&mut self.r, reg, v);
                }
                ("AND" | "ADD" | "SUB", a, O::Register(reg)) => {
                    let old = get(&self.r, reg);
                    let v = value(&self.r, a);
                    let out = match i.mnemonic {
                        "AND" => old & v,
                        "ADD" => old.wrapping_add(v),
                        "SUB" => old.wrapping_sub(v),
                        _ => unreachable!(),
                    };
                    self.zero = set(&mut self.r, reg, out);
                }
                ("CMP", a, b) => {
                    let a = value(&self.r, a);
                    let b = value(&self.r, b);
                    self.zero = a == b;
                    self.carry = b < a;
                }
                ("BRA" | "BEQ" | "BNE" | "BCC", O::Address(Ea::PcRelative { value, .. }), _) => {
                    let take = match i.mnemonic {
                        "BRA" => true,
                        "BEQ" => self.zero,
                        "BNE" => !self.zero,
                        "BCC" => !self.carry,
                        _ => unreachable!(),
                    };
                    if i.mnemonic != "BRA" {
                        edges.insert((at, take));
                    }
                    if take {
                        pc = pc.wrapping_add_signed(value);
                    }
                }
                ("JSR", O::Address(Ea::Absolute { value, .. }), _) => {
                    if p.reader == Some(value) {
                        let parameter = get(&self.r, Reg::Word(0)) as u16;
                        assert_eq!(parameter, 0x28f);
                        self.parameter_reads.push(parameter);
                        self.r[0] = 0xa5a5_0000 | u32::from(self.word);
                        self.r[1] = 0xc3c3_aabb;
                        self.r[2] = 0x5a5a_ccdd;
                    } else {
                        let channel = p
                            .coils
                            .iter()
                            .position(|a| *a == value)
                            .unwrap_or_else(|| panic!("unknown callee {value:x}"));
                        let row = self.row();
                        assert!(row < 64);
                        let table = self.r[1];
                        let role = p.role(table);
                        let at = table + u32::from(row) * 4;
                        let words = [self.read(p, at, 2) as u16, self.read(p, at + 2, 2) as u16];
                        self.calls.push(CoilCall {
                            channel,
                            row,
                            table_role: role,
                            words,
                        });
                        // ER0..ER2 and CCR are caller-clobbered. ER3..ER7 survive.
                        self.r[0] = (role ^ u32::from(row) ^ channel as u32).rotate_left(7);
                        self.r[1] = !role;
                        self.r[2] = role.wrapping_mul(0x10203);
                    }
                    self.zero = false;
                    self.carry = true;
                }
                ("RTS", _, _) => {
                    assert!(end.is_none(), "early return from argument fragment");
                    assert_eq!(self.stack.len(), initial_depth);
                    assert_eq!(&self.r[3..], &saved[3..]);
                    return;
                }
                _ => panic!("unsupported native instruction at {at:x}: {i:?}"),
            }
        }
        panic!("native instruction budget exhausted at {pc:x}");
    }
}
