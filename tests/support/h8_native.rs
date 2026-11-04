//! Bounded H8 instruction execution for native-code KATs. No cryptographic or
//! firmware-operation shortcuts; unknown instructions/addressing modes panic.
use h8_asm::{
    isa::{decode_insn, Decoded, Ea, Insn, Operand, Reg, Size},
    Mode, Target,
};

pub struct Cpu {
    pub er: [u32; 8],
    pub pc: u32,
    pub memory: Vec<u8>,
    pub steps: usize,
    pub instruction_limit: usize,
    pub writes: Vec<(u32, usize)>,
    pub z: bool,
    pub n: bool,
    pub v: bool,
    pub c: bool,
    pub ccr_upper: u8,
}
impl Cpu {
    pub fn new(size: usize) -> Self {
        Self {
            er: [0; 8],
            pc: 0,
            memory: vec![0; size],
            steps: 0,
            instruction_limit: 100_000_000,
            writes: vec![],
            z: false,
            n: false,
            v: false,
            c: false,
            ccr_upper: 0,
        }
    }
    pub fn load(&mut self, at: u32, bytes: &[u8]) {
        self.memory[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
    }
    pub fn read(&self, at: u32, width: usize) -> u32 {
        self.memory[at as usize..at as usize + width]
            .iter()
            .fold(0, |v, b| v << 8 | u32::from(*b))
    }
    pub fn write(&mut self, at: u32, width: usize, value: u32) {
        self.writes.push((at, width));
        self.memory[at as usize..at as usize + width]
            .copy_from_slice(&value.to_be_bytes()[4 - width..]);
    }
    fn width(size: Option<Size>) -> usize {
        match size.expect("operand width") {
            Size::Byte => 1,
            Size::Word => 2,
            Size::Long => 4,
        }
    }
    fn mask(width: usize) -> u32 {
        match width {
            1 => 0xff,
            2 => 0xffff,
            4 => u32::MAX,
            _ => panic!("width"),
        }
    }
    fn reg(&self, r: Reg) -> u32 {
        match r {
            Reg::Long(i) => self.er[i as usize],
            Reg::Word(i) => self.er[(i & 7) as usize] >> if i < 8 { 0 } else { 16 } & 0xffff,
            Reg::Byte(i) => self.er[(i & 7) as usize] >> if i < 8 { 8 } else { 0 } & 0xff,
            Reg::Ccr => {
                u32::from(self.ccr_upper)
                    | (u32::from(self.c))
                    | (u32::from(self.v) << 1)
                    | (u32::from(self.z) << 2)
                    | (u32::from(self.n) << 3)
            }
            _ => panic!("unsupported register {r:?}"),
        }
    }
    fn set_reg(&mut self, r: Reg, value: u32) {
        match r {
            Reg::Long(i) => self.er[i as usize] = value,
            Reg::Word(i) => {
                let shift = if i < 8 { 0 } else { 16 };
                let reg = &mut self.er[(i & 7) as usize];
                *reg = (*reg & !(0xffff << shift)) | ((value & 0xffff) << shift);
            }
            Reg::Byte(i) => {
                let shift = if i < 8 { 8 } else { 0 };
                let reg = &mut self.er[(i & 7) as usize];
                *reg = (*reg & !(0xff << shift)) | ((value & 0xff) << shift);
            }
            Reg::Ccr => {
                self.ccr_upper = value as u8 & 0xf0;
                self.c = value & 1 != 0;
                self.v = value & 2 != 0;
                self.z = value & 4 != 0;
                self.n = value & 8 != 0;
            }
            _ => panic!("unsupported register {r:?}"),
        }
    }
    fn address(&mut self, ea: Ea, width: usize) -> u32 {
        match ea {
            Ea::Indirect(r) => self.reg(r),
            Ea::Displacement { base, value, .. } => self.reg(base).wrapping_add_signed(value),
            Ea::Absolute { value, .. } => value,
            Ea::PreDecrement(r) => {
                let at = self.reg(r).wrapping_sub(width as u32);
                self.set_reg(r, at);
                at
            }
            Ea::PostIncrement(r) => {
                let at = self.reg(r);
                self.set_reg(r, at.wrapping_add(width as u32));
                at
            }
            _ => panic!("unsupported address {ea:?}"),
        }
    }
    fn value(&mut self, op: Operand, width: usize) -> u32 {
        match op {
            Operand::Immediate { value, .. } => value,
            Operand::Register(r) => self.reg(r),
            Operand::Address(ea) => {
                let at = self.address(ea, width);
                self.read(at, width)
            }
            _ => panic!("unsupported read operand {op:?}"),
        }
    }
    fn put(&mut self, op: Operand, width: usize, value: u32) {
        match op {
            Operand::Register(r) => self.set_reg(r, value),
            Operand::Address(ea) => {
                let at = self.address(ea, width);
                self.write(at, width, value)
            }
            _ => panic!("unsupported write operand {op:?}"),
        }
    }
    fn nz(&mut self, value: u32, width: usize) {
        let value = value & Self::mask(width);
        self.z = value == 0;
        self.n = value & (1 << (width * 8 - 1)) != 0;
        self.v = false;
    }
    fn arithmetic(&mut self, a: u32, b: u32, width: usize, subtract: bool) -> u32 {
        let mask = Self::mask(width);
        let a = a & mask;
        let b = b & mask;
        let sign = 1 << (width * 8 - 1);
        let result = if subtract {
            a.wrapping_sub(b)
        } else {
            a.wrapping_add(b)
        } & mask;
        self.nz(result, width);
        self.c = if subtract {
            a < b
        } else {
            u64::from(a) + u64::from(b) > u64::from(mask)
        };
        self.v = if subtract {
            (a ^ b) & (a ^ result) & sign != 0
        } else {
            (!(a ^ b)) & (a ^ result) & sign != 0
        };
        result
    }
    fn branch(&self, name: &str) -> bool {
        match name {
            "BRA" => true,
            "BRN" => false,
            "BHI" => !self.c && !self.z,
            "BLS" => self.c || self.z,
            "BCC" | "BHS" => !self.c,
            "BCS" | "BLO" => self.c,
            "BNE" => !self.z,
            "BEQ" => self.z,
            "BVC" => !self.v,
            "BVS" => self.v,
            "BPL" => !self.n,
            "BMI" => self.n,
            "BGE" => self.n == self.v,
            "BLT" => self.n != self.v,
            "BGT" => !self.z && self.n == self.v,
            "BLE" => self.z || self.n != self.v,
            _ => panic!("unsupported branch {name}"),
        }
    }
    fn decode(&self) -> Decoded {
        let b = &self.memory[self.pc as usize..];
        // h8-asm 0.5's legacy decoder omits this valid long displacement form.
        if b.starts_with(&[1, 0, 0x78]) && b[3] & 0x8f == 0 && b[4] == 0x6b && b[5] & 0x78 == 0x20 {
            let ea = Operand::Address(Ea::Displacement {
                base: Reg::Long(b[3] >> 4),
                value: i32::from_be_bytes(b[6..10].try_into().unwrap()),
                bits: 32,
            });
            let reg = Operand::Register(Reg::Long(b[5] & 7));
            let operands = if b[5] & 0x80 != 0 {
                [reg, ea, Operand::None]
            } else {
                [ea, reg, Operand::None]
            };
            return Decoded {
                insn: Insn::new("MOV", Some(Size::Long), operands),
                len: 10,
            };
        }
        decode_insn(b, Target::H8S2000, Mode::Advanced)
            .unwrap_or_else(|e| panic!("decode {:x}: {e:?}, bytes {:02x?}", self.pc, &b[..10]))
    }
    pub fn step(&mut self) {
        self.steps += 1;
        assert!(self.steps < self.instruction_limit, "instruction budget");
        let decoded = self.decode();
        let insn = decoded.insn;
        let [a, b, _] = insn.operands;
        let mut next = self.pc + decoded.len as u32;
        let width = insn.size.map(|s| Self::width(Some(s))).unwrap_or(4);
        match insn.mnemonic {
            "NOP" => {}
            "STC" | "LDC" => {
                let value = self.value(a, 1);
                self.put(b, 1, value);
            }
            "ORC" | "ANDC" | "XORC" => {
                let rhs = self.value(a, 1);
                let lhs = self.reg(Reg::Ccr);
                let value = match insn.mnemonic {
                    "ORC" => lhs | rhs,
                    "ANDC" => lhs & rhs,
                    _ => lhs ^ rhs,
                };
                self.set_reg(Reg::Ccr, value);
            }
            "MOV" => {
                let value = self.value(a, width);
                self.put(b, width, value);
                self.nz(value, width);
            }
            "ADD" | "SUB" | "CMP" => {
                let left = self.value(b, width);
                let right = self.value(a, width);
                let value = self.arithmetic(left, right, width, insn.mnemonic != "ADD");
                if insn.mnemonic != "CMP" {
                    self.put(b, width, value);
                }
            }
            "ADDS" | "SUBS" => {
                let left = self.value(b, 4);
                let right = self.value(a, 4);
                self.put(
                    b,
                    4,
                    if insn.mnemonic == "ADDS" {
                        left.wrapping_add(right)
                    } else {
                        left.wrapping_sub(right)
                    },
                );
            }
            "AND" | "OR" | "XOR" => {
                let left = self.value(b, width);
                let right = self.value(a, width);
                let value = match insn.mnemonic {
                    "AND" => left & right,
                    "OR" => left | right,
                    _ => left ^ right,
                };
                self.put(b, width, value);
                self.nz(value, width);
            }
            "INC" | "DEC" => {
                let (count, dest) = if b == Operand::None {
                    (1, a)
                } else {
                    (self.value(a, width), b)
                };
                let old_c = self.c;
                let value = self.value(dest, width);
                let result = self.arithmetic(value, count, width, insn.mnemonic == "DEC");
                self.c = old_c;
                self.put(dest, width, result);
            }
            "NOT" => {
                let value = !self.value(a, width) & Self::mask(width);
                self.put(a, width, value);
                self.nz(value, width);
            }
            "EXTU" => {
                let value = self.value(a, width) & Self::mask(width / 2);
                self.put(a, width, value);
                self.nz(value, width);
            }
            "SHLL" | "SHLR" | "ROTR" | "ROTL" => {
                let (count, dest) = if b == Operand::None {
                    (1, a)
                } else {
                    (self.value(a, width), b)
                };
                let mut value = self.value(dest, width);
                let bits = width * 8;
                for _ in 0..count {
                    let right = matches!(insn.mnemonic, "SHLR" | "ROTR");
                    self.c = if right {
                        value & 1 != 0
                    } else {
                        value & (1 << (bits - 1)) != 0
                    };
                    value = if right { value >> 1 } else { value << 1 } & Self::mask(width);
                    if insn.mnemonic == "ROTR" && self.c {
                        value |= 1 << (bits - 1)
                    }
                    if insn.mnemonic == "ROTL" && self.c {
                        value |= 1
                    }
                }
                self.put(dest, width, value);
                self.nz(value, width);
            }
            "BTST" => {
                let bit = self.value(a, 1);
                let value = self.value(b, 1);
                self.z = value & (1 << bit) == 0;
            }
            "STM" => {
                let Operand::Registers { first, last } = a else {
                    panic!("STM operands {insn:?}")
                };
                for r in (first..=last).rev() {
                    self.er[7] -= 4;
                    self.write(self.er[7], 4, self.er[r as usize]);
                }
            }
            "LDM" => {
                let Operand::Registers { first, last } = b else {
                    panic!("LDM operands {insn:?}")
                };
                for r in first..=last {
                    self.er[r as usize] = self.read(self.er[7], 4);
                    self.er[7] += 4;
                }
            }
            "JSR" | "JMP" => {
                let target = match a {
                    Operand::Address(ea) => self.address(ea, 4),
                    Operand::Register(r) => self.reg(r),
                    _ => panic!("call operand {insn:?}"),
                };
                if insn.mnemonic == "JSR" {
                    self.er[7] -= 4;
                    self.write(self.er[7], 4, next);
                }
                next = target;
            }
            "BSR" => {
                let Operand::Address(Ea::PcRelative { value, .. }) = a else {
                    panic!("BSR operand {insn:?}")
                };
                self.er[7] -= 4;
                self.write(self.er[7], 4, next);
                next = next.wrapping_add_signed(value);
            }
            "RTS" => {
                next = self.read(self.er[7], 4);
                self.er[7] += 4;
            }
            name if name.starts_with('B') => {
                if self.branch(name) {
                    let Operand::Address(Ea::PcRelative { value, .. }) = a else {
                        panic!("branch operand {insn:?}")
                    };
                    next = next.wrapping_add_signed(value);
                }
            }
            _ => panic!("unsupported {:x}: {insn:?}", self.pc),
        }
        self.pc = next;
    }
    #[allow(dead_code)] // SHA tests call directly; bridge tests drive individual steps.
    pub fn call(&mut self, entry: u32) {
        const SENTINEL: u32 = 0x00ff_fffe;
        self.er[7] -= 4;
        self.write(self.er[7], 4, SENTINEL);
        self.pc = entry;
        while self.pc != SENTINEL {
            self.step();
        }
    }
}
