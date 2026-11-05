//! Executes only the changed fetch/address blocks, not the scale subroutines.
use h8_asm::{
    isa::{decode_insn, Ea, Operand, Reg},
    Mode, Target,
};

pub struct Cpu {
    registers: [u32; 8],
    zero: bool,
    carry: bool,
}
impl Cpu {
    pub fn new(index: u16) -> Self {
        let mut cpu = Self {
            registers: [0xa55a_5aa5; 8],
            zero: false,
            carry: false,
        };
        cpu.set(Reg::Byte(12), index.into());
        cpu.set(Reg::Word(5), (index * 2).into());
        cpu.set(Reg::Word(11), index.into());
        cpu
    }
    fn parts(reg: Reg) -> (usize, u32, u32) {
        match reg {
            Reg::Byte(n) => ((n % 8) as usize, if n < 8 { 8 } else { 0 }, 255),
            Reg::Word(n) => ((n % 8) as usize, if n < 8 { 0 } else { 16 }, 65535),
            Reg::Long(n) => (n as usize, 0, u32::MAX),
            _ => panic!("unsupported {reg:?}"),
        }
    }
    pub fn get(&self, reg: Reg) -> u32 {
        let (n, shift, mask) = Self::parts(reg);
        (self.registers[n] >> shift) & mask
    }
    fn set(&mut self, reg: Reg, value: u32) {
        let (n, shift, mask) = Self::parts(reg);
        self.registers[n] = (self.registers[n] & !(mask << shift)) | ((value & mask) << shift);
        self.zero = value & mask == 0;
    }
    fn value(&self, op: Operand, table: (u32, &[u8])) -> u32 {
        match op {
            Operand::Register(r) => self.get(r),
            Operand::Immediate { value, .. } => value,
            Operand::Address(ea) => {
                let address = match ea {
                    Ea::Absolute { value, .. } => value,
                    Ea::Displacement { base, value, .. } => {
                        self.get(base).wrapping_add_signed(value)
                    }
                    _ => panic!("unsupported {ea:?}"),
                };
                let at = address.checked_sub(table.0).unwrap() as usize;
                u16::from_be_bytes(table.1[at..at + 2].try_into().unwrap()).into()
            }
            _ => panic!("unsupported {op:?}"),
        }
    }
    pub fn run(&mut self, code: &[u8], table: (u32, &[u8])) {
        let mut pc = 0;
        for _ in 0..64 {
            if pc == code.len() {
                return;
            }
            let decoded = decode_insn(&code[pc..], Target::H8S2600, Mode::Advanced).unwrap();
            pc += decoded.len;
            let i = decoded.insn;
            let [a, b, _] = i.operands;
            match (i.mnemonic, a, b) {
                ("MOV", a, Operand::Register(r)) => self.set(r, self.value(a, table)),
                ("INC" | "ADD", a, Operand::Register(r)) => {
                    self.set(r, self.get(r).wrapping_add(self.value(a, table)))
                }
                ("NEG", Operand::Register(r), _) => self.set(r, self.get(r).wrapping_neg()),
                ("EXTS", Operand::Register(Reg::Long(n)), _) => self.set(
                    Reg::Long(n),
                    self.get(Reg::Word(n)) as u16 as i16 as i32 as u32,
                ),
                ("SHLL", Operand::Immediate { value, .. }, Operand::Register(r)) => {
                    self.set(r, self.get(r) << value)
                }
                ("CMP", a, b) => {
                    let (left, right) = (self.value(b, table), self.value(a, table));
                    self.zero = left == right;
                    self.carry = left < right;
                }
                ("BRA" | "BNE" | "BCC", Operand::Address(Ea::PcRelative { value, .. }), _) => {
                    if i.mnemonic == "BRA"
                        || (i.mnemonic == "BNE" && !self.zero)
                        || (i.mnemonic == "BCC" && !self.carry)
                    {
                        pc = pc.wrapping_add_signed(value as isize);
                    }
                }
                ("NOP", _, _) => {}
                _ => panic!("unsupported {i:?}"),
            }
        }
        panic!("block did not terminate");
    }
}
