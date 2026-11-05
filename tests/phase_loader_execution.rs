//! Execute actual OEM loaders and their in-place specialization independently.
#![cfg(feature = "envelope")]
use h8_asm::{
    isa::{decode_insn, Ea, Insn, Operand as O, Reg, Size},
    Mode, Target,
};
use pioneer_optical::filters::phase::bundle::waveforms::{self, loader, resources};
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
    pointers: BTreeMap<u32, u32>,
    zero: bool,
    carry: bool,
    less_equal: bool,
    writes: Vec<(u16, u16)>,
    binding: loader::Binding,
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
    }
    fn value(&self, o: O) -> u32 {
        match o {
            O::Register(r) => self.get(r),
            O::Immediate { value, .. } => value,
            _ => panic!("value {o:?}"),
        }
    }
    fn load(&self, address: u32, size: Size) -> u32 {
        if size == Size::Long {
            if let Some(value) = self.pointers.get(&address) {
                return *value;
            }
        }
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
        if to == self.binding.coefficient_getter {
            self.set(Reg::Byte(8), self.get(Reg::Byte(0)));
        } else if to == self.binding.writer {
            self.writes
                .push((self.get(Reg::Word(0)) as u16, self.get(Reg::Word(8)) as u16));
        } else if to == self.binding.readback {
            assert_eq!(self.get(Reg::Word(0)), 0x4b0);
            self.set(Reg::Word(0), 0xa5b7);
        } else {
            panic!("unbound native helper {to:x}");
        }
    }
    fn run(image: &[u8], mode: u8) -> Vec<(u16, u16)> {
        let binding = loader::observe(image).unwrap();
        let graph = resources::observe(image).unwrap();
        let mut pointers = BTreeMap::new();
        for (table, range) in binding
            .tables
            .unwrap()
            .iter()
            .zip(&graph.selected.coefficients)
        {
            if let loader::Table::Pointer(cell) = table {
                pointers.insert(*cell, 0x410000 + range.start as u32);
            }
        }
        let code = loader::logical_program(image).unwrap();
        let mut program = BTreeMap::<usize, (Insn, usize)>::new();
        let mut at = 0;
        while at < code.len() {
            let d = decode_insn(&code[at..], Target::H8S2000, Mode::Advanced).unwrap();
            program.insert(at, (d.insn, d.len));
            at += d.len;
        }
        let mut c = Cpu {
            image,
            r: [0xa55a_1357; 8],
            stack: vec![],
            pointers,
            zero: false,
            carry: false,
            less_equal: false,
            writes: vec![],
            binding,
        };
        c.set(Reg::Byte(8), mode.into());
        let original = c.r;
        let mut pc = 0;
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
                ("MOV", a, O::Register(r)) => c.set(r, c.value(a)),
                ("EXTU", O::Register(Reg::Word(r)), _) => {
                    c.set(Reg::Word(r), c.get(Reg::Word(r)) & 255)
                }
                ("EXTS", O::Register(Reg::Long(r)), _) => {
                    c.set(Reg::Long(r), c.get(Reg::Word(r)) as i16 as i32 as u32)
                }
                ("SHLL", a, O::Register(r)) => c.set(r, c.get(r) << c.value(a)),
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
                    c.less_equal =
                        Self::signed(b, i.size.unwrap()) <= Self::signed(a, i.size.unwrap());
                }
                (
                    "BRA" | "BNE" | "BCS" | "BCC" | "BLE",
                    O::Address(Ea::PcRelative { value, .. }),
                    _,
                ) => {
                    let take = match i.mnemonic {
                        "BRA" => true,
                        "BNE" => !c.zero,
                        "BCS" => c.carry,
                        "BCC" => !c.carry,
                        "BLE" => c.less_equal,
                        _ => unreachable!(),
                    };
                    if take {
                        pc = pc.checked_add_signed(value as isize).unwrap();
                    }
                }
                ("JSR", O::Address(Ea::Absolute { value, .. }), _) => c.call(value),
                ("JSR", O::Address(Ea::Indirect(r)), _) => c.call(c.get(r)),
                ("NOP", _, _) => {}
                ("RTS", _, _) => {
                    assert!(c.stack.is_empty());
                    assert_eq!(&c.r[3..7], &original[3..7]);
                    assert_eq!(c.writes.len(), 20);
                    return c.writes;
                }
                _ => panic!("unsupported native loader instruction {i:?}"),
            }
        }
        panic!("native loader did not terminate");
    }
}

#[test]
fn specialized_loaders_preserve_every_dsp_write_and_saved_register() {
    let ud02 = "84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750";
    let xd08 = "3711cd5cdde5b5e7f288ccd7bc7fe1100eb6de5e40f3d0ffdcc528fb93ebeb46";
    for (target_hash, donor_hash) in [
        (
            "87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1",
            ud02,
        ),
        (
            "95664992a098ff6c3c8a9c4bae228209d956f4a1462c238fb37863b910b72149",
            ud02,
        ),
        (
            "e6bdfa9bd0220f618d3e4bf722a590c2e1cf4216431869ab399561b94c71f515",
            ud02,
        ),
        (
            "c93736b1fc66c7ada2d586044bf5d8a50a622b65e2f1fe6e74ad212f254adc1b",
            xd08,
        ),
    ] {
        let target = fixture(target_hash);
        let original = fixture(donor_hash);
        let source = resources::observe(&original).unwrap();
        for seed in [None, Some(0u16), Some(0x7fff), Some(0x8000), Some(0xffff)] {
            let mut donor = original.clone();
            if let Some(seed) = seed {
                for (role, range) in source.selected.coefficients.iter().enumerate() {
                    for (i, word) in donor[range.clone()].chunks_exact_mut(2).enumerate() {
                        word.copy_from_slice(
                            &seed
                                .wrapping_add((i as u16).wrapping_mul(997))
                                .wrapping_add(role as u16 * 313)
                                .to_be_bytes(),
                        );
                    }
                }
            }
            let changed = waveforms::specialize_ascending(&target, &donor).unwrap();
            for mode in [0, 1, 255] {
                assert_eq!(
                    Cpu::run(&changed, mode),
                    Cpu::run(&donor, mode),
                    "target {target_hash}, seed {seed:?}, mode {mode}"
                );
            }
        }
    }
}
