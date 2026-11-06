//! Native actual-mode coherence across DSP and movement controller paths.
#![cfg(feature = "envelope")]
use pioneer_optical::filters::phase::bundle::waveforms::resources::dsp_control_bridge as bridge;

#[test]
#[ignore = "requires PIONEER_PHASE_STATE decoded exact Normal/Kernel pairs"]
fn actual_paired_computed_and_plain_mode_graphs() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_STATE").unwrap());
    let target = root
        .join("phase-corpus/459673172ab424ff3a698d58d03421364ebb596435eb39a265728da02eb22851.bin");
    let donor =
        root.join("normals/87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1.bin");
    let t = std::fs::read(&target).unwrap();
    let d = std::fs::read(&donor).unwrap();
    let tk = std::fs::read(target.with_extension("kernel.bin")).unwrap();
    let dk = std::fs::read(donor.with_extension("kernel.bin")).unwrap();
    let proof = bridge::prove_plain_transplant(&t, &d, &tk, &dk).unwrap();
    assert_eq!(proof.donor.coherence.start + 0x410000, 0x539950);
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}
fn fixtures() -> Vec<(Vec<u8>, Vec<u8>)> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-dsp-control.json")).unwrap();
    rows.as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let mut n = vec![255; row["size"].as_u64().unwrap() as usize];
            for span in row["spans"].as_array().unwrap() {
                let at = span[0].as_u64().unwrap() as usize;
                let b = unhex(span[1].as_str().unwrap());
                n[at..at + b.len()].copy_from_slice(&b);
            }
            let compressed = unhex(row["kernel_zlib"].as_str().unwrap());
            let mut k = Vec::new();
            flate2::read::ZlibDecoder::new(compressed.as_slice())
                .read_to_end(&mut k)
                .unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(&k)),
                row["kernel_sha256"].as_str().unwrap()
            );
            (n, k)
        })
        .collect()
}
#[test]
fn mode_graph_requires_native_relationships_and_exact_reference_closure() {
    let f = fixtures();
    let (t, tk) = &f[0];
    let (d, dk) = &f[1];
    let proof = bridge::prove_plain_transplant(t, d, tk, dk).unwrap();
    assert!(bridge::prove_plain_transplant(t, d, &[], dk).is_err());
    for (n, k, b) in [(t, tk, &proof.target), (d, dk, &proof.donor)] {
        // Corrupt both input preparation and the post-helper direction transfer.
        for at in [
            b.coherence.start + 1,
            b.coherence.start + 45,
            b.control.end - 3,
            b.setter.start + 1,
            b.movement.start + 7,
            b.tick.start + 30,
        ] {
            let mut changed = n.clone();
            changed[at] ^= 1;
            assert!(
                bridge::observe(&changed, k).is_err(),
                "accepted changed instruction at {at:x}"
            );
        }
        for address in [
            b.loader.start,
            b.loader.start + 2,
            b.coherence.start + 2,
            b.coherence.start + 44,
        ] {
            let address = 0x410000 + address as u32;
            let mut changed = n.clone();
            changed[0x401..0x405].copy_from_slice(&address.to_be_bytes());
            assert!(bridge::observe(&changed, k).is_err());
            let mut resident = k.clone();
            resident[0x801..0x805].copy_from_slice(&address.to_be_bytes());
            assert!(bridge::observe(n, &resident).is_err());
        }
        let mut changed = n.clone();
        changed[b.vtable.start + 19] ^= 2;
        assert!(bridge::observe(&changed, k).is_err());
    }
}

use h8_asm::{
    isa::{decode_insn, Ea, Operand as O, Reg, Size},
    Mode, Target,
};
use std::collections::BTreeMap;
struct Machine<'a> {
    n: &'a [u8],
    l: pioneer_optical::filters::phase::bundle::waveforms::loader::Binding,
    r: [u32; 8],
    memory: BTreeMap<u32, u8>,
    zero: bool,
}
impl Machine<'_> {
    fn coordinates(r: Reg) -> (usize, u32, u32) {
        match r {
            Reg::Byte(n) => ((n % 8) as usize, if n < 8 { 8 } else { 0 }, 255),
            Reg::Word(n) => ((n % 8) as usize, if n < 8 { 0 } else { 16 }, 65535),
            Reg::Long(n) => (n as usize, 0, u32::MAX),
            _ => panic!("{r:?}"),
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
    fn width(size: Option<Size>) -> u32 {
        match size.unwrap() {
            Size::Byte => 1,
            Size::Word => 2,
            Size::Long => 4,
        }
    }
    fn load(&self, a: u32, w: u32) -> u32 {
        (0..w).fold(0, |v, i| {
            (v << 8) | u32::from(*self.memory.get(&(a + i)).unwrap_or(&0))
        })
    }
    fn store(&mut self, a: u32, w: u32, v: u32) {
        for i in 0..w {
            self.memory.insert(a + i, (v >> ((w - i - 1) * 8)) as u8);
        }
    }
    fn address(&mut self, ea: Ea, w: u32) -> u32 {
        match ea {
            Ea::Absolute { value, .. } => value,
            Ea::Indirect(r) => self.get(r),
            Ea::Displacement { base, value, .. } => self.get(base).wrapping_add_signed(value),
            Ea::PreDecrement(r) => {
                let a = self.get(r) - w;
                self.r[7] = a;
                a
            }
            Ea::PostIncrement(r) => {
                let a = self.get(r);
                self.r[7] = a + w;
                a
            }
            _ => panic!("{ea:?}"),
        }
    }
    fn value(&mut self, o: O, w: u32) -> u32 {
        match o {
            O::Register(r) => self.get(r),
            O::Immediate { value, .. } => value,
            O::Address(ea) => {
                let a = self.address(ea, w);
                self.load(a, w)
            }
            _ => panic!("{o:?}"),
        }
    }
    fn run(&mut self, b: &bridge::Binding, tick: bool) -> u8 {
        let (writer, reader) = (self.l.writer, self.l.readback);
        let mut pc = if tick {
            b.tick.start
        } else {
            b.coherence.start
        };
        let mut returns = Vec::new();
        let mut loader_mode = None;
        let object = self.r[7];
        if tick {
            self.r[0] = object;
        }
        for _ in 0..1000 {
            let d = decode_insn(&self.n[pc..], Target::H8S2000, Mode::Advanced).unwrap();
            let i = d.insn;
            let ops = i.operands;
            let at = pc;
            pc += d.len;
            match i.mnemonic {
                "JSR" => {
                    let target = match ops[0] {
                        O::Address(Ea::Absolute { value, .. }) => value,
                        O::Address(Ea::Indirect(r)) => self.get(r),
                        _ => panic!(),
                    };
                    if at == b.coherence.start + 2 {
                        loader_mode = Some(self.get(Reg::Byte(8)) as u8);
                        self.r[0] = 0x88ab1122;
                        self.r[1] = 0x772255aa;
                        self.r[2] = 0xdeadcafe;
                    } else if target == writer || target == reader {
                        self.r[0] = 0x1357a55a;
                        self.r[1] = 0x135799aa;
                        self.r[2] = 0xdeadbeef;
                    } else if tick && at == b.tick.start + 6 {
                        self.r[0] = 0x1234;
                        self.r[1] = 0xaaaa5555;
                        self.r[2] = 0x13572468;
                    } else if tick && at == b.tick.start + 30 {
                        let direction = self.load(object + 6, 1) as u8;
                        assert_eq!(
                            self.get(Reg::Word(1)),
                            if direction == 0 { 0xffff } else { 1 }
                        );
                        return direction;
                    } else {
                        returns.push(pc);
                        pc = target as usize - 0x410000;
                    }
                }
                "RTS" => pc = returns.pop().unwrap(),
                "STM" => {
                    let O::Registers { first, last } = ops[0] else {
                        panic!()
                    };
                    for reg in (first..=last).rev() {
                        self.r[7] -= 4;
                        self.store(self.r[7], 4, self.r[reg as usize]);
                    }
                }
                "LDM" => {
                    let O::Registers { first, last } = ops[1] else {
                        panic!()
                    };
                    for reg in first..=last {
                        self.r[reg as usize] = self.load(self.r[7], 4);
                        self.r[7] += 4;
                    }
                }
                "MOV" => {
                    let w = Self::width(i.size);
                    let v = self.value(ops[0], w);
                    match ops[1] {
                        O::Register(r) => self.set(r, v),
                        O::Address(ea) => {
                            let a = self.address(ea, w);
                            self.store(a, w, v);
                            self.zero = v == 0;
                        }
                        _ => panic!(),
                    }
                    if !tick && at == b.movement.start + 16 {
                        assert_eq!(self.load(object + 6, 1), u32::from(loader_mode.unwrap()));
                        assert_eq!(self.r[6] & 255, u32::from(loader_mode.unwrap()));
                        return loader_mode.unwrap();
                    }
                }
                "SUB" => {
                    let O::Register(r) = ops[1] else { panic!() };
                    let v = self.get(r).wrapping_sub(self.value(ops[0], 0));
                    self.set(r, v);
                }
                "AND" => {
                    let O::Register(r) = ops[1] else { panic!() };
                    let v = self.value(ops[0], 0) & self.get(r);
                    self.set(r, v);
                }
                "CMP" => {
                    let a = self.value(ops[0], 0);
                    let v = self.value(ops[1], 0);
                    self.zero = a == v;
                }
                "BSET" | "BCLR" => {
                    let O::Register(r) = ops[1] else { panic!() };
                    let bit = self.value(ops[0], 0);
                    let v = if i.mnemonic == "BSET" {
                        self.get(r) | (1 << bit)
                    } else {
                        self.get(r) & !(1 << bit)
                    };
                    self.set(r, v);
                }
                "BNE" | "BEQ" | "BRA" => {
                    let O::Address(Ea::PcRelative { value, .. }) = ops[0] else {
                        panic!()
                    };
                    if i.mnemonic == "BRA" || (i.mnemonic == "BEQ") == self.zero {
                        pc = pc.wrapping_add_signed(value as isize);
                    }
                }
                "EXTU" => {
                    let O::Register(r) = ops[0] else { panic!() };
                    self.set(r, self.get(r) & 255);
                }
                "NEG" => {
                    let O::Register(r) = ops[0] else { panic!() };
                    self.set(r, 0u32.wrapping_sub(self.get(r)));
                }
                _ => panic!("{:x} {i:?}", at + 0x410000),
            }
        }
        panic!("native execution did not reach its bound direction consumer")
    }
}
#[test]
fn every_native_mode_survives_both_control_branches_and_drives_the_same_direction() {
    for (n, k) in fixtures() {
        let b = bridge::observe(&n, &k).unwrap();
        let native_loader =
            pioneer_optical::filters::phase::bundle::waveforms::loader::observe(&n).unwrap();
        for mode in 0..=255u32 {
            for port in [4, 3] {
                let mut machine = Machine {
                    n: &n,
                    l: native_loader.clone(),
                    r: [0; 8],
                    memory: BTreeMap::new(),
                    zero: false,
                };
                machine.r[4] = 0x12345609;
                machine.r[5] = 0x12345678;
                machine.r[6] = 0xdeadbe00 | mode;
                machine.r[7] = 0x900000;
                machine.memory.insert(0xf930, port);
                assert_eq!(machine.run(&b, false), mode as u8);
                // The constructor has just saved registers; the callback runs later
                // with its own stack and the previously populated native object.
                machine.r[7] = 0x900000;
                assert_eq!(machine.run(&b, true), mode as u8);
            }
        }
    }
}
