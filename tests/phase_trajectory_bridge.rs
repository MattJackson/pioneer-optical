#![cfg(feature = "envelope")]
use pioneer_optical::filters::phase::bundle::waveforms::resources::{
    trajectory_bridge as bridge, trajectory_profile as profile,
};
fn fixture(role: &str) -> Vec<u8> {
    let f: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-trajectory-bridge.json")).unwrap();
    let f = f
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["role"] == role)
        .unwrap();
    let mut n = vec![255; f["size"].as_u64().unwrap() as usize];
    for s in f["spans"].as_array().unwrap() {
        let a = s[0].as_u64().unwrap() as usize;
        let h = s[1].as_str().unwrap();
        for i in 0..h.len() / 2 {
            n[a + i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
        }
    }
    n
}
fn plan(t: &[u8], s: &[u8], k: &[u8]) -> Option<bridge::Plan> {
    let [c, d] = profile::lengths();
    bridge::plan(t, s, k, 0x1000..0x1000 + c, 0x3000..0x3000 + d)
}
#[test]
fn complete_controller_graph_and_private_state_are_required() {
    let t = fixture("target");
    let s = fixture("source");
    let k = fixture("kernel");
    let p = plan(&t, &s, &k).expect("complete native controller graph");
    assert_eq!(p.writes.len(), 6);
    for a in [
        0x53960a, 0x538364, 0x539d76, 0x54bf4e, 0x54c01a, 0x538a88, 0x53957e,
    ] {
        let mut changed = t.clone();
        changed[a - 0x410000] ^= 1;
        assert!(plan(&changed, &s, &k).is_none(), "{a:x}");
    }
    for a in [
        0x5398a8u32,
        0x53956c,
        0x539620,
        0x53966e,
        0x538366,
        0xa05dde,
    ] {
        let mut changed = t.clone();
        changed[0x801..0x805].copy_from_slice(&a.to_be_bytes());
        assert!(plan(&changed, &s, &k).is_none(), "extra reference {a:x}");
    }
    let mut changed = k.clone();
    changed[1] ^= 1;
    assert!(plan(&t, &s, &changed).is_none());
}
#[test]
#[ignore = "requires locally reconstructed exact Normal/Kernel evidence"]
fn exact_native_pair_has_no_unowned_controller_or_ram_references() {
    let root = std::path::Path::new("/Users/matthew/Developer/tmp/release-0180");
    let t = std::fs::read(
        root.join("normals/87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1.bin"),
    )
    .unwrap();
    let s =
        std::fs::read(root.join(
            "phase-corpus/ddfa7d758503458345de549321b048574a162272b7e3ee0cfe2e257110eb6982.bin",
        ))
        .unwrap();
    let k = fixture("kernel");
    assert!(profile::validate_default(&t, &k).is_some(), "default");
    assert!(plan(&t, &s, &k).is_some());
}
#[test]
fn controller_reference_closure() {
    use pioneer_optical::filters::phase::bundle::waveforms::resources::retirement;
    let t = fixture("target");
    let k = fixture("kernel");
    let s = |a: usize, z: usize| a - 0x410000..z - 0x410000;
    let g = [
        s(0x538350, 0x53836e),
        s(0x5388a4, 0x5388c4),
        s(0x53956c, 0x53957e),
        s(0x5395e8, 0x539620),
        s(0x539620, 0x53962e),
        s(0x5398a6, 0x539b2c),
        s(0x53966e, 0x539766),
    ];
    let mut r = g.to_vec();
    r[0].start += 1;
    r[1].start += 1;
    assert!(retirement::references_clear(
        &t,
        &k,
        &r,
        &g,
        &[
            g[0].clone(),
            g[1].clone(),
            g[2].clone(),
            g[3].clone(),
            g[4].clone(),
            g[5].clone(),
            s(0x53966e, 0x5396a8),
            s(0x5396a8, 0x539766)
        ]
    )
    .is_some());
}

use h8_asm::{
    isa::{decode_insn, Ea, Operand as O, Reg, Size},
    Mode, Target,
};
use std::collections::BTreeMap;
struct Vm<'a> {
    image: &'a [u8],
    r: [u32; 8],
    m: BTreeMap<u32, u8>,
    z: bool,
    c: bool,
    n: bool,
    v: bool,
    object: u32,
    signaled: bool,
    timer: bool,
    row: u8,
    total: i32,
    steps: usize,
    abort_after: Option<usize>,
    callback: u32,
    reports: usize,
    status: Vec<u32>,
    media: bool,
    sensor: u8,
    trace: Vec<(u32, u32)>,
    stop_at: u32,
}
impl Vm<'_> {
    fn coord(r: Reg) -> (usize, u32, u32) {
        match r {
            Reg::Byte(n) => ((n % 8) as usize, if n < 8 { 8 } else { 0 }, 255),
            Reg::Word(n) => ((n % 8) as usize, if n < 8 { 0 } else { 16 }, 65535),
            Reg::Long(n) => (n as usize, 0, u32::MAX),
            _ => panic!(),
        }
    }
    fn get(&self, r: Reg) -> u32 {
        let (n, s, m) = Self::coord(r);
        (self.r[n] >> s) & m
    }
    fn set(&mut self, r: Reg, v: u32) {
        let (n, s, m) = Self::coord(r);
        self.r[n] = (self.r[n] & !(m << s)) | ((v & m) << s);
    }
    fn flags(&mut self, v: u32, w: u32) {
        let mask = if w == 4 { u32::MAX } else { (1 << (w * 8)) - 1 };
        self.z = v & mask == 0;
        self.n = v & (1 << (w * 8 - 1)) != 0;
        self.v = false;
    }
    fn load(&self, a: u32, w: u32) -> u32 {
        (0..w).fold(0, |v, i| {
            let x = a + i;
            let b = self.m.get(&x).copied().unwrap_or_else(|| {
                if (0x410000..0x410000 + self.image.len() as u32).contains(&x) {
                    self.image[(x - 0x410000) as usize]
                } else {
                    0
                }
            });
            (v << 8) | u32::from(b)
        })
    }
    fn store(&mut self, a: u32, w: u32, v: u32) {
        for i in 0..w {
            self.m.insert(a + i, (v >> ((w - i - 1) * 8)) as u8);
        }
    }
    fn push(&mut self, v: u32) {
        self.r[7] -= 4;
        self.store(self.r[7], 4, v);
    }
    fn pop(&mut self) -> u32 {
        let v = self.load(self.r[7], 4);
        self.r[7] += 4;
        v
    }
    fn addr(&mut self, a: Ea, w: u32) -> u32 {
        match a {
            Ea::Absolute { value, .. } => value,
            Ea::Indirect(r) => self.get(r),
            Ea::Displacement { base, value, .. } => self.get(base).wrapping_add_signed(value),
            Ea::PreDecrement(r) => {
                let a = self.get(r) - w;
                self.set(r, a);
                a
            }
            Ea::PostIncrement(r) => {
                let a = self.get(r);
                self.set(r, a + w);
                a
            }
            _ => panic!("{a:?}"),
        }
    }
    fn value(&mut self, o: O, w: u32) -> u32 {
        match o {
            O::Register(r) => self.get(r),
            O::Immediate { value, .. } => value,
            O::Address(a) => {
                let a = self.addr(a, w);
                self.load(a, w)
            }
            _ => panic!("{o:?}"),
        }
    }
    fn service(&mut self, pc: u32) -> bool {
        if self.stop_at != 0 && pc == 0x538a88 {
            return false;
        }
        match pc {
            0x522140 => self.r[0] = 0x5200,
            0x522232 => self.set(Reg::Byte(8), u32::from(self.media)),
            0x52219c => self.set(Reg::Word(0), 20),
            // Native special modes also terminate on the hardware end sensor.
            // Model both an asserted sensor and a rising edge after512 outputs.
            0x57bbfc => self.set(
                Reg::Byte(8),
                u32::from(if self.steps >= 512 { 1 } else { self.sensor }),
            ),
            0x54cae2 => {}
            0x53a940 => self.r[0] = 0x5100,
            0x53ad8e => self.status.push(self.get(Reg::Word(1))),
            0x538c7a => self.r[0] = 0x5000,
            0x538b74 => self.set(Reg::Byte(8), u32::from(self.row)),
            0x538b24 | 0x538b2c => {
                self.trace.push((pc, self.get(Reg::Byte(9))));
            }
            0x538a88 => {
                let delta = self.get(Reg::Word(1)) as i16 as i32;
                self.trace.push((pc, delta as u32));
                self.total += delta;
                self.row = (i32::from(self.row) + delta).rem_euclid(64) as u8;
                self.steps += 1;
            }
            0x530bae => self.r[0] = 0x6000,
            0x551f60 => self.signaled = false,
            0x551f8a => {
                assert_eq!(self.get(Reg::Word(1)), 0x800);
                self.signaled = true;
            }
            0x539d58 => {
                assert_eq!(self.object, 0);
                self.object = self.r[0];
            }
            0x539d76 => {
                assert_eq!(self.object, self.r[0]);
                let table = self.load(self.object, 4);
                assert_eq!(self.load(table + 16, 4), self.callback);
                assert_eq!(self.load(table + 10, 4), 0);
                self.timer = true;
            }
            0x539d98 => {
                self.trace.push((pc, self.get(Reg::Word(1))));
                assert_eq!(self.object, self.r[0]);
            }
            0x539d8c => self.timer = false,
            0x539d6a => {
                assert_eq!(self.object, self.r[0]);
                self.timer = false;
                self.object = 0;
            }
            0x551f0e => {
                for tick in 0..40000 {
                    if self.signaled {
                        break;
                    }
                    assert!(self.timer);
                    if self.abort_after == Some(tick) {
                        let saved = self.r;
                        self.run(0x53957e);
                        self.r = saved;
                    }
                    let saved = self.r;
                    let flags = (self.z, self.c, self.n, self.v);
                    self.r[0] = self.object;
                    self.run(self.callback);
                    self.r = saved;
                    (self.z, self.c, self.n, self.v) = flags;
                }
                assert!(self.signaled, "timer callback failed to terminate");
            }
            0x4f52fc | 0x4f5366 => assert_eq!(self.get(Reg::Byte(8)), 9),
            0x54c4c4 => {
                assert_eq!(self.get(Reg::Byte(8)), 4);
                self.reports += 1;
            }
            0x538f56 => self.r[0] = 0x7000,
            0x538f7e => self.set(Reg::Byte(8), 3),
            _ => return false,
        }
        // Scratch registers and CCR are not part of the target service ABI.
        self.r[1] = 0xaca55a57;
        self.r[2] = 0x13579bdf;
        self.z = false;
        self.c = true;
        self.n = true;
        self.v = true;
        true
    }
    fn run(&mut self, entry: u32) {
        self.push(0);
        let mut pc = entry;
        for _ in 0..1000000 {
            if pc == self.stop_at {
                return;
            }
            if self.service(pc) {
                pc = self.pop();
                if pc == 0 {
                    return;
                }
                continue;
            }
            let at = pc;
            let d = decode_insn(
                &self.image[(pc - 0x410000) as usize..],
                Target::H8S2000,
                Mode::Advanced,
            )
            .unwrap();
            let i = d.insn;
            let [a, b, _] = i.operands;
            pc += d.len as u32;
            let w = match i.size {
                Some(Size::Byte) => 1,
                Some(Size::Word) => 2,
                Some(Size::Long) => 4,
                None => 0,
            };
            match i.mnemonic {
                "NOP" => {}
                "JSR" | "JMP" => {
                    let to = match a {
                        O::Address(Ea::Absolute { value, .. }) => value,
                        O::Address(Ea::Indirect(r)) => self.get(r),
                        _ => panic!(),
                    };
                    if i.mnemonic == "JSR" {
                        self.push(pc);
                    }
                    pc = to;
                }
                "BSR" => {
                    let O::Address(Ea::PcRelative { value, .. }) = a else {
                        panic!()
                    };
                    self.push(pc);
                    pc = pc.wrapping_add_signed(value);
                }
                "RTS" => {
                    pc = self.pop();
                    if pc == 0 {
                        return;
                    }
                }
                "STM" => {
                    let O::Registers { first, last } = a else {
                        panic!()
                    };
                    for r in (first..=last).rev() {
                        self.push(self.r[r as usize]);
                    }
                }
                "LDM" => {
                    let O::Registers { first, last } = b else {
                        panic!()
                    };
                    for r in first..=last {
                        self.r[r as usize] = self.pop();
                    }
                }
                "MOV" => {
                    let val = self.value(a, w);
                    match b {
                        O::Register(r) => self.set(r, val),
                        O::Address(e) => {
                            let dest = self.addr(e, w);
                            self.store(dest, w, val)
                        }
                        _ => panic!(),
                    };
                    self.flags(val, w);
                }
                "ADD" | "SUB" | "CMP" | "AND" | "OR" | "XOR" | "ADDS" | "SUBS" | "INC" | "DEC" => {
                    let (a, r) = if let O::Register(r) = b {
                        (self.value(a, w), r)
                    } else if let O::Register(r) = a {
                        (1, r)
                    } else {
                        panic!()
                    };
                    let old = self.get(r);
                    let mask = Self::coord(r).2;
                    let width = match r {
                        Reg::Byte(_) => 1,
                        Reg::Word(_) => 2,
                        _ => 4,
                    };
                    let v = match i.mnemonic {
                        "ADD" | "ADDS" | "INC" => old.wrapping_add(a),
                        "SUB" | "SUBS" | "CMP" | "DEC" => old.wrapping_sub(a),
                        "AND" => old & a,
                        "OR" => old | a,
                        "XOR" => old ^ a,
                        _ => unreachable!(),
                    };
                    if i.mnemonic != "CMP" {
                        self.set(r, v);
                    }
                    if !matches!(i.mnemonic, "ADDS" | "SUBS") {
                        self.flags(v, width);
                        if matches!(i.mnemonic, "SUB" | "CMP") {
                            self.c = old < a;
                            self.v = ((old ^ a) & (old ^ v) & (1 << (width * 8 - 1))) != 0;
                        } else if i.mnemonic == "ADD" {
                            self.c = u64::from(old) + u64::from(a) > u64::from(mask);
                        }
                    }
                }
                "SHLL" | "SHLR" | "SHAR" => {
                    let (count, r) = if let O::Register(r) = b {
                        (self.value(a, w), r)
                    } else if let O::Register(r) = a {
                        (1, r)
                    } else {
                        panic!()
                    };
                    let old = self.get(r);
                    let v = if i.mnemonic == "SHLL" {
                        old << count
                    } else if i.mnemonic == "SHAR" {
                        (if w == 2 {
                            old as i16 as i32
                        } else {
                            old as i32
                        } >> count) as u32
                    } else {
                        old >> count
                    };
                    self.set(r, v);
                    self.flags(v, w);
                }
                "EXTU" | "EXTS" => {
                    let O::Register(r) = a else { panic!() };
                    let old = self.get(r);
                    let v = match (i.mnemonic, w) {
                        ("EXTU", 4) => old & 65535,
                        ("EXTU", 2) => old & 255,
                        ("EXTS", 4) => old as i16 as i32 as u32,
                        ("EXTS", 2) => old as i8 as i32 as u32,
                        _ => panic!(),
                    };
                    self.set(r, v);
                    self.flags(v, w);
                }
                "NEG" => {
                    let O::Register(r) = a else { panic!() };
                    let v = 0u32.wrapping_sub(self.get(r));
                    self.set(r, v);
                    self.flags(v, w);
                }
                "BSET" | "BCLR" => {
                    let bit = self.value(a, 1);
                    let (old, address) = match b {
                        O::Register(r) => (self.get(r), None),
                        O::Address(e) => {
                            let x = self.addr(e, 1);
                            (self.load(x, 1), Some(x))
                        }
                        _ => panic!(),
                    };
                    let val = if i.mnemonic == "BSET" {
                        old | (1 << bit)
                    } else {
                        old & !(1 << bit)
                    };
                    if let Some(x) = address {
                        self.store(x, 1, val)
                    } else if let O::Register(r) = b {
                        self.set(r, val)
                    }
                }
                "BTST" => {
                    let bit = self.value(a, 1);
                    let v = self.value(b, 1);
                    self.z = v & (1 << bit) == 0;
                }
                "DIVXS" => {
                    let divisor = self.value(a, w) as i16 as i32;
                    let O::Register(r) = b else { panic!() };
                    let numerator = self.get(r) as i32;
                    let q = numerator / divisor;
                    let rem = numerator % divisor;
                    self.set(r, ((rem as u32 & 65535) << 16) | (q as u32 & 65535));
                }
                "DIVXU" => {
                    let divisor = self.value(a, w);
                    let O::Register(r) = b else { panic!() };
                    let numerator = self.get(r);
                    assert_ne!(divisor, 0);
                    let q = numerator / divisor;
                    let rem = numerator % divisor;
                    assert!(q <= 65535);
                    self.set(r, (rem << 16) | q);
                }
                "BRA" | "BEQ" | "BNE" | "BCS" | "BCC" | "BLS" | "BHI" | "BGE" | "BLT" | "BGT"
                | "BLE" => {
                    let take = match i.mnemonic {
                        "BRA" => true,
                        "BEQ" => self.z,
                        "BNE" => !self.z,
                        "BCS" => self.c,
                        "BCC" => !self.c,
                        "BLS" => self.c || self.z,
                        "BHI" => !self.c && !self.z,
                        "BGE" => self.n == self.v,
                        "BLT" => self.n != self.v,
                        "BGT" => !self.z && self.n == self.v,
                        "BLE" => self.z || self.n != self.v,
                        _ => unreachable!(),
                    };
                    if take {
                        let O::Address(Ea::PcRelative { value, .. }) = a else {
                            panic!()
                        };
                        pc = pc.wrapping_add_signed(value);
                    }
                }
                _ => panic!("{at:x} {i:?}"),
            }
        }
        panic!("instruction budget")
    }
}
#[test]
fn native_profile_controller_and_irq_preserve_stack_and_terminate() {
    let mut t = fixture("target");
    let s = fixture("source");
    let k = fixture("kernel");
    let p = plan(&t, &s, &k).unwrap();
    for (r, b) in &p.writes {
        t[r.clone()].copy_from_slice(b);
    }
    for index in [0, 12, 13, 40, 81] {
        for row in [0, 1, 8, 63] {
            for direction in [0, 1] {
                for count in [0, 1, 16, 127, 1000, 4096, 65534, 65535] {
                    for abort in [None, Some(3)] {
                        let saved = [
                            0x12340000, 0, 0x23450000, 0x34560000, 0x45670000, 0x56780000,
                            0x67890000, 0x9000,
                        ];
                        let mut vm = Vm {
                            image: &t,
                            r: saved,
                            m: BTreeMap::new(),
                            z: false,
                            c: false,
                            n: false,
                            v: false,
                            object: 0,
                            signaled: false,
                            timer: false,
                            row,
                            total: 0,
                            steps: 0,
                            abort_after: abort,
                            callback: p.callback,
                            reports: 0,
                            status: Vec::new(),
                            media: false,
                            sensor: 0,
                            trace: Vec::new(),
                            stop_at: 0,
                        };
                        for a in 0x8800..0x9000 {
                            vm.store(a, 1, 0xa5);
                        }
                        vm.r[1] = (count << 16) | (direction << 8);
                        vm.store(0x3265, 1, index);
                        vm.run(0x5398a6);
                        assert_eq!(
                            &vm.r[3..],
                            &saved[3..],
                            "index{index} dir{direction} count{count} abort{abort:?}"
                        );
                        assert_eq!(vm.object, 0);
                        assert!(!vm.timer);
                        assert_eq!(vm.load(0xa05ddc, 1), 0);
                        if count == 0 || count == 65535 {
                            assert_eq!(vm.total, 0);
                        } else if abort.is_none() {
                            assert_eq!(
                                vm.total,
                                if direction == 0 {
                                    -(count as i32 + (count as i32 & 1) + i32::from(row & 1))
                                } else {
                                    count as i32 + (count as i32 & 1) + i32::from(row & 1)
                                },
                                "index{index} count{count}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn native_timer_teardown_clears_irq_and_stack_callback_before_free() {
    let t = fixture("target");
    for (channel, pointer, run, pending, enable, bit) in [
        (0, 0x3362, 0xff403201, 0xfffdff32, 0xfffdff2a, 1),
        (1, 0x336a, 0xff403401, 0xfffdff33, 0xfffdff2b, 7),
        (2, 0x3372, 0xff403501, 0xfffdff33, 0xfffdff2b, 6),
    ] {
        let mut vm = Vm {
            image: &t,
            r: [0x12340000; 8],
            m: BTreeMap::new(),
            z: false,
            c: false,
            n: false,
            v: false,
            object: 0,
            signaled: false,
            timer: false,
            row: 8,
            total: 0,
            steps: 0,
            abort_after: None,
            callback: 0,
            reports: 0,
            status: Vec::new(),
            media: false,
            sensor: 0,
            trace: Vec::new(),
            stop_at: 0,
        };
        vm.r[7] = 0x9000;
        vm.r[0] = channel;
        vm.store(pointer, 4, 0x8fc0);
        for a in [run, pending, enable, 0x337a] {
            vm.store(a, 1, 255);
        }
        vm.run(0x54bf4e);
        assert_eq!(vm.load(pointer, 4), 0);
        assert_eq!(vm.load(run, 1), 254);
        assert_eq!(vm.load(pending, 1), 255 & !(1 << bit));
        assert_eq!(vm.load(enable, 1), 255 & !(1 << bit));
        assert_eq!(vm.load(0x337a, 1), 255 & !(1 << channel));
        assert_eq!(vm.r[7], 0x9000);
        assert_eq!(vm.r[3], 0x12340000);
    }
}
#[test]
fn normalized_zero_counts_retain_native_caller_status_completion() {
    let mut t = fixture("target");
    let s = fixture("source");
    let k = fixture("kernel");
    let p = plan(&t, &s, &k).unwrap();
    for (r, b) in &p.writes {
        t[r.clone()].copy_from_slice(b);
    }
    for count in [0, 65535] {
        let saved = [
            0x5100, 0, 0x23450000, 0x34560000, 0x45670000, 0x56780000, 0x67890000, 0x9000,
        ];
        let mut vm = Vm {
            image: &t,
            r: saved,
            m: BTreeMap::new(),
            z: false,
            c: false,
            n: false,
            v: false,
            object: 0,
            signaled: false,
            timer: false,
            row: 1,
            total: 0,
            steps: 0,
            abort_after: None,
            callback: p.callback,
            reports: 0,
            status: Vec::new(),
            media: false,
            sensor: 0,
            trace: Vec::new(),
            stop_at: 0,
        };
        for a in 0x8800..0x9000 {
            vm.store(a, 1, 0xa5);
        }
        vm.store(0xa05ddc, 1, 0x7a);
        vm.r[1] = (count << 16) | 0x100;
        vm.run(0x53956c);
        assert_eq!(
            vm.status,
            if count == 0 { vec![] } else { vec![0x10a, 0xa] }
        );
        assert_eq!(vm.load(0xa05ddc, 1), 0x7a);
        assert_eq!(&vm.r[3..], &saved[3..]);
        assert_eq!(vm.total, 0);
        assert_eq!(vm.steps, 0);
        assert_eq!(vm.object, 0);
        assert!(!vm.timer);
        assert!(!vm.signaled);
        assert_eq!(vm.reports, 0);
    }
}
fn shared_plan(t: &[u8], s: &[u8], k: &[u8]) -> bridge::Plan {
    let (c, d) = profile::shared_lengths();
    let placement = profile::SharedPlacements {
        code: std::array::from_fn(|i| 0x1b0000 + i * 0x800..0x1b0000 + i * 0x800 + c[i]),
        data: std::array::from_fn(|i| 0x1c0000 + i * 0x800..0x1c0000 + i * 0x800 + d[i]),
    };
    let p = profile::shared_plan(
        t,
        s,
        k,
        placement,
        bridge::private_ram(),
        bridge::services(),
    )
    .expect("shared profile");
    assert_eq!(p.replaced_by_outer, 0x129b1a..0x129b1e);
    bridge::plan_with_profile(t, s, k, p.profile).expect("shared outer")
}
#[allow(clippy::too_many_arguments)]
fn legacy_run(
    image: &[u8],
    entry: u32,
    mode: u32,
    count: u32,
    row: u8,
    media: bool,
    sensor: u8,
    abort: Option<usize>,
) -> (Vec<(u32, u32)>, i32) {
    let saved = [
        0x5100, 0, 0x23450000, 0x34560000, 0x45670000, 0x56780000, 0x67890000, 0x9000,
    ];
    let mut vm = Vm {
        image,
        r: saved,
        m: BTreeMap::new(),
        z: false,
        c: false,
        n: false,
        v: false,
        object: 0,
        signaled: false,
        timer: false,
        row,
        total: 0,
        steps: 0,
        abort_after: abort,
        callback: 0x5392d2,
        reports: 0,
        status: Vec::new(),
        media,
        sensor,
        trace: Vec::new(),
        stop_at: 0,
    };
    for a in 0x8800..0x9000 {
        vm.store(a, 1, 0xa5);
    }
    vm.store(0x5100, 4, 0x5bcc34);
    vm.store(0x3265, 1, 42);
    vm.store(0x3266, 1, 39);
    vm.store(0x3267, 1, 19);
    vm.store(0x3269, 1, 20);
    vm.store(0x3256, 2, 3000);
    vm.r[1] = (count << 16) | 0x100 | mode;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vm.run(entry)));
    assert!(result.is_ok(),"entry{entry:x} mode{mode} count{count} row{row} media{media} sensor{sensor} abort{abort:?} profile={:?}",(0..42).map(|i|vm.load(0x5100+i,1)).collect::<Vec<_>>());
    assert_eq!(&vm.r[3..], &saved[3..]);
    assert_eq!(vm.object, 0);
    assert!(!vm.timer);
    (vm.trace, vm.total)
}
#[test]
fn shared_profile_preserves_native_special_modes_and_executes_source_mode_zero() {
    let t = fixture("target");
    let s = fixture("source");
    let k = fixture("kernel");
    let p = shared_plan(&t, &s, &k);
    let mut changed = t.clone();
    for (r, b) in &p.writes {
        changed[r.clone()].copy_from_slice(b);
    }
    let guard = u32::from_be_bytes([0, changed[0x1289e3], changed[0x1289e4], changed[0x1289e5]]);
    for mode in [0, 1, 2] {
        for count in [0, 1, 16, 127, 500, 65535] {
            for row in [0, 1, 8, 63] {
                for media in [false, true] {
                    for sensor in [0, 1] {
                        for abort in [None, Some(3)] {
                            let got =
                                legacy_run(&changed, guard, mode, count, row, media, sensor, abort);
                            if mode != 0 {
                                let original = legacy_run(
                                    &t, 0x539406, mode, count, row, media, sensor, abort,
                                );
                                assert_eq!(got,original,"mode{mode} count{count} row{row} media{media} sensor{sensor} abort{abort:?}");
                            } else if count == 0 || count == 65535 {
                                assert_eq!(got.1, 0);
                            } else if abort.is_none() {
                                assert_eq!(
                                    got.1,
                                    count as i32 + (count as i32 & 1) + i32::from(row & 1)
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn emitted_trajectory_is_rediscovered_without_source_or_dsp_loader() {
    let mut t = fixture("target");
    let s = fixture("source");
    let k = fixture("kernel");
    let p = shared_plan(&t, &s, &k);
    for (r, b) in &p.writes {
        t[r.clone()].copy_from_slice(b);
    }
    t[0x128e20..0x128ed8].fill(255);
    let observed = bridge::observe_detailed(&t, &k).expect("positive emitted trajectory");
    assert!(observed.verify(&t, &k));
    for at in [0x1298a6, 0x129d6a, 0x13c040, 0x1b0000, 0x1c0000] {
        let mut bad = t.clone();
        bad[at] ^= 1;
        assert!(bridge::observe(&bad, &k).is_none(), "mutated{at:x}");
    }
    for a in [0x5c0000u32, 0x5398a6, 0x539406, 0xa05dde] {
        let mut bad = t.clone();
        bad[0x801..0x805].copy_from_slice(&a.to_be_bytes());
        assert!(bridge::observe(&bad, &k).is_none(), "unbound caller{a:x}");
    }
}
#[test]
#[ignore = "requires actual integrated reverse image produced by composer"]
fn actual_composed_image_has_positive_effective_software_observation() {
    let n =
        std::fs::read("/Users/matthew/Developer/tmp/release-0180/reverse-composed.bin").unwrap();
    let k = fixture("kernel");
    assert!(
        bridge::observe_detailed(&n, &k).is_ok(),
        "{:?}",
        bridge::observe_detailed(&n, &k)
    );
}
#[test]
fn native_movers_share_signed_delta_position_and_phase_units() {
    for (role, entry, stop, position) in [
        ("target", 0x538a88, 0x538aa8, 0x3208),
        ("source", 0x5d6bce, 0x5d6bee, 0x322a),
    ] {
        let image = fixture(role);
        for row in [0, 63] {
            for old in [0, 1, 0x7fff, 0xffff] {
                for delta in 0..=255 {
                    let mut vm = Vm {
                        image: &image,
                        r: [0; 8],
                        m: BTreeMap::new(),
                        z: false,
                        c: false,
                        n: false,
                        v: false,
                        object: 0,
                        signaled: false,
                        timer: false,
                        row,
                        total: 0,
                        steps: 0,
                        abort_after: None,
                        callback: 0,
                        reports: 0,
                        status: Vec::new(),
                        media: false,
                        sensor: 0,
                        trace: Vec::new(),
                        stop_at: stop,
                    };
                    vm.r[0] = 0x5100;
                    vm.r[1] = delta;
                    vm.r[7] = 0x9000;
                    vm.store(0x5104, 1, u32::from(row));
                    vm.store(position, 2, old);
                    vm.run(entry);
                    let signed = delta as u8 as i8 as i32;
                    assert_eq!(vm.load(position, 2), (old as i32 + signed) as u16 as u32);
                    assert_eq!(
                        vm.get(Reg::Byte(4)) & 63,
                        (i32::from(row) + signed).rem_euclid(64) as u32
                    );
                    assert_eq!(vm.get(Reg::Byte(12)), delta);
                }
            }
        }
    }
}
