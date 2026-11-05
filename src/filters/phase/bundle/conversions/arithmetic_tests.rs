use super::*;
use h8_asm::{
    isa::{decode_insn, Ea, Insn, Operand as O, Reg},
    Mode, Target,
};

fn instructions(bytes: &[u8]) -> Vec<Insn> {
    let mut code = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let d = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced).unwrap();
        code.push(d.insn);
        at += d.len;
    }
    code
}
#[derive(Debug)]
struct Cpu {
    r: [u32; 8],
    stack: Vec<(u32, u32)>,
    calls: Vec<[u32; 8]>,
}
impl Cpu {
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
    }
    fn value(&self, o: O) -> u32 {
        match o {
            O::Register(r) => self.get(r),
            O::Immediate { value, .. } => value,
            _ => panic!("{o:?}"),
        }
    }
    fn run(code: &[Insn], kind: Element, p127: u16, p128: u16, arg: u16, phase: u16) -> Self {
        let mut c = Self {
            r: [
                0x7654_3210,
                0xcafe_0000 | u32::from(arg),
                0xa4a5_5a5a,
                0x1234_abcd,
                0x2233_4455,
                0x5566_7788,
                0x9900_aabb,
                0x8000,
            ],
            stack: Vec::new(),
            calls: Vec::new(),
        };
        for i in code {
            let [a, b, _] = i.operands;
            match (i.mnemonic, a, b) {
                ("MOV", O::Register(r), O::Address(Ea::PreDecrement(Reg::Long(7)))) => {
                    let w = if matches!(r, Reg::Long(_)) { 4 } else { 2 };
                    c.stack.push((c.get(r), w));
                    c.r[7] -= w;
                }
                ("MOV", O::Address(Ea::PostIncrement(Reg::Long(7))), O::Register(r)) => {
                    let (v, w) = c.stack.pop().unwrap();
                    c.set(r, v);
                    c.r[7] += w;
                }
                ("MOV", a, O::Register(r)) => c.set(r, c.value(a)),
                ("ADD", a, O::Register(r)) => c.set(r, c.get(r).wrapping_add(c.value(a))),
                ("SUB" | "DEC", a, O::Register(r)) => c.set(r, c.get(r).wrapping_sub(c.value(a))),
                ("AND", a, O::Register(r)) => c.set(r, c.get(r) & c.value(a)),
                ("NEG", O::Register(r), _) => c.set(r, c.get(r).wrapping_neg()),
                ("NOT", O::Register(r), _) => c.set(r, !c.get(r)),
                ("SHLL", a, O::Register(r)) => c.set(r, c.get(r) << c.value(a)),
                ("SHLR", a, O::Register(r)) => c.set(r, c.get(r) >> c.value(a)),
                ("EXTU", O::Register(r), _) => c.set(
                    r,
                    c.get(r)
                        & if matches!(r, Reg::Long(_)) {
                            65535
                        } else {
                            255
                        },
                ),
                ("MULXU", a, O::Register(Reg::Long(r))) => {
                    c.set(Reg::Long(r), (c.r[r as usize] & 65535) * c.value(a))
                }
                ("DIVXU", a, O::Register(Reg::Long(r))) => {
                    let n = c.r[r as usize];
                    let d = c.value(a);
                    assert!(n / d <= 65535);
                    c.set(Reg::Long(r), ((n % d) << 16) | (n / d));
                }
                ("JSR", _, _) => {
                    c.calls.push(c.r);
                    let n = c.calls.len() - 1;
                    // Getter/setter mocks preserve callee-saved ER3..ER6 and vary
                    // every caller-scratch register between calls.
                    let value = match (kind, n) {
                        (Element::CalibrationBase, 0) => u32::from(p128),
                        (Element::CalibrationBase, 1) | (Element::CalibrationStep, 0) => {
                            u32::from(p127)
                        }
                        (Element::CalibrationStep, 1) => 0xa01020,
                        (Element::CalibrationOffset, 1 | 3) => u32::from(phase),
                        _ => 0x8c12_3456,
                    };
                    c.r[0] = value;
                    c.r[1] = 0xbadd_abcd;
                    c.r[2] = 0x4321_dcba;
                }
                ("RTS", _, _) => {}
                other => panic!("{other:?}"),
            }
        }
        assert!(c.stack.is_empty());
        assert_eq!(c.r[7], 0x8000);
        c
    }
}
fn forms(kind: Element, variant: u8) -> (Vec<Insn>, Vec<Insn>) {
    let bytes: Vec<_> = original_templates(kind).unwrap()[usize::from(variant)]
        .iter()
        .map(|v| v.unwrap_or(0))
        .collect();
    let compact = compact_body(&bytes, kind, variant).unwrap();
    let expected = match kind {
        Element::CalibrationBase => 52,
        Element::CalibrationOffset => 60,
        Element::CalibrationStep => 44,
        _ => unreachable!(),
    };
    assert_eq!(compact.len(), expected);
    (instructions(&bytes), instructions(&compact))
}
#[test]
fn compact_mirror_base_executes_all_parameter_words_and_overflow_edges() {
    let (oem, compact) = forms(Element::CalibrationBase, 1);
    for p in 0..=u16::MAX {
        for (other, arg) in [(0, 0), (1, 0xffff), (0xffff, p), (p, !p)] {
            let a = Cpu::run(&oem, Element::CalibrationBase, p, other, arg, 0);
            let b = Cpu::run(&compact, Element::CalibrationBase, p, other, arg, 0);
            let q = p.wrapping_shl(4) / 18;
            let expected = 64u16
                .wrapping_sub(q)
                .wrapping_sub(other.wrapping_shl(6))
                .wrapping_add(arg);
            assert_eq!(a.r[0] as u16, expected);
            assert_eq!(b.r[0], a.r[0]);
            assert_eq!(b.r[2..], a.r[2..]);
            assert_eq!(
                a.calls.iter().map(|r| r[0] as u16).collect::<Vec<_>>(),
                [0x128, 0x127]
            );
            assert_eq!(
                b.calls.iter().map(|r| r[0] as u16).collect::<Vec<_>>(),
                [0x128, 0x127]
            );
        }
    }
}
#[test]
fn compact_mirror_offset_preserves_full_helper_register_abi_for_every_phase_word() {
    for variant in [1, 2] {
        let (oem, compact) = forms(Element::CalibrationOffset, variant);
        for phase in 0..=u16::MAX {
            let a = Cpu::run(&oem, Element::CalibrationOffset, 0, 0, 0, phase);
            let b = Cpu::run(&compact, Element::CalibrationOffset, 0, 0, 0, phase);
            assert_eq!(a.calls, b.calls, "variant {variant}, phase {phase}");
            assert_eq!(a.r, b.r);
            assert_eq!(a.calls[2][0] as u16, 0x127);
            assert_eq!(
                (a.calls[2][0] >> 16) as u16,
                (((if variant == 1 { 48u16 } else { 80u16 }).wrapping_sub(phase & 255) & 63) * 18)
                    >> 4
            );
            assert_eq!(a.calls[4][0] as u16, 0x128);
            assert_eq!((a.calls[4][0] >> 16) as u16, (phase >> 6).wrapping_neg());
        }
    }
}
#[test]
fn compact_mirror_step_preserves_pointer_phase_and_saved_registers() {
    let (oem, compact) = forms(Element::CalibrationStep, 1);
    for p in 0..=u16::MAX {
        let a = Cpu::run(&oem, Element::CalibrationStep, p, 0, 0, 0);
        let b = Cpu::run(&compact, Element::CalibrationStep, p, 0, 0, 0);
        assert_eq!(a.calls[2][0], 0xa01020);
        assert_eq!(b.calls[2][0], a.calls[2][0]);
        assert_eq!(
            a.calls[2][1] & 255,
            (48u16.wrapping_sub(p.wrapping_shl(4) / 18) & 63) as u32
        );
        assert_eq!(b.calls[2][1] & 255, a.calls[2][1] & 255);
        assert_eq!(b.r, a.r);
    }
}

fn native_fixtures() -> Vec<(Vec<u8>, Vec<u8>)> {
    let data: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/phase-compact-arithmetic.json"
    )))
    .unwrap();
    data.as_array()
        .unwrap()
        .iter()
        .map(|fixture| {
            let mut normal = alloc::vec![255;fixture["normal_len"].as_u64().unwrap() as usize];
            let mut kernel = alloc::vec![255;0x10000];
            for span in fixture["spans"].as_array().unwrap() {
                let address = span[0].as_u64().unwrap() as usize;
                let text = span[1].as_str().unwrap();
                let bytes: Vec<_> = (0..text.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                    .collect();
                let (image, base) = if address < BASE_ADDRESS {
                    (&mut kernel, 0x400000)
                } else {
                    (&mut normal, BASE_ADDRESS)
                };
                image[address - base..address - base + bytes.len()].copy_from_slice(&bytes);
            }
            (normal, kernel)
        })
        .collect()
}

#[test]
fn native_caller_proofs_allow_compact_arithmetic_and_reject_changed_consumers() {
    let fixtures = native_fixtures();
    let donor = &fixtures
        .iter()
        .find(|(n, _)| programs(n).unwrap()[0].variant == 1)
        .unwrap()
        .0;
    for (target, kernel) in fixtures
        .iter()
        .filter(|(n, _)| programs(n).unwrap()[0].variant == 0)
    {
        let changed = rewrite_specialized_with_kernel(
            target,
            donor,
            [None, Some(0x400..0x40a), None],
            Some(kernel),
        )
        .unwrap();
        let bound = programs(&changed).unwrap();
        assert_eq!(
            bound.iter().map(|p| p.variant).collect::<Vec<_>>(),
            [1, 1, 1]
        );
        assert_eq!(bound[0].body.bytes.len(), 52);
        assert_eq!(bound[1].body.bytes.len(), 60);
        assert_eq!(bound[2].body.bytes.len(), 44);
        verify_specialized_callers(&changed, Some(kernel)).unwrap();
        assert!(verify_specialized_callers(&changed, None).is_err());
        assert_eq!(
            rewrite_specialized_with_kernel(&changed, donor, [None, None, None], Some(kernel))
                .unwrap(),
            changed
        );
        let regions = crate::image::regions(&changed).unwrap();
        let call = (BASE_ADDRESS + bound[0].at).to_be_bytes();
        let pattern = [
            Some(0x5e),
            Some(call[call.len() - 3]),
            Some(call[call.len() - 2]),
            Some(call[call.len() - 1]),
        ];
        let callers = sites(&changed, &regions.stored, &pattern);
        assert_eq!(callers.len(), 3);
        let read_scratch = h8_asm::isa::encode_insn(
            Insn::new(
                "MOV",
                Some(h8_asm::isa::Size::Long),
                [
                    O::Register(Reg::Long(1)),
                    O::Register(Reg::Long(0)),
                    O::None,
                ],
            ),
            Target::H8S2000,
            Mode::Advanced,
        )
        .unwrap();
        let mut broken = changed.clone();
        broken[callers[0] + 4..callers[0] + 6].copy_from_slice(&read_scratch);
        assert!(verify_specialized_callers(&broken, Some(kernel)).is_err());
        let mut broken_kernel = kernel.clone();
        let entry = broken_kernel.iter().position(|b| *b != 255).unwrap();
        broken_kernel[entry..entry + 2].copy_from_slice(&read_scratch);
        assert!(verify_specialized_callers(&changed, Some(&broken_kernel)).is_err());
        // The compact OFFSET can differ in CCR.H until the native NEG.W.
        // Turning the setter's saved CCR into a parameter value must fail.
        let fields = calls(&bound[1].template).unwrap();
        let field = fields[2];
        let setter = u32::from_be_bytes([
            0,
            bound[1].body.bytes[field],
            bound[1].body.bytes[field + 1],
            bound[1].body.bytes[field + 2],
        ]) as usize
            - BASE_ADDRESS;
        let mut at = setter;
        let (saved, next) = loop {
            let d = decode_insn(&changed[at..], Target::H8S2000, Mode::Advanced).unwrap();
            at += d.len;
            if d.insn.mnemonic == "STC" {
                break (d.insn.operands[1], at);
            }
        };
        let leak = h8_asm::isa::encode_insn(
            Insn::new(
                "MOV",
                Some(h8_asm::isa::Size::Byte),
                [saved, O::Register(Reg::Byte(8)), O::None],
            ),
            Target::H8S2000,
            Mode::Advanced,
        )
        .unwrap();
        assert_eq!(leak.len(), 2);
        let mut bad_flags = changed.clone();
        bad_flags[next..next + 2].copy_from_slice(&leak);
        assert!(verify_specialized_callers(&bad_flags, Some(kernel)).is_err());
        // A new direct tail-entry cannot borrow the ABI proof of the three calls.
        let mut tail_entry = changed.clone();
        tail_entry[0x600..0x604]
            .copy_from_slice(&native::encoding::jump((BASE_ADDRESS + bound[0].at) as u32).unwrap());
        assert!(verify_specialized_callers(&tail_entry, Some(kernel)).is_err());
    }
}
