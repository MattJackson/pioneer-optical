#![cfg(feature = "envelope")]
use pioneer_optical::filters::phase::bundle::{
    self,
    waveforms::loader::{self, computed},
};
fn image(hash: &str) -> Vec<u8> {
    let all: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-native-spans.json")).unwrap();
    let f = all
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["original_sha256"] == hash)
        .unwrap();
    let mut out = vec![255; f["size"].as_u64().unwrap() as usize];
    for span in f["spans"].as_array().unwrap() {
        let at = span[0].as_u64().unwrap() as usize;
        let s = span[1].as_str().unwrap();
        let bytes: Vec<_> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        out[at..at + bytes.len()].copy_from_slice(&bytes);
    }
    let basis: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-computed-basis.json")).unwrap();
    if basis["original_sha256"] == hash {
        for span in basis["spans"].as_array().unwrap() {
            let at = span[0].as_u64().unwrap() as usize;
            let h = span[1].as_str().unwrap();
            for i in 0..h.len() / 2 {
                out[at + i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
            }
        }
    }
    out
}
const COMPUTED: &str = "84b76c71728dd9c27d27c3cb974f062b55c59a7a26145c858dc45cc1a79db66a";
const DOWN: &str = "87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1";
#[test]
fn native_computed_direction_retains_scaling_graph() {
    let original = image(COMPUTED);
    let donor = image(DOWN);
    let kernel = vec![255; 65536];
    let before = computed::observe(&original).unwrap();
    let changed = computed::specialize_direction(&original, &donor, &kernel).unwrap();
    let mut expected = before.clone();
    expected.loader.loader = bundle::Loader::DescendingNegated17;
    assert_eq!(computed::observe(&changed).unwrap(), expected);
    assert_eq!(
        computed::specialize_direction(&changed, &donor, &kernel).unwrap(),
        changed
    );
    let restored = computed::specialize_direction(&changed, &original, &kernel).unwrap();
    assert_eq!(computed::observe(&restored).unwrap(), before);
    assert_eq!(
        computed::specialize_direction(&restored, &donor, &kernel).unwrap(),
        changed
    );
    for (i, (a, b)) in original.iter().zip(&changed).enumerate() {
        if a != b {
            assert!(before.loader.program.contains(&i));
        }
    }
    let start = before.loader.program.start;
    let mut broken = changed.clone();
    broken[start + 35] ^= 1;
    assert!(loader::observe(&broken).is_err());
    for kernel in [&kernel[..0], &kernel[..65534]] {
        assert!(computed::specialize_direction(&original, &donor, kernel).is_err());
    }
    let mut hostile = kernel.clone();
    hostile[0..4].copy_from_slice(&[
        0x5e,
        ((0x410000 + start + 2) >> 16) as u8,
        ((start + 2) >> 8) as u8,
        (start + 2) as u8,
    ]);
    assert!(computed::specialize_direction(&original, &donor, &hostile).is_err());
}

use h8_asm::{
    isa::{decode_insn, Ea, Insn, Operand as O, Reg},
    Mode, Target,
};
fn instructions(bytes: &[u8]) -> Vec<(usize, Insn, usize)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let d = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced).unwrap();
        out.push((at, d.insn, d.len));
        at += d.len;
    }
    out
}
fn coordinates(r: Reg) -> (usize, u32, u32) {
    match r {
        Reg::Byte(n) => ((n % 8) as usize, if n < 8 { 8 } else { 0 }, 255),
        Reg::Word(n) => ((n % 8) as usize, if n < 8 { 0 } else { 16 }, 65535),
        Reg::Long(n) => (n as usize, 0, u32::MAX),
        _ => panic!("{r:?}"),
    }
}
fn get(r: &[u32; 8], o: O) -> u32 {
    match o {
        O::Immediate { value, .. } => value,
        O::Register(reg) => {
            let (n, s, m) = coordinates(reg);
            r[n] >> s & m
        }
        _ => panic!("{o:?}"),
    }
}
fn set(r: &mut [u32; 8], o: O, value: u32) {
    let O::Register(reg) = o else { panic!("{o:?}") };
    let (n, s, m) = coordinates(reg);
    r[n] = (r[n] & !(m << s)) | ((value & m) << s);
}
// Execute only transformed arithmetic regions. Calls, stack operations, clipping
// and all other instructions are asserted byte-identical below.
fn run(code: &[(usize, Insn, usize)], mut r: [u32; 8]) -> [u32; 8] {
    let mut pc = 0;
    let mut carry = false;
    for _ in 0..64 {
        let Some((_, i, n)) = code.iter().find(|(at, _, _)| *at == pc) else {
            return r;
        };
        pc += n;
        let [a, b, _] = i.operands;
        let av = if matches!(a, O::Register(_) | O::Immediate { .. }) {
            get(&r, a)
        } else {
            0
        };
        match i.mnemonic {
            "MOV" => set(&mut r, b, av),
            "ADD" => {
                let v = get(&r, b).wrapping_add(av);
                set(&mut r, b, v)
            }
            "SUB" => {
                let v = get(&r, b).wrapping_sub(av);
                set(&mut r, b, v)
            }
            "SHLL" => {
                let v = get(&r, b) << av;
                set(&mut r, b, v)
            }
            "EXTS" => set(&mut r, a, (av as i16 as i32) as u32),
            "NEG" => set(&mut r, a, av.wrapping_neg()),
            "CMP" => carry = get(&r, b) < av,
            "BCC" | "BHS" | "BRA" => {
                if i.mnemonic == "BRA" || !carry {
                    let O::Address(Ea::PcRelative { value, .. }) = a else {
                        panic!()
                    };
                    pc = pc.checked_add_signed(value as isize).unwrap();
                }
            }
            "NOP" => {}
            _ => panic!("{i:?}"),
        }
    }
    panic!("branch loop")
}
#[test]
fn computed_fold_and_dsp_addresses_execute_native_equivalence() {
    let original = image(COMPUTED);
    let donor = image(DOWN);
    let kernel = vec![255; 65536];
    let changed = computed::specialize_direction(&original, &donor, &kernel).unwrap();
    let before = loader::logical_program(&original).unwrap();
    let after = loader::logical_program(&changed).unwrap();
    assert_eq!(&before[..32], &after[..32]);
    assert_eq!(&before[44..252], &after[38..246]);
    assert_eq!(&before[266..280], &after[262..276]);
    assert_eq!(&before[284..398], &after[280..394]);
    assert_eq!(&before[398..], &after[398..]);
    let original_fold = instructions(&before[32..48]);
    let mut folded = instructions(&after[32..42]);
    // Exhaust every calibration word with wrap, sign and half-word boundaries.
    for a in 0..=u16::MAX {
        for b in [0, 1, 32767, 32768, 65535, a] {
            let value = b.wrapping_sub(a.wrapping_mul(2));
            folded[0].1.operands[0] = O::Immediate {
                value: u32::from(value),
                bits: 16,
            };
            let r = [
                0xcafe0000 | u32::from(b),
                0xdeadbeef,
                0xabcd0000 | u32::from(b),
                u32::from(a) << 16 | 0x0011,
                0xa5a55a5a,
                0x12345678,
                0x87654321,
                0x8000,
            ];
            assert_eq!(run(&original_fold, r), run(&folded, r));
        }
    }
    let donor_code = loader::logical_program(&donor).unwrap();
    let donor_start = donor_code
        .windows(8)
        .position(|b| b == [0xac, 9, 0x44, 8, 0x79, 0, 6, 0x13])
        .unwrap();
    for index in 0..18u32 {
        let r = [
            0xdeadbeef,
            0xcafebabe,
            0x12345678,
            index << 16 | 0xa55a,
            index << 16 | index,
            0x00123456,
            0x88776655,
            0x8000,
        ];
        let actual = run(&instructions(&after[244..262]), r);
        let expected = run(&instructions(&donor_code[donor_start..donor_start + 22]), r);
        assert_eq!(
            actual[0] as u16,
            expected[0] as u16,
            "index={index} actual={:?} expected={:?} code={:?}",
            actual,
            expected,
            instructions(&after[244..262])
        );
        assert_eq!(&actual[1..], &r[1..]);
        assert_eq!(actual[0] >> 16, r[0] >> 16);
    }
}

fn checksum(bytes: &mut [u8]) {
    bytes[16..20].fill(0);
    let sum = bytes.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    bytes[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
}
#[test]
fn controlled_computed_direction_composes_through_phase_owner() {
    use bundle::waveforms::resources::generated;
    use pioneer_optical::{
        compatibility::Firmware,
        filters::{self, Filter},
    };
    let mut target = image(COMPUTED);
    checksum(&mut target);
    let kernel = vec![255; 65536];
    generated::observe(&target).unwrap();
    // This donor is a controlled direction mutation of one complete native
    // computed/generated graph, not a claim of an observed OEM package pair.
    let mut donor = computed::specialize_direction(&target, &image(DOWN), &kernel).unwrap();
    checksum(&mut donor);
    let installed = filters::Context::new(Firmware {
        hardware: "SAT 8600",
        normal: &donor,
        kernel: Some(&kernel),
    });
    let destination = filters::Context::new(Firmware {
        hardware: "SAT 8600",
        normal: &target,
        kernel: Some(&kernel),
    });
    let registry: &[&dyn Filter] = &[&filters::phase::FILTER];
    let plan = filters::runner::plan_with(
        &installed,
        &destination,
        filters::runner::Policy::Strict,
        registry,
    )
    .unwrap();
    let context = filters::Preparation {
        target: destination.firmware,
        normal: None,
        kernel: None,
    };
    let changed = plan
        .prepare_with(&context, registry)
        .unwrap()
        .expect("complete computed operation");
    plan.verify_with(&context, &changed, registry).unwrap();
    assert_eq!(
        computed::observe(&changed).unwrap(),
        computed::observe(&donor).unwrap()
    );
    assert_eq!(
        generated::observe(&changed).unwrap(),
        generated::observe(&target).unwrap()
    );
    let mut broken = changed.clone();
    let binding = computed::observe(&changed).unwrap();
    broken[binding.loader.program.start + 35] ^= 1;
    assert!(plan.verify_with(&context, &broken, registry).is_err());
}
