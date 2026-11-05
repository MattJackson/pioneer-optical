//! Execute the complete native fixed-value getter after in-place source transfer.
#![cfg(feature = "envelope")]
use h8_asm::{
    isa::{decode_insn, Ea, Operand, Reg},
    Mode, Target,
};
use pioneer_optical::filters::phase::bundle::waveforms::resources::{
    calibration_bridge, evaluators,
};
use pioneer_optical::{filters::prerequisites, image::layout};

const PARAMETER: &str = "8037cdb3ae67e04a82aa3e9b7a0f52202e17f1e39d1f50b894158d9be0cec898";
const CONSTANT: &str = "99ba77ae1cedc967096c770b21c066d04a5163f1c5a4aa82f27584c6faced796";
fn fixture(hash: &str) -> Vec<u8> {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-native-spans.json")).unwrap();
    let f = fixtures
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["original_sha256"].as_str() == Some(hash))
        .unwrap();
    let mut normal = vec![255; f["size"].as_u64().unwrap() as usize];
    for span in f["spans"].as_array().unwrap() {
        let start = span[0].as_u64().unwrap() as usize;
        let hex = span[1].as_str().unwrap();
        for at in 0..hex.len() / 2 {
            normal[start + at] = u8::from_str_radix(&hex[at * 2..at * 2 + 2], 16).unwrap();
        }
    }
    normal
}

fn parameters_with_reader() -> Vec<u8> {
    let mut normal = fixture(PARAMETER);
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-calibration-reader.json")).unwrap();
    assert_eq!(fixture["original_sha256"], PARAMETER);
    for span in fixture["spans"].as_array().unwrap() {
        let start = span[0].as_u64().unwrap() as usize;
        let hex = span[1].as_str().unwrap();
        for at in 0..hex.len() / 2 {
            normal[start + at] = u8::from_str_radix(&hex[at * 2..at * 2 + 2], 16).unwrap();
        }
    }
    normal
}

fn coordinate(reg: Reg) -> (usize, u32, u32) {
    match reg {
        Reg::Byte(n) => ((n % 8) as usize, if n < 8 { 8 } else { 0 }, 255),
        Reg::Word(n) => ((n % 8) as usize, if n < 8 { 0 } else { 16 }, 65535),
        Reg::Long(n) => (n as usize, 0, u32::MAX),
        _ => panic!("unsupported register {reg:?}"),
    }
}
fn value(registers: &[u32; 8], operand: Operand) -> u32 {
    match operand {
        Operand::Register(reg) => {
            let (n, shift, mask) = coordinate(reg);
            registers[n] >> shift & mask
        }
        Operand::Immediate { value, .. } => value,
        _ => panic!("unexpected memory access {operand:?}"),
    }
}
fn run(bytes: &[u8], mode: u8) -> [u32; 8] {
    run_with_words(bytes, mode, 0, None)
}

fn run_with_words(
    bytes: &[u8],
    mode: u8,
    entry: u32,
    source: Option<([u32; 2], &[u16; 8])>,
) -> [u32; 8] {
    let mut registers = [0xa55a_5aa5; 8];
    registers[0] = (registers[0] & !255) | u32::from(mode);
    let mut zero = false;
    let mut calls = Vec::new();
    let mut at = 0;
    for _ in 0..32 {
        let decoded = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced).unwrap();
        let instruction = decoded.insn;
        let [a, b, _] = instruction.operands;
        at += decoded.len;
        match (instruction.mnemonic, a, b) {
            ("MOV" | "SUB", source, Operand::Register(destination)) => {
                let result = if instruction.mnemonic == "SUB" {
                    value(&registers, b).wrapping_sub(value(&registers, source))
                } else {
                    value(&registers, source)
                };
                let (n, shift, mask) = coordinate(destination);
                registers[n] = (registers[n] & !(mask << shift)) | ((result & mask) << shift);
                zero = result & mask == 0;
            }
            ("CMP", a, b) => zero = value(&registers, a) == value(&registers, b),
            ("BRA" | "BEQ" | "BNE", Operand::Address(Ea::PcRelative { value, .. }), _) => {
                if instruction.mnemonic == "BRA"
                    || (instruction.mnemonic == "BEQ" && zero)
                    || (instruction.mnemonic == "BNE" && !zero)
                {
                    at = at.checked_add_signed(value as isize).unwrap();
                }
            }
            ("JMP", Operand::Address(Ea::Absolute { value, .. }), _) => {
                at = value.checked_sub(entry).unwrap() as usize;
            }
            ("JSR", Operand::Address(Ea::Absolute { value, .. }), _) => {
                let (helpers, words) = source.expect("constant getter must not call helpers");
                calls.push(value);
                if value == helpers[0] {
                    registers[0] = 0x20d6;
                } else {
                    assert_eq!(value, helpers[1]);
                    assert_eq!(calls, helpers);
                    let index = registers[1] as u16;
                    assert_eq!(index, 0x30 + u16::from(mode));
                    // The complete native graph separately binds this logical
                    // word boundary; this interpreter executes its caller.
                    registers[0] = u32::from(words[(index - 0x30) as usize]);
                }
            }
            ("RTS", _, _) => {
                if let Some((helpers, _)) = source {
                    assert_eq!(calls, helpers);
                }
                return registers;
            }
            _ => panic!("unexpected native getter instruction {instruction:?}"),
        }
    }
    panic!("native getter did not return")
}

#[test]
fn native_constants_replace_parameter_source_without_storage_or_helper_access() {
    let target = fixture(PARAMETER);
    let donor = fixture(CONSTANT);
    let before = evaluators::observe(&target).unwrap();
    let old = evaluators::calibration(&target, &before).unwrap();
    let source = evaluators::observe(&donor).unwrap();
    let wanted = evaluators::calibration(&donor, &source).unwrap();
    assert!(matches!(old.1, evaluators::Calibration::Parameters { .. }));
    let evaluators::Calibration::Constants(constants) = wanted.1 else {
        panic!()
    };
    assert_eq!(constants, [675, 1481, -646, -1476, 675, 1476, -657, -1486]);
    let changed = calibration_bridge::transplant(&target, &donor).unwrap();
    let actual = evaluators::calibration(&changed, &before).unwrap();
    assert_eq!(actual.0.len(), 80);
    assert_eq!(actual.1, wanted.1);
    assert_eq!(evaluators::observe(&changed).unwrap(), before);
    assert_eq!(&changed[..actual.0.start], &target[..actual.0.start]);
    assert_eq!(&changed[actual.0.end..], &target[actual.0.end..]);
    for mode in 0..=255 {
        let result = run(&changed[actual.0.clone()], mode);
        assert_eq!(result, run(&donor[wanted.0.clone()], mode));
        assert_eq!(&result[1..], &[0xa55a_5aa5; 7]);
        if mode < 8 {
            assert_eq!(result[0] as i16, constants[mode as usize]);
        }
    }
    calibration_bridge::verify(&target, &donor, &changed).unwrap();
    assert_eq!(
        calibration_bridge::transplant(&changed, &donor).unwrap(),
        changed
    );
    let mut broken = changed;
    broken[actual.0.start + 74] ^= 1;
    assert!(calibration_bridge::verify(&target, &donor, &broken).is_err());
}

#[test]
fn parameter_defaults_never_become_unconditional_calibration_values() {
    let parameters = fixture(PARAMETER);
    let constants = fixture(CONSTANT);
    assert!(calibration_bridge::transplant(&constants, &parameters).is_err());
    assert_eq!(
        calibration_bridge::transplant(&parameters, &parameters).unwrap(),
        parameters
    );
    let binding = evaluators::observe(&constants).unwrap();
    let span = evaluators::calibration(&constants, &binding).unwrap().0;
    let mut broken = constants.clone();
    broken[span.start + 2] ^= 1;
    assert!(calibration_bridge::transplant(&parameters, &broken).is_err());
}

#[test]
fn reverse_bridge_requires_exact_native_words_and_the_complete_installed_reader() {
    let donor = parameters_with_reader();
    let target = fixture(CONSTANT);
    let layout::Observation::Known(reader) = layout::discover_h8_reader(&donor, None) else {
        panic!("complete native getter graph")
    };
    assert_eq!(reader.getter, 0x5ecbfa);
    assert_eq!(reader.argument_register, 1);
    let plan = calibration_bridge::plan(&target, &donor).unwrap();
    assert_eq!(plan.image, target);
    assert_eq!(plan.required_words.len(), 8);
    let binding = evaluators::observe(&donor).unwrap();
    let native = evaluators::calibration(&donor, &binding).unwrap();
    let evaluators::Calibration::Parameters {
        defaults, helpers, ..
    } = native.1
    else {
        panic!()
    };
    let words: [u16; 8] = core::array::from_fn(|i| plan.required_words[i].value);
    for mode in 0..8 {
        let execute = |words: &[u16; 8]| {
            run_with_words(
                &donor[native.0.clone()],
                mode,
                binding.calibration_getter,
                Some((helpers, words)),
            )[0] as u16
        };
        assert_eq!(execute(&words), words[mode as usize]);
        assert_eq!(execute(&[0xffff; 8]) as i16, defaults[mode as usize]);
        for raw in [0, 1, 0x7fff, 0x8000, 0xfffe] {
            assert_eq!(execute(&[raw; 8]), raw);
        }
    }
    for (mode, word) in plan.required_words.iter().enumerate() {
        assert_eq!(word.parameter, 0x30 + mode as u16);
        assert_eq!(
            word.value as i16,
            [675, 1481, -646, -1476, 675, 1476, -657, -1486][mode]
        );
    }
    assert_eq!(
        calibration_bridge::verify_guarded(&target, &donor, &plan.image).unwrap(),
        plan.required_words
    );
    assert!(calibration_bridge::transplant(&target, &donor).is_err());
    assert!(calibration_bridge::verify(&target, &donor, &plan.image).is_err());
    let owned: Vec<_> = plan
        .required_words
        .iter()
        .map(|word| prerequisites::OwnedWord {
            filter: "phase",
            word: *word,
        })
        .collect();
    let mut reads = Vec::new();
    prerequisites::check(&owned, |parameter| {
        reads.push(parameter);
        Ok::<_, ()>(plan.required_words[(parameter - 0x30) as usize].value)
    })
    .unwrap();
    assert_eq!(reads, (0x30..=0x37).collect::<Vec<_>>());
    assert!(prerequisites::check(&owned, |_| Ok::<_, ()>(0xffff)).is_err());
    for mode in 0..8 {
        assert!(prerequisites::check(&owned, |parameter| {
            let at = (parameter - 0x30) as usize;
            Ok::<_, ()>(plan.required_words[at].value ^ u16::from(at == mode))
        })
        .is_err());
    }
    for function in reader.functions {
        let mut broken = donor.clone();
        broken[(function.address - 0x410000) as usize] ^= 1;
        assert!(
            calibration_bridge::plan(&target, &broken).is_err(),
            "{:?}",
            function.role
        );
    }
    assert!(calibration_bridge::plan(&target, &fixture(PARAMETER)).is_err());
    let binding = evaluators::observe(&target).unwrap();
    let span = evaluators::calibration(&target, &binding).unwrap().0;
    let mut erased = target;
    erased[span.start + 74..span.start + 76].fill(255);
    assert!(calibration_bridge::plan(&erased, &donor).is_err());
}
