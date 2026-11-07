use super::*;
use crate::{
    compatibility::Firmware,
    filters::{Context, Filter},
};

fn fixture(required: u16, variant: usize) -> Vec<u8> {
    let mut normal = vec![0xff; 0x8000];
    crate::image::layout::install_test_layout_variant(&mut normal, 0x1000, variant);
    normal[0x80..0x94].copy_from_slice(&[
        0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
        0x41, 0x60, 0,
    ]);
    normal[0x8a..0x8c].copy_from_slice(&required.to_be_bytes());
    normal[0x6000..0x6006].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
    normal
}
fn context(normal: &[u8]) -> Context<'_> {
    Context::new(Firmware {
        hardware: "SAT 8000",
        normal,
        kernel: None,
    })
}
fn operation(installed: &[u8], target: &[u8]) -> Result<Option<Box<dyn Operation>>, Error> {
    let installed = context(installed);
    let target = context(target);
    super::super::FILTER.plan(
        &Transition {
            installed: &installed,
            target: &target,
        },
        &super::super::inspect(&installed),
        &super::super::inspect(&target),
    )
}
fn preparation(normal: &[u8]) -> Preparation<'_> {
    Preparation {
        target: context(normal).firmware,
        #[cfg(feature = "envelope")]
        normal: None,
        #[cfg(feature = "envelope")]
        kernel: None,
    }
}

#[test]
fn filter_preserves_unchanged_comparison_and_requires_live_word_read_only() {
    let mut installed = fixture(0xfe24, 0);
    installed[0x7000] ^= 1;
    let target = fixture(0xfe24, 0);
    let operation = operation(&installed, &target).unwrap().unwrap();
    assert_eq!(operation.filter_id(), "startup-prerequisite");
    assert_eq!(
        operation.required_words(),
        [Word {
            parameter: 0x9f,
            value: 0xfe24
        }]
    );
    assert!(super::super::FILTER
        .parameters(&context(&target))
        .unwrap()
        .is_empty());
    let preparation = preparation(&target);
    assert!(operation.prepare(&preparation).unwrap().is_none());
    operation.verify(&preparation, &target).unwrap();
    for offset in [0x80, 0x84, 0x8a, 0x8c, 0x8e, 0x1000, 0x6000] {
        let mut bad = target.clone();
        bad[offset] ^= 1;
        assert!(
            operation.verify(&preparation, &bad).is_err(),
            "offset {offset:#x}"
        );
    }
    // Other owners may change disjoint image bytes during atomic composition.
    let mut composed = target.clone();
    composed[0x7000] ^= 1;
    operation.verify(&preparation, &composed).unwrap();
    assert!(operation.prepare(&self::preparation(&installed)).is_err());
}

#[test]
fn equal_gate_retains_read_only_requirement_without_an_image_effect() {
    let normal = fixture(0xfe24, 0);
    let operation = operation(&normal, &normal).unwrap().unwrap();
    assert_eq!(
        operation.required_words(),
        [Word {
            parameter: 0x9f,
            value: 0xfe24
        }]
    );
    assert!(operation.prepare(&preparation(&normal)).unwrap().is_none());
}

#[test]
fn differing_primary_comparisons_refuse_without_writer_lifecycle_proof() {
    for (source, target) in [(0xfe25, 0xfe24), (0xfe24, 0xfe25)] {
        assert!(matches!(
            operation(&fixture(source, 0), &fixture(target, 0)),
            Err(Error::Unsupported)
        ));
    }
}

#[test]
fn operation_and_final_comparison_cannot_bypass_unchanged_operand_restriction() {
    let target = fixture(0xfe24, 0);
    let prepared = preparation(&target);
    let op = operation(&target, &target).unwrap().unwrap();
    let mut tampered = target.clone();
    tampered[0x8b] = 0x25;
    assert!(matches!(
        op.verify(&prepared, &tampered),
        Err(Error::VerificationFailed)
    ));
    // Even a stale/preconstructed operation carrying a different desired word
    // must refuse before encoding or final-output verification can approve it.
    let forged = StartupOperation {
        hardware: "SAT 8000".into(),
        normal: target.clone(),
        kernel: None,
        gate: Gate::bind(&target).unwrap(),
        required: 0xfe25,
    };
    assert!(matches!(forged.prepare(&prepared), Err(Error::Unsupported)));
    assert!(matches!(
        forged.verify(&prepared, &tampered),
        Err(Error::Unsupported)
    ));
}

#[test]
fn unresolved_source_keeps_target_word_fallback_and_unknown_exact_pairs() {
    let normal = fixture(0xfe24, 0);
    let mut no_gate = normal.clone();
    no_gate[0x80..0x94].fill(0xff);
    let condition = operation(&no_gate, &normal).unwrap().unwrap();
    assert_eq!(
        condition.required_words(),
        [Word {
            parameter: 0x9f,
            value: 0xfe24
        }]
    );
    assert!(condition.prepare(&preparation(&normal)).unwrap().is_none());
    assert!(operation(&normal, &no_gate).is_err());
    assert!(operation(&no_gate, &no_gate).unwrap().is_none());
    let mut different = no_gate.clone();
    different[0x7000] ^= 1;
    assert!(operation(&no_gate, &different).is_err());
}

#[test]
fn conditional_alternative_is_not_erased_or_promoted_to_unconditional_acceptance() {
    let target = h8_conditional::tests::fixture(0x1000, 0x4000, 0x5000);
    let installed = fixture(0xfe23, 5);
    let operation = operation(&installed, &target).unwrap().unwrap();
    let prepared = preparation(&target);
    assert!(operation.prepare(&prepared).unwrap().is_none());
    operation.verify(&prepared, &target).unwrap();
    let gate = Gate::bind(&target).unwrap();
    assert_eq!(gate.bound.requirement.required, 0xfe23);
    assert_eq!(gate.conditional, Gate::bind(&target).unwrap().conditional);
    assert!(self::operation(&fixture(0xfe09, 5), &target).is_err());
    for offset in [0x90, 0x94, 0x4000 + 253, 0x4000 + 279, 0x5000 + 10] {
        let mut bad = target.clone();
        bad[offset] ^= 1;
        assert!(operation.verify(&prepared, &bad).is_err(), "{offset:#x}");
    }
    assert!(matches!(
        self::operation(&fixture(0xfe24, 5), &target),
        Err(Error::Unsupported)
    ));
    // A conditional shape without its complete predicate cannot be admitted.
    let mut incomplete = target.clone();
    incomplete[0x4000 + 253] ^= 1;
    assert!(self::operation(&installed, &incomplete).is_err());
}

#[test]
fn unchanged_indirect_getter_and_long_branch_keep_original_abi_and_call_address() {
    let installed = fixture(0xfe24, 0);
    for load_before in [false, true] {
        let mut target = fixture(0xfe24, 0);
        target[0x80..0xa0].fill(0xff);
        let load = [0x7a, 5, 0, 0x41, 0x10, 0];
        let param = [0x79, 0, 0, 0x9f];
        let mut code = vec![];
        if load_before {
            code.extend(load);
            code.extend(param);
        } else {
            code.extend(param);
            code.extend(load);
        }
        code.extend([
            0x5d, 0x50, 0x79, 0x20, 0xfe, 0x24, 0x58, 0x70, 0, 6, 0xf8, 1, 0x5e, 0x41, 0x60, 0,
        ]);
        target[0x80..0x80 + code.len()].copy_from_slice(&code);
        let op = operation(&installed, &target).unwrap().unwrap();
        assert_eq!(
            op.required_words(),
            [Word {
                parameter: 0x9f,
                value: 0xfe24
            }]
        );
        assert!(op.prepare(&preparation(&target)).unwrap().is_none());
        op.verify(&preparation(&target), &target).unwrap();
    }
}

/// Independent instruction execution of the complete native gate. Getter and
/// predicate calls are explicit inputs; Kernel loader service calls are outputs.
fn native_accepts(code: &[u8], word: u16, predicate: bool, saved_flag: bool) -> (bool, usize) {
    let mut registers = [0u32; 8];
    registers[4] = u32::from(saved_flag);
    let mut zero = false;
    let mut at = 0;
    let mut rejected = false;
    let mut predicate_calls = 0;
    let get = |registers: &[u32; 8], reg| match reg {
        Reg::Byte(n) => (registers[(n % 8) as usize] >> if n < 8 { 8 } else { 0 }) & 255,
        Reg::Word(n) => (registers[(n % 8) as usize] >> if n < 8 { 0 } else { 16 }) & 65535,
        Reg::Long(n) => registers[n as usize],
        _ => panic!("unsupported register {reg:?}"),
    };
    let value = |registers: &[u32; 8], operand| match operand {
        Operand::Register(reg) => get(registers, reg),
        Operand::Immediate { value, .. } => value,
        _ => panic!("unsupported operand {operand:?}"),
    };
    for _ in 0..64 {
        if at == code.len() {
            return (!rejected, predicate_calls);
        }
        let d = decode_insn(&code[at..], Target::H8S2000, Mode::Advanced).unwrap();
        let [a, b, _] = d.insn.operands;
        at += d.len;
        match (d.insn.mnemonic, a, b) {
            ("MOV" | "SUB", a, Operand::Register(reg)) => {
                let result = if d.insn.mnemonic == "MOV" {
                    value(&registers, a)
                } else {
                    get(&registers, reg).wrapping_sub(value(&registers, a))
                };
                let (n, shift, mask) = match reg {
                    Reg::Byte(n) => (n % 8, if n < 8 { 8 } else { 0 }, 255),
                    Reg::Word(n) => (n % 8, if n < 8 { 0 } else { 16 }, 65535),
                    Reg::Long(n) => (n, 0, u32::MAX),
                    _ => panic!("{reg:?}"),
                };
                let old = &mut registers[n as usize];
                *old = (*old & !(mask << shift)) | ((result & mask) << shift);
                zero = result & mask == 0;
            }
            ("CMP", a, b) => zero = value(&registers, a) == value(&registers, b),
            ("BEQ" | "BNE", Operand::Address(Ea::PcRelative { value, .. }), _) => {
                if (d.insn.mnemonic == "BEQ") == zero {
                    at = at.checked_add_signed(value as isize).unwrap();
                }
            }
            ("JSR", Operand::Address(Ea::Absolute { value, .. }), _) => match value {
                0x411000 => {
                    assert_eq!(registers[0] & 65535, 0x9f);
                    registers[0] = u32::from(word);
                }
                0x414000 => {
                    registers[0] = u32::from(predicate);
                    predicate_calls += 1;
                }
                0x415110 | 0x416000 => {
                    assert_eq!(registers[0] & 255, 1);
                    rejected = true;
                }
                0x415100 | 0x415120 => {}
                _ => panic!("unknown native service {value:#x}"),
            },
            other => panic!("unsupported native instruction {other:?}"),
        }
    }
    panic!("native gate did not terminate");
}

#[test]
fn unchanged_conditional_gate_preserves_native_word_and_predicate_semantics() {
    let conditional = h8_conditional::tests::fixture(0x1000, 0x4000, 0x5000);
    let donor = fixture(0xfe23, 5);
    let op = operation(&donor, &conditional).unwrap().unwrap();
    assert!(op.prepare(&preparation(&conditional)).unwrap().is_none());
    for word in 0..=u16::MAX {
        for predicate in [false, true] {
            for saved_flag in [false, true] {
                let (accepted, calls) =
                    native_accepts(&conditional[0x80..0xbc], word, predicate, saved_flag);
                assert_eq!(
                    accepted,
                    word == 0xfe23 || (word == 0xfe09 && predicate),
                    "{word:04x}/{predicate}/{saved_flag}"
                );
                assert_eq!(calls, usize::from(word == 0xfe09));
            }
        }
    }
    let simple = fixture(0xfe25, 0);
    for word in 0..=u16::MAX {
        assert_eq!(
            native_accepts(&simple[0x80..0x94], word, false, false),
            (word == 0xfe25, 0)
        );
    }
}

#[test]
fn native_oem_rejection_continuation_is_preserved_after_the_flag_service() {
    // Held SAT8801 OEM form. The final call follows the proven loader-flag
    // service; it must remain unchanged, not be mistaken for another gate.
    let mut target = fixture(0xfe13, 0);
    target[0x8c..0xa4].copy_from_slice(&[
        0x47, 0x16, 0x0c, 0xee, 0x47, 0x06, 0xf8, 1, 0x5e, 0x41, 0x60, 0x10, 0xf8, 1, 0x5e, 0x41,
        0x60, 0, 0x18, 0x88, 0x5e, 0x41, 0x61, 0,
    ]);
    target[0x6010..0x6016].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x14, 0x54, 0x70]);
    target[0x6100..0x6106].copy_from_slice(&[0x01, 0x10, 0x6d, 0xf4, 0x0c, 0x8c]);
    let donor = fixture(0xfe13, 0);
    let op = operation(&donor, &target).unwrap().unwrap();
    assert!(op.prepare(&preparation(&target)).unwrap().is_none());
    op.verify(&preparation(&target), &target).unwrap();
    assert!(matches!(
        operation(&fixture(0xfe24, 0), &target),
        Err(Error::Unsupported)
    ));
}
