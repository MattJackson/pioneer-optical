use super::*;

fn fixture() -> Vec<u8> {
    crate::image::phase::tests::fixture(false)
}
fn context<'a>(normal: &'a [u8]) -> Context<'a> {
    Context::new(Firmware {
        hardware: "SAT 8000",
        normal,
        kernel: None,
    })
}
fn assessment(value: NativePhase) -> Assessment {
    Assessment::known("phase", Role::Hardware, value.value(), "test native fact")
}
fn known(context: &Context<'_>) -> NativePhase {
    let Finding::Known(value) = FILTER.inspect(context).finding else {
        panic!("native phase");
    };
    NativePhase::from_value(&value).unwrap()
}
fn preparation<'a>(target: Firmware<'a>) -> Preparation<'a> {
    Preparation {
        target,
        #[cfg(feature = "envelope")]
        normal: None,
        #[cfg(feature = "envelope")]
        kernel: None,
    }
}
fn complete(mut raw: Vec<u8>) -> Vec<u8> {
    raw[..16].copy_from_slice(b"PIONEER TEST    ");
    raw[16..20].fill(0);
    let length = raw.len() as u32;
    raw[20..24].copy_from_slice(&length.to_be_bytes());
    let sum = raw.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    raw[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
    raw
}

#[test]
fn native_value_keeps_architecture_interface_and_register_coordinates() {
    let values = [
        NativePhase {
            architecture: Architecture::H8,
            interface: Interface::H8BytePair {
                outputs: [0xf908, 0xf909],
            },
            assignment: native::Assignment::Direct,
        },
        NativePhase {
            architecture: Architecture::H8,
            interface: Interface::H8SplitWord {
                outputs: [0xf910, 0xf911],
                controls: [0xf912, 0xf913],
            },
            assignment: native::Assignment::Direct,
        },
        NativePhase {
            architecture: Architecture::M32c,
            interface: Interface::Direct8 {
                channels: [0x118, 0x119],
            },
            assignment: native::Assignment::Swapped,
        },
        NativePhase {
            architecture: Architecture::M32c,
            interface: Interface::Indexed16 {
                window: 0x100100,
                channels: [0x8e, 0x8f],
            },
            assignment: native::Assignment::Direct,
        },
        NativePhase {
            architecture: Architecture::V850,
            interface: Interface::Indexed16 {
                window: 0x200100,
                channels: [0x8e, 0x8f],
            },
            assignment: native::Assignment::Direct,
        },
    ];
    for (at, value) in values.iter().enumerate() {
        assert_eq!(NativePhase::from_value(&value.value()), Some(*value));
        for other in &values[..at] {
            assert_ne!(
                value.value().canonical_bytes(),
                other.value().canonical_bytes()
            );
        }
    }
}

#[test]
fn interface_difference_refuses_even_when_assignments_match() {
    let raw = fixture();
    let installed = context(&raw);
    let target = context(&raw);
    let direct = known(&installed);
    for interface in [
        Interface::H8BytePair {
            outputs: [0xf908, 0xf909],
        },
        Interface::H8SplitWord {
            outputs: [0xf920, 0xf921],
            controls: [0xf912, 0xf913],
        },
    ] {
        let different = NativePhase {
            interface,
            ..direct
        };
        let (a, b) = (assessment(direct), assessment(different));
        assert_eq!(FILTER.compare(&a, &b), Comparison::Different);
        assert!(matches!(
            FILTER.plan(
                &Transition {
                    installed: &installed,
                    target: &target
                },
                &a,
                &b
            ),
            Err(Error::Incompatible)
        ));
    }
}

#[test]
fn detected_mismatch_survives_missing_checksum_and_unrelated_family_evidence() {
    let raw = fixture();
    let swapped = native::correct_pair(&raw, native::Assignment::Swapped).unwrap();
    let installed = context(&swapped);
    let target = context(&raw);
    let (a, b) = (FILTER.inspect(&installed), FILTER.inspect(&target));
    assert_eq!(FILTER.compare(&a, &b), Comparison::Different);
    // Missing layout/host/loading evidence is not a prerequisite for detecting
    // phase; the original raw fixture deliberately has no valid Normal header.
    assert!(crate::image::matrix::discover("SAT 8000", &raw, None).is_none());
    let operation = FILTER
        .plan(
            &Transition {
                installed: &installed,
                target: &target,
            },
            &a,
            &b,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        operation.prepare(&preparation(target.firmware)),
        Err(Error::Phase(native::CorrectionError::InvalidNormal))
    );
}

#[test]
fn paired_candidate_keeps_interface_but_does_not_require_file_correction_support() {
    let raw = fixture();
    let swapped = native::correct_pair(&raw, native::Assignment::Swapped).unwrap();
    let (a, b) = (context(&raw), context(&swapped));
    let (a_observed, b_observed) = (FILTER.inspect(&a), FILTER.inspect(&b));
    assert_ne!(a_observed.finding, b_observed.finding);
    let a_candidate = FILTER.candidate(&a, &a_observed);
    assert_eq!(a_candidate, FILTER.candidate(&b, &b_observed));
    let Finding::Known(Value::Variant(2, fields)) = a_candidate else {
        panic!("paired projection");
    };
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0], Value::U8(0));
    assert_eq!(
        fields[1],
        Value::Variant(
            1,
            vec![
                Value::U16(0xf910),
                Value::U16(0xf911),
                Value::U16(0xf912),
                Value::U16(0xf913)
            ]
        )
    );
}

#[test]
fn phase_operation_is_component_bound_and_composes_with_one_checksum_owner() {
    let raw = complete(fixture());
    let swapped = native::correct_normal(&raw, native::Assignment::Swapped).unwrap();
    let installed = context(&swapped);
    let target = context(&raw);
    let operation = FILTER
        .plan(
            &Transition {
                installed: &installed,
                target: &target,
            },
            &FILTER.inspect(&installed),
            &FILTER.inspect(&target),
        )
        .unwrap()
        .unwrap();
    let context = preparation(target.firmware);
    let operands = operation.prepare(&context).unwrap().unwrap();
    assert_eq!(&operands[16..20], &raw[16..20]);
    let integrity = operation.integrity().unwrap();
    let repaired = (integrity.repair)(&context, &operands).unwrap();
    assert_eq!(repaired, swapped);
    operation.verify(&context, &repaired).unwrap();
    assert_eq!(
        operation.verify(&context, &raw),
        Err(Error::VerificationFailed)
    );
    let mut substituted = raw.clone();
    substituted[480] ^= 1;
    assert_eq!(
        operation.prepare(&preparation(Firmware {
            normal: &substituted,
            ..target.firmware
        })),
        Err(Error::ComponentMismatch)
    );
    // A separately owned disjoint effect does not invalidate phase postcondition.
    let mut composed = repaired;
    composed[480] ^= 1;
    operation.verify(&context, &composed).unwrap();
}

#[test]
fn unknown_legacy_and_missing_values_are_not_known_equal_or_inapplicable() {
    for hardware in [
        "SCSI0001", "ATA 0000", "SAT 1000", "SAT 8000", "SAT 9000", "UNKNOWN",
    ] {
        let context = Context::new(Firmware {
            hardware,
            normal: &[],
            kernel: None,
        });
        let finding = FILTER.inspect(&context);
        assert!(matches!(finding.finding, Finding::Unresolved(_)));
        assert_eq!(FILTER.compare(&finding, &finding), Comparison::Unresolved);
    }
}

#[test]
fn helper_relocation_does_not_become_phase_hardware_identity() {
    let original = fixture();
    let mut relocated = original.clone();
    let mut calls = 0;
    for at in (0..relocated.len() - 3).step_by(2) {
        if relocated[at] != 0x5e {
            continue;
        }
        let address =
            u32::from_be_bytes([0, relocated[at + 1], relocated[at + 2], relocated[at + 3]]);
        if matches!(address, 0x400010 | 0x400012) {
            relocated[at + 1..at + 4].copy_from_slice(&(address + 0x20).to_be_bytes()[1..]);
            calls += 1;
        }
    }
    assert_eq!(calls, 4);
    let (a, b) = (context(&original), context(&relocated));
    assert_eq!(FILTER.inspect(&a).finding, FILTER.inspect(&b).finding);
    assert_eq!(
        FILTER.candidate(&a, &FILTER.inspect(&a)),
        FILTER.candidate(&b, &FILTER.inspect(&b))
    );
}
