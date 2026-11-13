//! Target-only mapping over captured OEM byte and split output programs.
#![cfg(feature = "envelope")]
#![cfg(feature = "internals")]
use pioneer_optical::filters::phase::native::{
    self, sat1::phase_only, Assignment, CorrectionError,
};

fn image(record: &serde_json::Value) -> Vec<u8> {
    let mut image = vec![255; record["normal_len"].as_u64().unwrap() as usize];
    for span in record["spans"].as_array().unwrap() {
        let address = span[0].as_u64().unwrap() as usize;
        if address < 0x410000 {
            continue;
        }
        let at = address - 0x410000;
        let hex = span[1].as_str().unwrap();
        for i in 0..hex.len() / 2 {
            image[at + i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
    }
    image
}

#[test]
fn mapping_preserves_target_motion_and_round_trips_native_outputs() {
    let fixtures: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/phase-sat1-output-native.json")).unwrap();
    let split: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/phase-sat1-native.json")).unwrap();
    for record in fixtures.iter().chain(&split) {
        let original = image(record);
        let before = phase_only::observe(&original).unwrap();
        let assignment = match before.assignment {
            Assignment::Direct => Assignment::Swapped,
            Assignment::Swapped => Assignment::Direct,
        };
        assert_eq!(
            phase_only::correct(&original, before.assignment).unwrap(),
            original
        );
        // This frozen native form's assignment flip requires replacing its JSR
        // with inline MOV. Output/register agreement cannot prove preservation
        // of the deleted call/return timing and temporary stack effects.
        if record["encoded_component"]
            == "76fe0e3331eea46a11cf8a6eec2e083817963bdb9af4b719866dde203bdfd926"
        {
            assert_eq!(
                phase_only::correct(&original, assignment),
                Err(CorrectionError::Unresolved)
            );
            continue;
        }
        let changed = phase_only::correct(&original, assignment).unwrap();
        assert_eq!(
            phase_only::observe(&changed).unwrap().assignment,
            assignment
        );
        assert_eq!(
            phase_only::observe(&changed).unwrap().interface,
            before.interface
        );
        phase_only::verify(&original, assignment, &changed).unwrap();
        assert_eq!(
            phase_only::correct(&changed, before.assignment).unwrap(),
            original
        );
        // These fixtures contain callers, coefficient banks and producers as
        // well as output code. The mapping is only a handful of operand bytes.
        let differences: Vec<_> = original
            .iter()
            .zip(&changed)
            .enumerate()
            .filter_map(|(at, (a, b))| (a != b).then_some(at))
            .collect();
        assert!(!differences.is_empty() && differences.len() <= 20);
        let mut partial = changed.clone();
        partial[differences[0]] = original[differences[0]];
        assert!(phase_only::verify(&original, assignment, &partial).is_err());
        // Composition may alter disjoint metadata; it cannot alter the bound
        // output program or produce a partially swapped channel pair.
        let mut composed = changed;
        composed[0x100] ^= 1;
        phase_only::verify(&original, assignment, &composed).unwrap();
    }
}

#[test]
fn native_call_and_previously_emitted_inline_form_refuse_assignment_changes() {
    let fixtures: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/phase-sat1-output-native.json")).unwrap();
    let record = fixtures
        .iter()
        .find(|record| {
            record["encoded_component"]
                == "76fe0e3331eea46a11cf8a6eec2e083817963bdb9af4b719866dde203bdfd926"
        })
        .unwrap();
    let original = image(record);
    // Frozen independent disassembly contract: F908 byte operand and JSR to the
    // adjacent F909 MOV/RTS leaf. These are the exact bytes previously emitted.
    assert_eq!(
        &original[0x161a78..0x161a7e],
        &[0x6a, 0x88, 0xf9, 9, 0x54, 0x70]
    );
    assert_eq!(&original[0x161b56..0x161b5a], &[0x6a, 0x89, 0xf9, 8]);
    assert_eq!(&original[0x161b64..0x161b68], &[0x5e, 0x57, 0x1a, 0x78]);
    let mut inline = original.clone();
    inline[0x161b59] = 9;
    inline[0x161b64..0x161b68].copy_from_slice(&[0x6a, 0x88, 0xf9, 8]);
    for (before, after, current, requested) in [
        (&original, &inline, Assignment::Direct, Assignment::Swapped),
        (&inline, &original, Assignment::Swapped, Assignment::Direct),
    ] {
        assert_eq!(phase_only::observe(before).unwrap().assignment, current);
        assert_eq!(phase_only::observe(after).unwrap().assignment, requested);
        assert_eq!(native::correct_legacy(before, current).unwrap(), *before);
        assert_eq!(phase_only::correct(before, current).unwrap(), *before);
        phase_only::verify(before, current, before).unwrap();
        assert_eq!(
            native::correct_legacy(before, requested),
            Err(CorrectionError::Unresolved)
        );
        assert_eq!(
            phase_only::correct(before, requested),
            Err(CorrectionError::Unresolved)
        );
        assert_eq!(
            phase_only::verify(before, requested, after),
            Err(CorrectionError::Unresolved)
        );
    }
}
