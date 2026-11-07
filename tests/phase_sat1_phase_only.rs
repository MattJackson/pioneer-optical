//! Target-only mapping over captured OEM byte and split output programs.
#![cfg(feature = "envelope")]
use pioneer_optical::filters::phase::native::{sat1::phase_only, Assignment};

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
