//! Generated software waveforms through the independent phase owner.
#![cfg(feature = "envelope")]
use pioneer_optical::{
    compatibility::Firmware,
    filters::phase::{
        bundle::waveforms::resources::{evaluators, generated},
        native,
    },
};
#[path = "support/phase_only.rs"]
mod phase_only;
const HASHES: [&str; 2] = [
    "8037cdb3ae67e04a82aa3e9b7a0f52202e17f1e39d1f50b894158d9be0cec898",
    "99ba77ae1cedc967096c770b21c066d04a5163f1c5a4aa82f27584c6faced796",
];
fn fixture(hash: &str) -> Vec<u8> {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-native-spans.json")).unwrap();
    let f = fixtures
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["original_sha256"].as_str() == Some(hash))
        .unwrap();
    let mut n = vec![255; f["size"].as_u64().unwrap() as usize];
    for s in f["spans"].as_array().unwrap() {
        let at = s[0].as_u64().unwrap() as usize;
        let h = s[1].as_str().unwrap();
        for i in 0..h.len() / 2 {
            n[at + i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
        }
    }
    let proofs: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-generated-arithmetic.json")).unwrap();
    for proof in proofs
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["normal"].as_str() == Some(hash))
    {
        for span in proof["spans"].as_array().unwrap() {
            let at = span[0].as_u64().unwrap() as usize - 0x410000;
            let h = span[1].as_str().unwrap();
            for i in 0..h.len() / 2 {
                n[at + i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
            }
        }
    }
    let reader: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-calibration-reader.json")).unwrap();
    if reader["original_sha256"].as_str() == Some(hash) {
        for span in reader["spans"].as_array().unwrap() {
            let at = span[0].as_u64().unwrap() as usize;
            let h = span[1].as_str().unwrap();
            for i in 0..h.len() / 2 {
                n[at + i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
            }
        }
    }
    checksum(&mut n);
    n
}
fn checksum(n: &mut [u8]) {
    n[16..20].fill(0);
    let sum = n.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    n[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
}

#[test]
fn generated_phase_retains_target_basis_calibration_and_lifecycle() {
    for hash in HASHES {
        let target = fixture(hash);
        let before = generated::observe(&target).unwrap();
        for assignment in [native::Assignment::Direct, native::Assignment::Swapped] {
            let mut donor = native::correct_pair(&target, assignment).unwrap();
            let range = before.evaluator.basis.clone();
            for row in 0..64 {
                donor[range.start + row * 4..range.start + row * 4 + 4].copy_from_slice(
                    &target[range.start + ((row + 16) % 64) * 4
                        ..range.start + ((row + 16) % 64) * 4 + 4],
                );
            }
            checksum(&mut donor);
            assert_eq!(generated::rotation(&target, &donor), Ok(16));
            let changed = phase_only::check(
                Firmware {
                    hardware: "SAT 8000",
                    normal: &donor,
                    kernel: None,
                },
                Firmware {
                    hardware: "SAT 8000",
                    normal: &target,
                    kernel: None,
                },
                None,
                None,
            );
            assert_eq!(&changed[range.clone()], &target[range]);
            assert_eq!(
                generated::observe(&changed).unwrap().calibration,
                before.calibration
            );
            let mut broken = donor.clone();
            broken[before.evaluator.basis.start] ^= 1;
            assert!(generated::transplant(&target, &broken).is_err());
        }
    }
}

#[test]
fn generated_resource_api_keeps_its_guards_but_phase_ignores_calibration_differences() {
    let a = fixture(HASHES[0]);
    let b = fixture(HASHES[1]);
    for (target, donor, conditional) in [(&a, &b, false), (&b, &a, true)] {
        assert!(generated::rotation(target, donor).is_err());
        let complete = generated::plan(target, donor).unwrap();
        assert_eq!(
            complete.required_words.len(),
            if conditional { 8 } else { 0 }
        );
        if conditional {
            assert!(generated::transplant(target, donor).is_err());
        }
        let changed = phase_only::check(
            Firmware {
                hardware: "SAT 8000",
                normal: donor,
                kernel: None,
            },
            Firmware {
                hardware: "SAT 8000",
                normal: target,
                kernel: None,
            },
            None,
            None,
        );
        assert_eq!(changed, *target);
    }
}

#[test]
fn native_generated_modes_move_selector_producer_and_initialization_together() {
    use pioneer_optical::filters::phase::bundle::waveforms::resources::software;
    let a = fixture(HASHES[0]);
    let b = fixture(HASHES[1]);
    for (target, donor) in [(&a, &b), (&b, &a)] {
        let before = software::observe(target).unwrap();
        let required = software::observe(donor).unwrap();
        let changed = software::transplant_modes(target, donor).unwrap();
        let after = software::observe(&changed).unwrap();
        let producer = software::observe_producer(&changed).unwrap();
        let role = |binding: &software::Binding, mode: u8| {
            binding
                .choices
                .iter()
                .position(|(m, _)| *m == Some(mode))
                .unwrap_or_else(|| {
                    binding
                        .choices
                        .iter()
                        .position(|(m, _)| m.is_none())
                        .unwrap()
                })
        };
        for mode in 0..=255 {
            assert_eq!(role(&after, mode), role(&required, mode));
        }
        for (a, b) in before.choices.iter().zip(&after.choices) {
            assert_eq!(a.1, b.1);
        }
        assert_eq!(
            software::transplant_modes(&changed, target).unwrap(),
            *target
        );
        let mut broken = changed.clone();
        broken[producer.initializer.start + 13] = target[producer.initializer.start + 13];
        assert!(software::observe_producer(&broken).is_err());
        assert_eq!(
            evaluators::calibration(&changed, &evaluators::observe(&changed).unwrap()).unwrap(),
            evaluators::calibration(target, &evaluators::observe(target).unwrap()).unwrap()
        );
    }
}

#[path = "../examples/hardware_matrix/page.rs"]
mod page;

#[test]
#[ignore = "requires PIONEER_HOARD; two actual generated representations through original codecs"]
fn native_generated_directions_round_trip_original_envelopes() {
    use pioneer_optical::envelope::Envelope;
    let root = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").unwrap());
    let components = [
        "ddfa7d758503458345de549321b048574a162272b7e3ee0cfe2e257110eb6982",
        "87b5c390eb782406c8fb7a6e9f1e02626c6ea7bdf5d23c3c342b1e7233af8ca8",
    ];
    let (packages, _) = page::hoard_packages(&root).unwrap();
    let originals: Vec<_> = components
        .iter()
        .map(|hash| {
            let p = packages.iter().find(|p| p.component == *hash).unwrap();
            (p.hardware.clone(), page::decode(&root, p).unwrap())
        })
        .collect();
    for (target, donor) in [(0, 1), (1, 0)] {
        let (hardware, original) = &originals[target];
        let (source_hardware, source) = &originals[donor];
        let changed = phase_only::check(
            Firmware {
                hardware: source_hardware,
                normal: &source.normal.image,
                kernel: source.kernel.as_ref().map(|k| k.image.as_slice()),
            },
            Firmware {
                hardware,
                normal: &original.normal.image,
                kernel: original.kernel.as_ref().map(|k| k.image.as_slice()),
            },
            Some(&original.normal),
            original.kernel.as_ref(),
        );
        let encoded = original.normal.repack(&changed).unwrap();
        let decoded = if let Some(kernel) = &original.kernel {
            Envelope::load_with_kernel(&encoded, kernel)
        } else {
            Envelope::load(&encoded)
        }
        .unwrap();
        assert_eq!(decoded.image, changed);
        assert_eq!(decoded.repack(&decoded.image).unwrap(), encoded);
    }
}

#[test]
fn four_choice_selector_distinguishes_stored_tables_from_runtime_producers() {
    use pioneer_optical::filters::phase::bundle::waveforms::resources::software;
    let mut image = fixture(HASHES[0]);
    let original = software::observe(&image).unwrap();
    assert!(original
        .choices
        .iter()
        .all(|(_, s)| matches!(s, software::Source::Runtime(_))));
    assert!(image[0x10000..0x10400].iter().all(|b| *b == 255));
    for (i, field) in [20, 28, 36, 44].into_iter().enumerate() {
        let at = original.selector.start + field;
        image[at..at + 4].copy_from_slice(&(0x420000u32 + i as u32 * 256).to_be_bytes());
        image[0x10000 + i * 256..0x10100 + i * 256].fill(i as u8);
    }
    let materialized = software::observe(&image).unwrap();
    assert_eq!(
        materialized
            .choices
            .iter()
            .map(|(m, _)| *m)
            .collect::<Vec<_>>(),
        original.choices.iter().map(|(m, _)| *m).collect::<Vec<_>>()
    );
    assert!(materialized
        .choices
        .iter()
        .all(|(_, s)| matches!(s,software::Source::Image(r) if r.len()==256)));
    assert!(software::observe_producer(&image).is_err());
    let at = original.selector.start + 20;
    let incomplete = 0x410000 + image.len() as u32 - 2;
    image[at..at + 4].copy_from_slice(&incomplete.to_be_bytes());
    assert!(software::observe(&image).is_err());
}

#[test]
fn equal_phase_assignment_is_noop_across_resource_and_encoder_representations() {
    let literal = fixture("87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1");
    for hash in HASHES {
        let target = fixture(hash);
        let source = native::correct_pair(
            &literal,
            generated::observe(&target).unwrap().coils.assignment,
        )
        .unwrap();
        assert!(generated::observe(&source).is_err());
        assert_ne!(
            native::encoders::observe(&source).unwrap().representation,
            native::encoders::observe(&target).unwrap().representation
        );
        assert_eq!(
            phase_only::check(
                Firmware {
                    hardware: "SAT 8000",
                    normal: &source,
                    kernel: None
                },
                Firmware {
                    hardware: "SAT 8000",
                    normal: &target,
                    kernel: None
                },
                None,
                None
            ),
            target
        );
    }
}
