#![cfg(feature = "envelope")]
use pioneer_optical::startup::bank;
use sha2::{Digest, Sha256};

fn image(model: &str) -> Vec<u8> {
    let root = std::env::var("PIONEER_STARTUP_IMAGE_DIR")
        .expect("set PIONEER_STARTUP_IMAGE_DIR to the held decoded pair");
    let b = std::fs::read(format!("{root}/BDR-{model}U-normal.bin")).unwrap();
    let expected = match model {
        "212" => "1a84694c45cc1575a8f4c817ce21edbf99575ce0b45845b1fd6a57081575b73c",
        "213" => "4c57a8f1a43367489a24ed591ba3bcd0e87267a07b58d290a8f658d2cc200025",
        _ => panic!("unknown fixture"),
    };
    assert_eq!(format!("{:x}", Sha256::digest(&b)), expected);
    b
}

#[test]
#[ignore = "requires held OEM decoded 212U/213U 1.02 images"]
fn held_pair_addresses_and_values_are_recovered() {
    for (model, magic, markers, extended) in [
        (
            "212",
            0xfedc4321,
            [0x5efffa, 0x5ffffa],
            [0x7dfffa, 0x7efffa],
        ),
        (
            "213",
            0xfedc4322,
            [0x5f3ffa, 0x5ffffa],
            [0x7dbffa, 0x7e7ffa],
        ),
    ] {
        let b = image(model);
        let guard = bank::discover(&b).expect("bank guard");
        let layout = guard.layout(&b).expect("linked base calculation");
        assert_eq!(guard.magic, magic);
        assert_eq!(layout.when_one.markers, markers);
        assert_eq!(layout.otherwise.markers, extended);
    }
}

#[test]
#[ignore = "requires held OEM decoded 212U/213U 1.02 images"]
fn operands_are_extracted_and_relocated_code_is_recognized() {
    for model in ["212", "213"] {
        let mut b = image(model);
        let before = bank::discover(&b).unwrap();
        let old_layout = before.layout(&b).unwrap();
        let guard_at = (before.validator - 0x410000) as usize;
        let calculation_at = (old_layout.calculation - 0x410000) as usize;
        b[guard_at + 0xe..guard_at + 0x12].copy_from_slice(&0x12345678u32.to_be_bytes());
        for (at, value) in [
            (0x26, before.marker_offsets[0] + 4),
            (0x34, before.marker_offsets[0]),
            (0x46, before.marker_offsets[1]),
            (0x66, before.marker_offsets[0]),
            (0x82, before.marker_offsets[1]),
        ] {
            b[guard_at + at..guard_at + at + 4].copy_from_slice(&(value + 0x100).to_be_bytes());
        }
        // Change the compact flash-end operand, independently of bank offsets.
        b[calculation_at + 16..calculation_at + 18].copy_from_slice(&0x6fu16.to_be_bytes());
        let changed = bank::discover(&b).unwrap();
        assert_eq!(changed.magic, 0x12345678);
        let changed_layout = changed.layout(&b).unwrap();
        assert_eq!(
            changed_layout.when_one.markers,
            old_layout.when_one.markers.map(|a| a + 0x100100)
        );

        // Relocate both routines and the calls linking them; erase original
        // copies so the detector cannot select the known firmware locations.
        let guard_copy = b[guard_at..guard_at + 0x96].to_vec();
        let calc_len = if model == "212" { 0x32 } else { 0x36 };
        let calc_copy = b[calculation_at..calculation_at + calc_len].to_vec();
        let moved_calc = (b.len() + 0x100 + 1) & !1;
        let moved_guard = moved_calc + 0x100;
        let new_calc_address = 0x410000 + moved_calc as u32;
        let new_guard_address = 0x410000 + moved_guard as u32;
        for (old, new) in [
            (old_layout.calculation, new_calc_address),
            (before.validator, new_guard_address),
        ] {
            for at in (0..b.len() - 4).step_by(2) {
                if b[at] == 0x5e && b[at + 1..at + 4] == old.to_be_bytes()[1..] {
                    b[at + 1..at + 4].copy_from_slice(&new.to_be_bytes()[1..]);
                }
            }
        }
        b[guard_at..guard_at + 0x96].fill(0xff);
        b[calculation_at..calculation_at + calc_len].fill(0xff);
        b.resize(moved_guard + guard_copy.len(), 0xff);
        b[moved_calc..moved_calc + calc_copy.len()].copy_from_slice(&calc_copy);
        b[moved_guard..moved_guard + guard_copy.len()].copy_from_slice(&guard_copy);
        let moved = bank::discover(&b).unwrap();
        assert_eq!(moved.validator, new_guard_address);
        assert_eq!(moved.magic, changed.magic);
        assert_eq!(
            moved.layout(&b).unwrap().when_one.markers,
            changed_layout.when_one.markers
        );
    }
}

#[test]
#[ignore = "requires held OEM decoded 212U/213U 1.02 images"]
fn damaged_control_flow_or_ambiguous_validators_are_unknown() {
    for model in ["212", "213"] {
        let b = image(model);
        let guard = bank::discover(&b).unwrap();
        let at = (guard.validator - 0x410000) as usize;
        let mut corrupt = b.clone();
        corrupt[at + 0x7b] ^= 2; // Changes the accept-first-bank branch target.
        assert!(bank::discover(&corrupt).is_none());
        let mut duplicate = b.clone();
        duplicate.extend_from_slice(&b[at..at + 0x96]);
        assert!(bank::discover(&duplicate).is_none());
        let mut unbound = b.clone();
        let layout = guard.layout(&b).unwrap();
        let store =
            (layout.calculation - 0x410000) as usize + if model == "212" { 0x2c } else { 0x30 };
        unbound[store + 3] ^= 2; // Break the data-flow binding to the guard's slot.
        assert!(guard.layout(&unbound).is_none());
    }
}

#[test]
#[ignore = "requires decoded Normal/Kernel corpus and metadata in PIONEER_STARTUP_CORPUS"]
fn held_hoard_resolves_every_supported_pair_with_available_components() {
    use std::collections::{BTreeMap, BTreeSet};
    let root = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_CORPUS").unwrap());
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("packages.json")).unwrap()).unwrap();
    let mut resolved = BTreeMap::new();
    let mut missing = BTreeSet::new();
    let mut unsupported = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for p in metadata["packages"].as_array().unwrap() {
        let sha = p["normal_sha256"].as_str().unwrap();
        let Ok(normal) = std::fs::read(root.join("normal").join(format!("{sha}.bin"))) else {
            continue;
        };
        seen.insert(sha.to_string());
        let kernel = p["kernel_sha256"]
            .as_str()
            .and_then(|sha| std::fs::read(root.join("kernel").join(format!("{sha}.bin"))).ok());
        let storage = bank::analyze_pair(&normal, kernel.as_deref());
        if pioneer_optical::image::receiver_control(&normal).is_none() {
            assert!(
                storage.is_none(),
                "unsupported receiver unexpectedly recognized: {sha}"
            );
            unsupported.insert(sha.to_string());
        } else if kernel.is_none() && storage.is_none() {
            missing.insert(sha.to_string());
        } else {
            let storage = storage.unwrap_or_else(|| panic!("supported pair unresolved: {sha}"));
            assert_eq!(bank::check(Some(storage), Some(storage)), Ok(()));
            resolved.insert(sha.to_string(), storage);
        }
    }
    assert_eq!(
        (seen.len(), resolved.len(), missing.len(), unsupported.len()),
        (700, 527, 3, 170)
    );
    let mut counts = [0; 5];
    for storage in resolved.values() {
        let kind = match storage {
            bank::Storage::Versioned(bank::Contract {
                addresses: bank::Addresses::Capacity { .. },
                ..
            }) => 0,
            bank::Storage::Versioned(bank::Contract {
                validation: bank::Validation::RejectMismatch,
                ..
            }) => 1,
            bank::Storage::Versioned(_) => 2,
            bank::Storage::StateHeaders { .. } => 3,
            bank::Storage::KernelSequences { .. } => 4,
        };
        counts[kind] += 1;
    }
    assert_eq!(counts, [381, 52, 76, 12, 6]);
}

#[test]
#[ignore = "requires held OEM decoded 212U/213U 1.02 images"]
fn unified_startup_plan_preserves_checks_and_refuses_format_conversion() {
    use pioneer_optical::startup::checks::{Check, Checks, Error};
    let a = Checks::discover(&image("212"), None);
    let b = Checks::discover(&image("213"), None);
    let plan = a.plan_to(a).unwrap();
    assert!(plan
        .target_checks()
        .iter()
        .any(|c| matches!(c, Check::PersistentBanks(Some(_)))));
    assert_eq!(plan.word_setting().value, 0xffff);
    assert!(!plan.word_setting().explicit);
    for (source, target) in [(a, b), (b, a)] {
        assert!(matches!(
            source.plan_to(target),
            Err(Error::Banks(bank::Error::ConversionRequired { .. }))
        ));
    }
    let unknown = Checks::discover(&[], None);
    assert_eq!(
        unknown.plan_to(a),
        Err(Error::Banks(bank::Error::UnknownInstalled))
    );
    assert_eq!(
        a.plan_to(unknown),
        Err(Error::Banks(bank::Error::UnknownTarget))
    );
}
