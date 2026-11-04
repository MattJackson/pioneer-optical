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
        assert!(bank::analyze(&unbound).is_none());
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

fn customer_image(model: &str) -> Vec<u8> {
    let root = std::env::var("PIONEER_SETTINGS_HOARD")
        .expect("set PIONEER_SETTINGS_HOARD to the retained OEM corpus");
    let (path, encoded_hash, decoded_hash) = match model {
        "212" => (
            "oem/pioneer/sat/8F01/ID83/1.01/normal/9201ee0287df6e6b2acbd26f79414c75d4ed08745a0f3c4bae0908880c86567a.enc",
            "9201ee0287df6e6b2acbd26f79414c75d4ed08745a0f3c4bae0908880c86567a",
            "f03d176de05bc788d16b5fa4c44024a07c836006863d13ee5226ce1047939ac9",
        ),
        "213" => (
            "oem/pioneer/sat/9201/ID58/1.02/normal/c45156efa3e19f3092cdd57e68a6d4e71cb2d7fa54509cb56a0c470a8fe65fc4.enc",
            "c45156efa3e19f3092cdd57e68a6d4e71cb2d7fa54509cb56a0c470a8fe65fc4",
            "4b0192fdc3050b222eee0fe0faac7675887d7873af47dbc6674f80a2b7916fd8",
        ),
        _ => panic!("unknown customer image"),
    };
    let encoded = std::fs::read(std::path::Path::new(&root).join(path)).unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(&encoded)), encoded_hash);
    let bytes = pioneer_optical::envelope::Envelope::load(&encoded)
        .unwrap()
        .image;
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), decoded_hash);
    bytes
}

#[test]
#[ignore = "requires PIONEER_SETTINGS_HOARD with hash-locked customer OEM envelopes"]
fn customer_both_bank_addresses_and_capacity_cases_are_code_derived() {
    for (model, magic, compact, extended, stride) in [
        (
            "212",
            0xfedc4321,
            [0x5efffa, 0x5ffffa],
            [0x7dfffa, 0x7efffa],
            0x10000,
        ),
        (
            "213",
            0xfedc4322,
            [0x5f3ffa, 0x5ffffa],
            [0x7dbffa, 0x7e7ffa],
            0xc000,
        ),
    ] {
        let bytes = customer_image(model);
        let guard = bank::discover(&bytes).unwrap();
        let layout = guard.layout(&bytes).unwrap();
        assert_eq!(guard.magic, magic);
        assert_eq!(guard.stride(), Some(stride));
        assert_eq!(layout.when_one.markers, compact);
        assert_eq!(layout.otherwise.markers, extended);
        assert_eq!(
            bank::analyze_pair(&bytes, None),
            Some(bank::Storage::Versioned(bank::Contract {
                magic,
                addresses: bank::Addresses::Capacity {
                    when_one: compact,
                    otherwise: extended
                },
                validation: bank::Validation::RejectMismatch
            }))
        );
    }
}

#[test]
#[ignore = "requires PIONEER_SETTINGS_HOARD with hash-locked customer OEM envelopes"]
fn customer_guard_rejects_changed_accept_branches_operands_and_loader_effects() {
    for model in ["212", "213"] {
        let bytes = customer_image(model);
        let guard = bank::discover(&bytes).unwrap();
        let at = (guard.validator - 0x410000) as usize;
        // Independent semantic mutation sites: both acceptance branches,
        // initialization writes, matching operands, and rejection call.
        for offset in [0x7b, 0x89, 0x26, 0x82, 0x66, 0x5c, 0x72, 0x8a] {
            let mut changed = bytes.clone();
            changed[at + offset] ^= 2;
            assert!(
                bank::discover(&changed).is_none(),
                "{model} mutation {offset:x}"
            );
        }
        for (offset, value) in [
            (0xe, u32::MAX),
            (0x34, u32::MAX),
            (0x46, guard.marker_offsets[0]),
        ] {
            let mut changed = bytes.clone();
            changed[at + offset..at + offset + 4].copy_from_slice(&value.to_be_bytes());
            assert!(
                bank::discover(&changed).is_none(),
                "{model} operand {offset:x}"
            );
        }
        let helper = (guard.reject_helper - 0x410000) as usize;
        for offset in [0, 6, 12, 2, 8] {
            let mut changed = bytes.clone();
            changed[helper + offset] ^= 2;
            assert!(
                bank::discover(&changed).is_none(),
                "{model} helper {offset:x}"
            );
        }
        for call_at in [helper + 2, helper + 8] {
            let wrapper = u32::from_be_bytes([
                0,
                bytes[call_at + 1],
                bytes[call_at + 2],
                bytes[call_at + 3],
            ]) as usize
                - 0x410000;
            let mut changed = bytes.clone();
            changed[wrapper + 3] ^= 2;
            assert!(bank::discover(&changed).is_none());
        }
        let mut duplicate = bytes.clone();
        duplicate.extend_from_slice(&bytes[at..at + 0x96]);
        assert!(bank::discover(&duplicate).is_none());
    }
}

#[test]
#[ignore = "requires PIONEER_SETTINGS_HOARD with hash-locked customer OEM envelopes"]
fn customer_capacity_layout_rejects_unbound_ambiguous_and_overflowing_geometry() {
    for model in ["212", "213"] {
        let bytes = customer_image(model);
        let guard = bank::discover(&bytes).unwrap();
        let layout = guard.layout(&bytes).unwrap();
        let at = (layout.calculation - 0x410000) as usize;
        let compare = if model == "212" { 18 } else { 22 };
        for offset in [
            4,
            10,
            compare,
            compare + 6,
            compare + 14,
            compare + 22,
            compare + 26,
            compare + 30,
        ] {
            let mut changed = bytes.clone();
            changed[at + offset] ^= 2;
            assert!(
                guard.layout(&changed).is_none(),
                "{model} layout {offset:x}"
            );
        }
        for offset in [compare + 10, compare + 18] {
            let mut changed = bytes.clone();
            changed[at + offset..at + offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(guard.layout(&changed).is_none());
        }
        let mut unbound = bytes.clone();
        let mut calls = 0;
        for p in (0..bytes.len() - 8).step_by(2) {
            if bytes[p] == 0x5e
                && bytes[p + 1..p + 4] == layout.calculation.to_be_bytes()[1..]
                && bytes[p + 4] == 0x5e
                && bytes[p + 5..p + 8] == guard.validator.to_be_bytes()[1..]
            {
                unbound[p] = 0;
                calls += 1;
            }
        }
        assert!(calls > 0);
        assert!(guard.layout(&unbound).is_none());
        assert!(bank::analyze(&unbound).is_none());
        let mut duplicate = bytes.clone();
        let moved = duplicate.len();
        duplicate.extend_from_slice(&bytes[at..at + compare + 32]);
        let addr = 0x410000 + moved as u32;
        duplicate.push(0x5e);
        duplicate.extend_from_slice(&addr.to_be_bytes()[1..]);
        duplicate.push(0x5e);
        duplicate.extend_from_slice(&guard.validator.to_be_bytes()[1..]);
        assert!(guard.layout(&duplicate).is_none());
    }
}

#[test]
#[ignore = "requires PIONEER_SETTINGS_HOARD with hash-locked legacy OEM envelopes"]
fn customer_policy_does_not_reclassify_legacy_bank_formats_as_capacity_banks() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_SETTINGS_HOARD").unwrap());
    let expected_state = bank::Storage::StateHeaders {
        headers: [[0x7dfff6, 0x7dfffa], [0x7efff6, 0x7efffa]],
        sequences: [0x7dfffe, 0x7efffe],
        status: [0x7d8000, 0x7e8000],
    };
    let expected_fixed = bank::Storage::Versioned(bank::Contract {
        magic: 0xfedc4321,
        addresses: bank::Addresses::Fixed([0x7dfffa, 0x7efffa]),
        validation: bank::Validation::RejectMismatch,
    });
    for (directory, hash, expected) in [
        (
            "1005/GENERAL/1.10",
            "9293eb86cdade4392b98a34ce3cb0526e3d759b6e2d8c38eeb1e7245377b96f1",
            expected_state,
        ),
        (
            "1010/GENERAL/0.05e",
            "c9863dfa278034a908dc397e787c35caf1310fccbc96371c56f2387e86e19fda",
            expected_fixed,
        ),
    ] {
        let encoded =
            std::fs::read(root.join(format!("oem/pioneer/sat/{directory}/normal/{hash}.enc")))
                .unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&encoded)), hash);
        let normal = pioneer_optical::envelope::Envelope::load(&encoded)
            .unwrap()
            .image;
        assert_eq!(bank::discover(&normal), None);
        assert_eq!(bank::analyze_pair(&normal, None), Some(expected));
        assert_eq!(bank::check(Some(expected), Some(expected)), Ok(()));
        // Sharing the 212's magic or final header addresses does not establish
        // equality with its capacity-dependent storage contract.
        let customer = bank::analyze_pair(&customer_image("212"), None).unwrap();
        assert!(matches!(
            bank::check(Some(expected), Some(customer)),
            Err(bank::Error::ConversionRequired { .. })
        ));
    }
}

#[test]
#[ignore = "requires PIONEER_SETTINGS_HOARD with hash-locked customer OEM envelopes"]
fn customer_212u_and_213u_banks_refuse_in_both_directions_under_every_policy() {
    use pioneer_optical::startup::checks::{Checks, Error, Policy};
    let (u212, u213) = (customer_image("212"), customer_image("213"));
    for (installed, target) in [(&u212, &u213), (&u213, &u212)] {
        let (installed, target) = (
            Checks::discover(installed, None),
            Checks::discover(target, None),
        );
        for policy in [Policy::CompatibleBanks, Policy::ExplicitCrossflash] {
            assert!(matches!(
                installed.plan_to_with_policy(target, policy),
                Err(Error::Banks(bank::Error::ConversionRequired { .. }))
            ));
        }
    }
}
