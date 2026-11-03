//! Combined SAT identity projections against the signed-off matrix contracts.
#![cfg(feature = "image")]
use pioneer_optical::image::matrix::{SatEvidence, SatPlatform};
use std::collections::{BTreeMap, BTreeSet};

#[test]
#[ignore = "requires PIONEER_PHASE_AUDIT, PIONEER_LAYOUT_AUDIT, PIONEER_ATA_AUDIT and PIONEER_NORMAL_CORPUS"]
fn combined_ata_keys_match_corrected_html_partitions_and_require_exact_kernel() {
    use pioneer_optical::image::matrix::AtaEvidence;
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_AUDIT").unwrap());
    let layout = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let original = std::path::PathBuf::from(std::env::var("PIONEER_ATA_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let read = |path: std::path::PathBuf| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    };
    let expected = read(layout.join("after-v850-input-keys.json"));
    let by: BTreeMap<_, _> = expected
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["sha"].as_str().unwrap(), r))
        .collect();
    let m32c = read(original.join("m32c/component-inventory.json"));
    let v850 = read(audit.join("native-replay/v850/host-signature-contracts.json"));
    let mut observations = Vec::new();
    for r in m32c.as_array().unwrap() {
        let component = r["component"].as_str().unwrap();
        let base = u32::from_str_radix(
            r["base_candidate"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let evidence = AtaEvidence::discover_m32c(&raw, base);
        assert_eq!(
            pioneer_optical::image::family_with_context(&raw, "ATA 0000", None),
            evidence.as_is_key().and_then(|k| k.family()),
            "{component}"
        );
        observations.push((component, evidence));
    }
    for r in v850.as_array().unwrap() {
        let component = r["sha"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let kernel = r["kernel"]["sha"].as_str().map(|s| {
            std::fs::read(
                corpus
                    .parent()
                    .unwrap()
                    .join("kernel")
                    .join(format!("{s}.bin")),
            )
            .unwrap()
        });
        let evidence = AtaEvidence::discover_v850_bus(&raw, kernel.as_deref()).unwrap();
        assert_eq!(
            pioneer_optical::image::family_with_context(&raw, "ATA 0000", kernel.as_deref()),
            evidence.as_is_key().and_then(|k| k.family()),
            "{component}"
        );
        observations.push((component, evidence));
        assert!(
            AtaEvidence::discover_v850_bus(&raw, None)
                .unwrap()
                .as_is_key()
                .is_none(),
            "{component}"
        );
    }
    let (mut known, mut missing) = (0, 0);
    let mut forward = BTreeMap::new();
    let mut backward = BTreeMap::new();
    let mut digests = BTreeMap::new();
    for (component, evidence) in observations {
        let key = evidence.as_is_key();
        assert_eq!(
            key,
            evidence.candidate_key(),
            "ATA phase normalization unsupported"
        );
        let expected = by[component]["candidate"].as_str();
        assert_eq!(
            key.is_some(),
            expected.is_some(),
            "{component}: {evidence:?}"
        );
        let Some(key) = key else {
            missing += 1;
            continue;
        };
        known += 1;
        let actual = format!("{:02x?}", key.canonical_bytes().unwrap());
        if let Some(previous) = digests.insert(key.family().unwrap(), actual.clone()) {
            assert_eq!(previous, actual, "digest collision {component}");
        }
        let expected = expected.unwrap().to_owned();
        if let Some(previous) = forward.insert(expected.clone(), actual.clone()) {
            assert_eq!(previous, actual, "unexpected split {component}");
        }
        if let Some(previous) = backward.insert(actual, expected.clone()) {
            assert_eq!(previous, expected, "unexpected merge {component}");
        }
    }
    assert_eq!((known, missing), (148, 22));
}
#[test]
#[ignore = "requires PIONEER_PHASE_AUDIT, PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn combined_sat_keys_preserve_every_as_is_and_candidate_partition() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_AUDIT").unwrap());
    let layouts = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let serialization: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("serialization-contract.json")).unwrap())
            .unwrap();
    let layout: serde_json::Value =
        serde_json::from_slice(&std::fs::read(layouts.join("all-platform-layouts.json")).unwrap())
            .unwrap();
    let graphs: serde_json::Value =
        serde_json::from_slice(&std::fs::read(layouts.join("h8-reader-graphs.json")).unwrap())
            .unwrap();
    let kernels: BTreeMap<_, _> = graphs["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| {
            r["kernel"]
                .as_str()
                .map(|k| (r["component"].as_str().unwrap(), k))
        })
        .collect();
    let mut expected_to_actual = [BTreeMap::new(), BTreeMap::new()];
    let mut actual_to_expected = [BTreeMap::new(), BTreeMap::new()];
    let mut counts = BTreeMap::new();
    let mut missing = BTreeSet::new();
    let mut digests = BTreeMap::new();
    let mut known = 0;
    for row in serialization["records"].as_array().unwrap() {
        let platform = match row["platform"].as_str().unwrap() {
            "SAT 1xxx" => SatPlatform::Sat1,
            "SAT 8xxx" => SatPlatform::Sat8,
            "SAT 9xxx" => SatPlatform::Sat9,
            _ => continue,
        };
        let component = row["component"].as_str().unwrap();
        let normal = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let kernel = kernels.get(component).map(|k| {
            std::fs::read(
                corpus
                    .parent()
                    .unwrap()
                    .join("kernel")
                    .join(format!("{k}.bin")),
            )
            .unwrap()
        });
        let evidence = SatEvidence::discover(platform, &normal, kernel.as_deref());
        let hardware = match platform {
            SatPlatform::Sat1 => "SAT 1000",
            SatPlatform::Sat8 => "SAT 8000",
            SatPlatform::Sat9 => "SAT 9000",
        };
        assert_eq!(
            pioneer_optical::image::family_with_context(&normal, hardware, kernel.as_deref()),
            evidence.as_is_key().and_then(|k| k.family()),
            "{component}"
        );
        let layout_name = layout["images"][component]["layout"].as_str();
        for (i, key) in [evidence.as_is_key(), evidence.candidate_key()]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                key.is_some(),
                layout_name.is_some(),
                "{component}: {evidence:?}"
            );
            let Some(key) = key else {
                missing.insert(component.to_owned());
                continue;
            };
            let mut expected = row["as_is_payload"].clone();
            let fields = expected[2].as_array_mut().unwrap();
            if i == 1 && platform != SatPlatform::Sat1 {
                fields.retain(|f| f[0] != 4);
            }
            fields.push(serde_json::json!([
                5,
                layout["contracts"][layout_name.unwrap()]
            ]));
            let expected = expected.to_string();
            let actual = format!("{:02x?}", key.canonical_bytes().unwrap());
            if let Some(previous) = digests.insert(key.family().unwrap(), actual.clone()) {
                assert_eq!(previous, actual, "digest collision {component}");
            }
            if let Some(previous) = expected_to_actual[i].insert(expected.clone(), actual.clone()) {
                assert_eq!(previous, actual, "matrix group split at {component}");
            }
            if let Some(previous) = actual_to_expected[i].insert(actual.clone(), expected.clone()) {
                assert_eq!(previous, expected, "matrix groups merged at {component}");
            }
            if i == 1 {
                counts
                    .entry(row["platform"].as_str().unwrap().to_owned())
                    .or_insert_with(BTreeSet::new)
                    .insert(actual);
            }
        }
        known += usize::from(layout_name.is_some());
    }
    assert_eq!(known, 527);
    assert_eq!(missing.len(), 3);
    assert_eq!(counts["SAT 8xxx"].len(), 10);
    assert_eq!(counts["SAT 9xxx"].len(), 3);
}
