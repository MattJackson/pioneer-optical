//! Optional local native-layout corpus checks. Firmware is not redistributed.
#![cfg(feature = "image")]

use pioneer_optical::image::layout::{
    discover_h8, discover_h8_component, discover_m32c_records, discover_m32c_serial,
    discover_m7900_ata, discover_m7900_scsi, discover_v850_bus, discover_v850_native, Observation,
    ParameterLayout, SerialSelection, Unresolved, WordEncoding,
};

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT, PIONEER_NORMAL_CORPUS and PIONEER_V850_NATIVE"]
fn v850_requires_both_native_backends_and_preserves_unresolved_cases() {
    let audit = std::path::PathBuf::from(
        std::env::var("PIONEER_LAYOUT_AUDIT").expect("PIONEER_LAYOUT_AUDIT"),
    );
    let corpus = std::path::PathBuf::from(
        std::env::var("PIONEER_NORMAL_CORPUS").expect("PIONEER_NORMAL_CORPUS"),
    );
    let native = std::path::PathBuf::from(
        std::env::var("PIONEER_V850_NATIVE").expect("PIONEER_V850_NATIVE"),
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("all-platform-layouts.json")).unwrap())
            .unwrap();
    let evidence: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("v850-header-binding.json")).unwrap())
            .unwrap();
    let by: std::collections::BTreeMap<_, _> = evidence["images"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["component"].as_str().unwrap(), r))
        .collect();
    assert_eq!(by.len(), 71);
    let mut known = 0;
    let mut resident_required = 0;
    for (component, obs) in manifest["images"].as_object().unwrap() {
        let row = by.get(component.as_str());
        let body = std::fs::read(if row.is_some() {
            native.join(format!("{component}.bin"))
        } else {
            corpus.join(format!("{component}.bin"))
        })
        .unwrap();
        let kernel = row
            .and_then(|r| r["kernel_backend"]["component"].as_str())
            .map(|k| std::fs::read(native.join(format!("{k}.bin"))).unwrap());
        let result = discover_v850_native(&body, kernel.as_deref());
        if let Some(row) = row {
            let stored = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
            let stored_kernel = row["kernel_backend"]["component"].as_str().map(|k| {
                std::fs::read(
                    corpus
                        .parent()
                        .unwrap()
                        .join("kernel")
                        .join(format!("{k}.bin")),
                )
                .unwrap()
            });
            let decoded_result = discover_v850_bus(&stored, stored_kernel.as_deref());
            match (&result, &decoded_result) {
                (Observation::Known(_), Observation::Known(_)) => {
                    assert_eq!(result.compare(&decoded_result), Some(true))
                }
                (Observation::Unresolved(a), Observation::Unresolved(b)) => assert_eq!(a, b),
                _ => panic!("bus decoder changed recognition for {component}"),
            }
        }
        let expected = obs["layout"].as_str() == Some("v850_three_regions");
        assert_eq!(
            matches!(result, Observation::Known(_)),
            expected,
            "unexpected V850 result for {component}: {result:?}"
        );
        if let Observation::Known(ParameterLayout::FlashRecords {
            regions,
            domains,
            encoding,
        }) = result
        {
            assert_eq!(
                regions
                    .iter()
                    .map(|r| (r.address, r.record_bytes, r.record_count, r.header_bytes))
                    .collect::<Vec<_>>(),
                vec![
                    (0x1fa000, 320, 8, 16),
                    (0x1faa20, 160, 9, 18),
                    (0x1fb000, 64, 62, 124)
                ]
            );
            assert_eq!(encoding, WordEncoding::DirectOrBusPermutedLittleEndian);
            assert_eq!((domains[0].first, domains[0].last), (0x160, 0x1ff));
            known += 1;
            assert!(matches!(
                discover_v850_native(&body, None),
                Observation::Unresolved(Unresolved::ResidentCodeRequired(_))
            ));
        } else if row.is_some() {
            assert!(matches!(
                result,
                Observation::Unresolved(Unresolved::ResidentCodeRequired(_))
            ));
            resident_required += 1;
        }
    }
    assert_eq!((known, resident_required), (49, 22));
}

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn h8_reader_graphs_match_all_proven_primary_layouts() {
    let audit = std::env::var("PIONEER_LAYOUT_AUDIT").expect("PIONEER_LAYOUT_AUDIT");
    let corpus = std::path::PathBuf::from(
        std::env::var("PIONEER_NORMAL_CORPUS").expect("PIONEER_NORMAL_CORPUS"),
    );
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::path::Path::new(&audit).join("h8-reader-graphs.json")).unwrap(),
    )
    .unwrap();
    let rows = manifest["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 527);
    for row in rows {
        let component = row["component"].as_str().unwrap();
        let kernel = row["kernel"].as_str();
        let path = if let Some(kernel) = kernel {
            corpus
                .parent()
                .unwrap()
                .join("kernel")
                .join(format!("{kernel}.bin"))
        } else {
            corpus.join(format!("{component}.bin"))
        };
        let body = std::fs::read(path).unwrap();
        let result =
            discover_h8_component(&body, if kernel.is_some() { 0x400000 } else { 0x410000 });
        let Observation::Known(ParameterLayout::FlashRecords {
            regions, domains, ..
        }) = result
        else {
            panic!("missing H8 layout for {component}: {result:?}")
        };
        assert_eq!(regions.len(), 1);
        assert_eq!(domains.len(), 1);
        let expected =
            u32::from_str_radix(row["base"].as_str().unwrap().trim_start_matches("0x"), 16)
                .unwrap();
        assert_eq!(regions[0].address, expected, "{component}");
        assert_eq!(
            u64::from(regions[0].record_count),
            row["records"].as_u64().unwrap()
        );
        assert_eq!(regions[0].record_bytes, 320);
        assert_eq!(domains[0].first, 0);
        assert_eq!(domains[0].last, 159);
    }
}

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn h8_layout_reader_rejects_other_architectures_and_missing_resident_code() {
    let audit = std::path::PathBuf::from(
        std::env::var("PIONEER_LAYOUT_AUDIT").expect("PIONEER_LAYOUT_AUDIT"),
    );
    let corpus = std::path::PathBuf::from(
        std::env::var("PIONEER_NORMAL_CORPUS").expect("PIONEER_NORMAL_CORPUS"),
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("all-platform-layouts.json")).unwrap())
            .unwrap();
    let graphs: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("h8-reader-graphs.json")).unwrap())
            .unwrap();
    let kernels: std::collections::BTreeMap<_, _> = graphs["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| {
            r["kernel"]
                .as_str()
                .map(|k| (r["component"].as_str().unwrap(), k))
        })
        .collect();
    assert_eq!(kernels.len(), 7);
    let mut recognized = 0;
    let rows = manifest["images"].as_object().unwrap();
    assert_eq!(rows.len(), 722);
    for (component, row) in rows {
        let kernel = kernels.get(component.as_str());
        let path = if let Some(kernel) = kernel {
            corpus
                .parent()
                .unwrap()
                .join("kernel")
                .join(format!("{kernel}.bin"))
        } else {
            corpus.join(format!("{component}.bin"))
        };
        let component_body = std::fs::read(path).unwrap();
        let result = discover_h8_component(
            &component_body,
            if kernel.is_some() { 0x400000 } else { 0x410000 },
        );
        let normal = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let combined = discover_h8(&normal, kernel.map(|_| component_body.as_slice()));
        if matches!(result, Observation::Known(_)) {
            assert_eq!(
                result.compare(&combined),
                Some(true),
                "combined reader {component}: {combined:?}"
            );
        } else {
            assert!(!matches!(combined, Observation::Known(_)), "{component}");
        }
        if kernel.is_some() {
            assert!(
                matches!(
                    discover_h8(&normal, None),
                    Observation::Unresolved(Unresolved::ResidentCodeRequired(_))
                ),
                "{component}"
            );
        }
        let expected = row["layout"].as_str().is_some_and(|name| {
            manifest["contracts"][name][0].as_str() == Some("persistent_primary_parameters")
        });
        assert_eq!(
            matches!(result, Observation::Known(_)),
            expected,
            "unexpected H8 recognition for {component}: {result:?}"
        );
        recognized += usize::from(expected);
    }
    assert_eq!(recognized, 527);
}

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn m32c_record_reader_matches_audited_corpus() {
    let audit = std::env::var("PIONEER_LAYOUT_AUDIT").expect("PIONEER_LAYOUT_AUDIT");
    let corpus = std::env::var("PIONEER_NORMAL_CORPUS").expect("PIONEER_NORMAL_CORPUS");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::path::Path::new(&audit).join("m32c-record-binding.json")).unwrap(),
    )
    .unwrap();
    let rows = manifest["images"].as_array().unwrap();
    assert_eq!(rows.len(), 85, "unexpected audited coverage");
    for row in rows {
        let component = row["component"].as_str().unwrap();
        let body =
            std::fs::read(std::path::Path::new(&corpus).join(format!("{component}.bin"))).unwrap();
        let Observation::Known(ParameterLayout::FlashRecords { regions, .. }) =
            discover_m32c_records(&body)
        else {
            panic!("missing native record layout for {component}");
        };
        let expected = row["regions"].as_array().unwrap();
        assert_eq!(regions.len(), expected.len());
        for (actual, expected) in regions.iter().zip(expected) {
            assert_eq!(
                u64::from(actual.address),
                expected["base"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(actual.record_bytes),
                expected["record_bytes"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(actual.record_count),
                expected["record_count"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(actual.header_bytes),
                expected["header_bytes"].as_u64().unwrap()
            );
            assert_eq!(
                actual.allocation_bytes.map(u64::from),
                expected["region_bytes"].as_u64()
            );
        }
    }
}

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn m7900_scsi_matches_two_images_and_exact_slot_map() {
    let audit = std::env::var("PIONEER_LAYOUT_AUDIT").expect("PIONEER_LAYOUT_AUDIT");
    let corpus = std::env::var("PIONEER_NORMAL_CORPUS").expect("PIONEER_NORMAL_CORPUS");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::path::Path::new(&audit).join("all-platform-layouts.json")).unwrap(),
    )
    .unwrap();
    let rows = manifest["images"].as_object().unwrap();
    assert_eq!(rows.len(), 722);
    let mut known = 0;
    for (component, observation) in rows {
        let body =
            std::fs::read(std::path::Path::new(&corpus).join(format!("{component}.bin"))).unwrap();
        let result = discover_m7900_scsi(&body, 0x3800);
        let expected = observation["layout"].as_str() == Some("scsi_serial_selected");
        assert_eq!(
            matches!(result, Observation::Known(_)),
            expected,
            "unexpected SCSI recognition for {component}"
        );
        if expected {
            assert_eq!(
                result.compare(&Observation::Known(ParameterLayout::SerialSelected {
                    address_bits: 10,
                    bases: [0x220, 0x260],
                    slots: [8, 10, 11, 9, 12, 0, 1, 2],
                    selection: SerialSelection::Header(0x256),
                    encoding: WordEncoding::SerialHighByteFirst
                })),
                Some(true)
            );
            known += 1;
        }
    }
    assert_eq!(known, 2);
}

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn m7900_ata_matches_seven_images_and_exact_fallback_words() {
    let audit = std::env::var("PIONEER_LAYOUT_AUDIT").expect("PIONEER_LAYOUT_AUDIT");
    let corpus = std::env::var("PIONEER_NORMAL_CORPUS").expect("PIONEER_NORMAL_CORPUS");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::path::Path::new(&audit).join("all-platform-layouts.json")).unwrap(),
    )
    .unwrap();
    let rows = manifest["images"].as_object().unwrap();
    assert_eq!(rows.len(), 722);
    let mut known = 0;
    for (component, observation) in rows {
        let body =
            std::fs::read(std::path::Path::new(&corpus).join(format!("{component}.bin"))).unwrap();
        let result = discover_m7900_ata(&body, 0x3800);
        let expected = observation["layout"].as_str() == Some("ata_serial_selected");
        assert_eq!(
            matches!(result, Observation::Known(_)),
            expected,
            "unexpected ATA recognition for {component}"
        );
        if expected {
            assert_eq!(
                result.compare(&Observation::Known(ParameterLayout::SerialSelected {
                    address_bits: 10,
                    bases: [0x220, 0x260],
                    slots: [8, 10, 11, 9, 12, 0, 1, 2],
                    selection: SerialSelection::FallbackWords([
                        0x240, 0x242, 0x243, 0x241, 0x246, 0x247, 0x245, 0x244
                    ]),
                    encoding: WordEncoding::SerialHighByteFirst
                })),
                Some(true)
            );
            known += 1;
        }
    }
    assert_eq!(known, 7);
}

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn m32c_reader_does_not_claim_other_native_layouts() {
    let audit = std::env::var("PIONEER_LAYOUT_AUDIT").expect("PIONEER_LAYOUT_AUDIT");
    let corpus = std::env::var("PIONEER_NORMAL_CORPUS").expect("PIONEER_NORMAL_CORPUS");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::path::Path::new(&audit).join("all-platform-layouts.json")).unwrap(),
    )
    .unwrap();
    let rows = manifest["images"].as_object().unwrap();
    assert_eq!(rows.len(), 722);
    let mut known = 0;
    for (component, observation) in rows {
        let body =
            std::fs::read(std::path::Path::new(&corpus).join(format!("{component}.bin"))).unwrap();
        let recognized = matches!(discover_m32c_records(&body), Observation::Known(_));
        let expected = matches!(
            observation["layout"].as_str(),
            Some("m32c_three_regions" | "m32c_two_regions")
        );
        assert_eq!(
            recognized, expected,
            "unexpected recognition for {component}"
        );
        known += usize::from(recognized);
    }
    assert_eq!(known, 86);
}

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn m32c_serial_matches_thirteen_images_without_cross_platform_false_positives() {
    let audit = std::env::var("PIONEER_LAYOUT_AUDIT").expect("PIONEER_LAYOUT_AUDIT");
    let corpus = std::env::var("PIONEER_NORMAL_CORPUS").expect("PIONEER_NORMAL_CORPUS");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::path::Path::new(&audit).join("all-platform-layouts.json")).unwrap(),
    )
    .unwrap();
    let rows = manifest["images"].as_object().unwrap();
    assert_eq!(rows.len(), 722);
    let mut known = 0;
    for (component, observation) in rows {
        let body =
            std::fs::read(std::path::Path::new(&corpus).join(format!("{component}.bin"))).unwrap();
        let result = discover_m32c_serial(&body, 0xf80000);
        let expected = observation["layout"].as_str() == Some("m32c_serial_mechanical");
        assert_eq!(
            matches!(result, Observation::Known(_)),
            expected,
            "unexpected serial recognition for {component}"
        );
        if expected {
            assert_eq!(
                result.compare(&Observation::Known(ParameterLayout::SerialRange {
                    address_bits: 10,
                    first_word: 0xc0,
                    word_count: 160,
                    encoding: WordEncoding::SerialHighByteFirst
                })),
                Some(true)
            );
            known += 1;
        }
    }
    assert_eq!(known, 13);
}

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn sat9_primary_only_changes_leave_secondary_word_on_the_wrong_record_region() {
    use pioneer_optical::image::layout::discover_h8_reader;
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let proof: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("h8-native-read-proof.json")).unwrap())
            .unwrap();
    let mut counts = [0, 0];
    for row in proof["rows"].as_array().unwrap().iter().filter(|r| {
        r["sat"].as_str().is_some_and(|s| s.starts_with("SAT 9"))
            && r["status"].as_str() == Some("native_reader_cases_passed")
    }) {
        let component = row["component"].as_str().unwrap();
        let mut normal = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(reader) = discover_h8_reader(&normal, None) else {
            panic!("complete resolver missing: {component}");
        };
        let ParameterLayout::FlashRecords { regions, .. } = &reader.layout else {
            panic!()
        };
        let primary = regions[0].address;
        let index = match primary {
            0x5984 => 0,
            0x9984 => 1,
            _ => panic!(),
        };
        let secondary = [0x4352u32, 0x8352][index];
        let span = &row["source_spans"][1];
        let cpu = u32::from_str_radix(span["cpu"].as_str().unwrap().trim_start_matches("0x"), 16)
            .unwrap();
        let start = (cpu - 0x410000) as usize;
        let end = start + span["length"].as_u64().unwrap() as usize;
        // The native branch is bounded by both comparisons of logical 0x01A0,
        // then assigns the region pointer before returning domain 0x01A0.
        let at = normal[start..end]
            .windows(24)
            .position(|w| {
                w[..5] == [0x79, 0x25, 1, 0xa0, 0x45]
                    && w[6..11] == [0x79, 0x25, 1, 0xa0, 0x42]
                    && w[12..14] == [0x7a, 0]
                    && w[18..] == [1, 0, 0x69, 0x90, 0x79, 0]
            })
            .map(|n| start + n)
            .expect(component);
        assert_eq!(
            u32::from_be_bytes(normal[at + 14..at + 18].try_into().unwrap()),
            secondary
        );
        assert_eq!(&normal[at + 24..at + 26], &[1, 0xa0]);
        // Construct exactly the proposed primary-only correction. The bound
        // reader accepts its three changed fields; the other logical domain
        // still points to its original region, 0x4000 away from required data.
        let other_primary = [0x9984u32, 0x5984][index];
        let old = primary.to_be_bytes();
        for offset in (34..normal.len() - 3).step_by(2) {
            if normal[offset - 2] == 0x7a && normal[offset..offset + 4] == old {
                normal[offset..offset + 4].copy_from_slice(&other_primary.to_be_bytes());
            }
        }
        let Observation::Known(changed) = discover_h8_reader(&normal, None) else {
            panic!("{component}")
        };
        let ParameterLayout::FlashRecords { regions, .. } = changed.layout else {
            panic!()
        };
        assert_eq!(regions[0].address, other_primary);
        assert_eq!(
            u32::from_be_bytes(normal[at + 14..at + 18].try_into().unwrap()),
            secondary
        );
        assert_ne!(secondary, [0x8352u32, 0x4352][index]);
        counts[index] += 1;
    }
    assert_eq!(counts, [29, 37]);
}

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn sat1_old_absolute_record_space_contains_new_normal_payload_for_every_image() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let proof: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("sat1-normal-primary-address-overlap.json")).unwrap(),
    )
    .unwrap();
    let rows = proof["images"].as_array().unwrap();
    assert_eq!(rows.len(), 64);
    for row in rows {
        let component = row["component"].as_str().unwrap();
        let normal = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let collision = &normal[(0x5e0000 - 0x410000)..(0x5e3250 - 0x410000)];
        let occupied = collision.iter().filter(|&&b| b != 0xff).count();
        assert!(occupied > 0, "{component}");
        assert_eq!(
            occupied as u64,
            row["non_ff_in_old_primary"].as_u64().unwrap()
        );
    }
}
