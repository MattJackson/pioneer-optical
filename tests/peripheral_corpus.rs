//! ATA native interfaces against the independently disassembled audit.
#![cfg(feature = "image")]
#![cfg(feature = "internals")]
use pioneer_optical::image::{
    layout::Observation,
    peripheral::{self, Interface},
    phase::Assignment,
};

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT, PIONEER_ATA_AUDIT and PIONEER_NORMAL_CORPUS"]
fn v850_key_state_machines_match_native_reconciliation_and_reject_broken_consumers() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let native =
        std::path::PathBuf::from(std::env::var("PIONEER_ATA_AUDIT").unwrap()).join("v850/native");
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let contracts: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("v850-input-contracts.json")).unwrap())
            .unwrap();
    let functions: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("v850-input-function-binding.json")).unwrap(),
    )
    .unwrap();
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for row in functions.as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(native.join(format!("{component}.bin"))).unwrap();
        let actual = peripheral::v850_input_native(&raw);
        let Observation::Known(actual) = actual else {
            panic!("{component}: {actual:?}");
        };
        let stored = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        assert_eq!(
            Observation::Known(actual).compare(&peripheral::v850_input_bus(&stored)),
            Some(true)
        );
        let label = match actual {
            peripheral::KeyAlgorithm::CounterLow => "counter_low",
            peripheral::KeyAlgorithm::TimerLow => "timer_low",
            peripheral::KeyAlgorithm::HighFallingSelected => "high_falling_selected",
            peripheral::KeyAlgorithm::LowRisingSelected => "low_rising_selected",
            peripheral::KeyAlgorithm::LowRisingMode => "low_rising_mode",
        };
        assert_eq!(
            label,
            contracts["images"][component]["contract"].as_str().unwrap(),
            "{component}"
        );
        *counts.entry(label.to_owned()).or_default() += 1;
        let mut bad = raw.clone();
        bad[row["start"].as_u64().unwrap() as usize] ^= 1;
        assert!(
            matches!(
                peripheral::v850_input_native(&bad),
                Observation::Unresolved(_)
            ),
            "{component}: broken function"
        );
        let mut bad = raw.clone();
        let at = row["diagnostic"].as_u64().unwrap() as usize;
        let ptr = u32::from_le_bytes(bad[at + 2..at + 6].try_into().unwrap()) as usize - 0x10000;
        bad[ptr] ^= 1;
        assert!(
            matches!(
                peripheral::v850_input_native(&bad),
                Observation::Unresolved(_)
            ),
            "{component}: broken diagnostic"
        );
    }
    assert_eq!(
        counts,
        std::collections::BTreeMap::from([
            ("counter_low".into(), 25),
            ("timer_low".into(), 35),
            ("high_falling_selected".into(), 4),
            ("low_rising_selected".into(), 5),
            ("low_rising_mode".into(), 2)
        ])
    );
    let all: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("all-platform-layouts.json")).unwrap())
            .unwrap();
    let mut rejected = 0;
    for component in all["images"].as_object().unwrap().keys() {
        if contracts["images"].get(component).is_some() {
            continue;
        }
        let stored = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        assert!(
            !matches!(peripheral::v850_input_bus(&stored), Observation::Known(_)),
            "{component}: other architecture"
        );
        rejected += 1;
    }
    assert_eq!(rejected, 651);
}
#[test]
#[ignore = "requires PIONEER_PHASE_AUDIT, PIONEER_ATA_AUDIT and PIONEER_NORMAL_CORPUS"]
fn all_m32c_host_and_phase_contracts_match() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_AUDIT").unwrap());
    let original = std::path::PathBuf::from(std::env::var("PIONEER_ATA_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let phases: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("native-replay/m32c/phase-contracts.json")).unwrap(),
    )
    .unwrap();
    let hosts: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("native-replay/m32c/host-signature-contracts.json")).unwrap(),
    )
    .unwrap();
    let inventory: serde_json::Value = serde_json::from_slice(
        &std::fs::read(original.join("m32c/component-inventory.json")).unwrap(),
    )
    .unwrap();
    let bases: std::collections::BTreeMap<_, _> = inventory
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["component"].as_str().unwrap(),
                u32::from_str_radix(
                    r["base_candidate"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                    16,
                )
                .unwrap(),
            )
        })
        .collect();
    let host_by: std::collections::BTreeMap<_, _> = hosts["images"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["component"].as_str().unwrap(), r))
        .collect();
    let input_contracts: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("value-contracts.json")).unwrap())
            .unwrap();
    let input_by: std::collections::BTreeMap<_, _> = input_contracts
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["platform"] == "ATA" && r["field_index"] == 3)
        .flat_map(|r| {
            r["components"]
                .as_array()
                .unwrap()
                .iter()
                .map(move |c| (c.as_str().unwrap(), &r["typed_value"]))
        })
        .collect();
    let loading: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("native-replay/m32c/loading-limit-contracts.json")).unwrap(),
    )
    .unwrap();
    let loading_by: std::collections::BTreeMap<_, _> = loading["images"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["component"].as_str().unwrap(), r))
        .collect();
    let mut count = 0;
    for row in phases["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let phase = peripheral::m32c_phase(&raw, bases[component]);
        let Observation::Known(phase) = phase else {
            panic!("{component}: {phase:?}");
        };
        assert_eq!(
            phase.assignment,
            if row["phase_order"] == 0 {
                Assignment::Direct
            } else {
                Assignment::Swapped
            },
            "{component}"
        );
        let label = match phase.interface {
            Interface::Direct8 { channels: [a, b] } => format!("direct 8-bit pair 0x{a:X}/0x{b:X}"),
            Interface::Indexed16 { window, channels } => {
                assert_eq!(channels, [0x8e, 0x8f]);
                format!("indexed 16-bit pair 0x{window:X}")
            }
        };
        assert_eq!(
            label.to_lowercase(),
            row["interface"].as_str().unwrap().to_lowercase(),
            "{component}"
        );
        let host = peripheral::m32c_host(&raw);
        let Observation::Known(host) = host else {
            panic!("{component}: {host:?}");
        };
        assert_eq!(
            format!("M32C host 0x{:X}", host.coordinate),
            host_by[component]["host_interface"].as_str().unwrap(),
            "{component}"
        );
        let registers = &host_by[component]["evidence"][0]["registers"];
        for (name, value) in [
            ("byte_count_low", host.signature_low),
            ("byte_count_high", host.signature_high),
            ("sector_count_or_interrupt_reason", host.initial_one[0]),
            ("sector_number_or_lba_low", host.initial_one[1]),
        ] {
            assert_eq!(
                value,
                u32::from_str_radix(
                    registers[name].as_str().unwrap().trim_start_matches("0x"),
                    16
                )
                .unwrap(),
                "{component}"
            );
        }
        let input = peripheral::m32c_input(&raw, bases[component]);
        let Observation::Known(input) = input else {
            panic!("{component}: {input:?}");
        };
        let expected = input_by[component];
        match input {
            peripheral::Input::LoadingLimits {
                address,
                closed_bit,
                opened_bit,
                active,
                open_first,
            } => {
                assert_eq!(expected["kind"], "loading_limit_inputs");
                assert_eq!(
                    u64::from(address),
                    expected["address_u32"].as_u64().unwrap()
                );
                assert_eq!(
                    u64::from(closed_bit),
                    expected["closed_bit_u8"].as_u64().unwrap()
                );
                assert_eq!(
                    u64::from(opened_bit),
                    expected["open_bit_u8"].as_u64().unwrap()
                );
                assert!(!active && open_first);
            }
            peripheral::Input::KeyEvent {
                address,
                mask,
                required,
            } => {
                assert_eq!(expected["kind"], "open_key_input_projection");
                assert_eq!(
                    u64::from(address),
                    expected["address_u32"].as_u64().unwrap()
                );
                assert_eq!(u64::from(mask), expected["mask_u8"].as_u64().unwrap());
                assert_eq!(
                    u64::from(required),
                    expected["required_masked_value_u8"].as_u64().unwrap()
                );
            }
        }
        if let Some(loading) = loading_by.get(component) {
            for name in [
                "startup_selection",
                "closed_arrival_and_stability",
                "open_arrival_and_stability",
            ] {
                let offset = usize::from_str_radix(
                    loading["evidence"][name]["file_offset"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                    16,
                )
                .unwrap();
                let mut altered = raw.clone();
                altered[offset] ^= 1;
                assert!(
                    !matches!(
                        peripheral::m32c_input(&altered, bases[component]),
                        Observation::Known(_)
                    ),
                    "unbound loading consumer {component} {name}"
                );
            }
        }
        if let Some(bus) = row.get("bus_evidence") {
            let offset = usize::from_str_radix(
                bus["file_offset"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap();
            let mut altered = raw.clone();
            altered[offset] ^= 1;
            assert!(
                !matches!(
                    peripheral::m32c_phase(&altered, bases[component]),
                    Observation::Known(_)
                ),
                "unbound indexed bus {component}"
            );
        }
        count += 1;
    }
    assert_eq!(count, 99);
}

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT, PIONEER_ATA_AUDIT and PIONEER_NORMAL_CORPUS"]
fn m32c_recognizers_reject_other_architectures_in_full_corpus() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let original = std::path::PathBuf::from(std::env::var("PIONEER_ATA_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let inventory: serde_json::Value = serde_json::from_slice(
        &std::fs::read(original.join("m32c/component-inventory.json")).unwrap(),
    )
    .unwrap();
    let all: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("all-platform-layouts.json")).unwrap())
            .unwrap();
    let m32c: std::collections::BTreeSet<_> = inventory
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["component"].as_str().unwrap())
        .collect();
    let mut count = 0;
    for component in all["images"].as_object().unwrap().keys() {
        if m32c.contains(component.as_str()) {
            continue;
        }
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        assert!(
            !matches!(peripheral::m32c_host(&raw), Observation::Known(_)),
            "{component}"
        );
        for base in [0xf40000, 0xf80000] {
            assert!(
                !matches!(peripheral::m32c_input(&raw, base), Observation::Known(_)),
                "{component}"
            );
            assert!(
                !matches!(peripheral::m32c_phase(&raw, base), Observation::Known(_)),
                "{component}"
            );
        }
        count += 1;
    }
    assert_eq!(count, 623);
}

#[test]
#[ignore = "requires PIONEER_PHASE_AUDIT, PIONEER_ATA_AUDIT and PIONEER_NORMAL_CORPUS"]
fn v850_host_coordinates_require_exact_reset_binding_and_match_bus_decode() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_AUDIT").unwrap());
    let original = std::path::PathBuf::from(std::env::var("PIONEER_ATA_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let rows: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("native-replay/v850/host-signature-contracts.json")).unwrap(),
    )
    .unwrap();
    let mut known = 0;
    let mut missing = 0;
    let phases: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("native-replay/v850/phase-contracts.json")).unwrap(),
    )
    .unwrap();
    let phase_by: std::collections::BTreeMap<_, _> = phases
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["sha"].as_str().unwrap(), r))
        .collect();
    for row in rows.as_array().unwrap() {
        let component = row["sha"].as_str().unwrap();
        let raw = std::fs::read(
            original
                .join("v850/native")
                .join(format!("{component}.bin")),
        )
        .unwrap();
        let kernel_name = row["kernel"]["sha"].as_str();
        let kernel = kernel_name
            .map(|s| std::fs::read(original.join("v850/native").join(format!("{s}.bin"))).unwrap());
        let actual = peripheral::v850_host_native(&raw, kernel.as_deref());
        let phase = peripheral::v850_phase_native(&raw, kernel.as_deref());
        let stored = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let stored_kernel = kernel_name.map(|s| {
            std::fs::read(
                corpus
                    .parent()
                    .unwrap()
                    .join("kernel")
                    .join(format!("{s}.bin")),
            )
            .unwrap()
        });
        let decoded = peripheral::v850_host_bus(&stored, stored_kernel.as_deref());
        if let Some(ep) = row["kernel_entry"]["initial_ep_loads"][0]["value"].as_u64() {
            let Observation::Known(value) = actual else {
                panic!("{component}: {actual:?}");
            };
            assert_eq!(u64::from(value.coordinate), ep + 0xd2);
            assert_eq!(
                (value.signature_low, value.signature_high, value.initial_one),
                (
                    ep as u32 + 0xd2,
                    ep as u32 + 0xd3,
                    [ep as u32 + 0xd4, ep as u32 + 0xd5]
                )
            );
            assert_eq!(Observation::Known(value).compare(&decoded), Some(true));
            assert!(
                matches!(phase, Observation::Known(peripheral::Phase {
                assignment: Assignment::Swapped,
                interface: Interface::Indexed16 { window, channels: [0x8e, 0x8f] },
            }) if u64::from(window) == ep + 0x100),
                "{component}: {phase:?}"
            );
            let stored_kernel = stored_kernel.as_deref().unwrap();
            let direct =
                peripheral::correct_v850_phase_bus(&stored, stored_kernel, Assignment::Direct)
                    .unwrap();
            assert_eq!(
                stored.iter().zip(&direct).filter(|(a, b)| a != b).count(),
                2,
                "{component}"
            );
            assert_eq!(
                peripheral::correct_v850_phase_bus(&direct, stored_kernel, Assignment::Direct)
                    .unwrap(),
                direct
            );
            assert_eq!(
                peripheral::correct_v850_phase_bus(&direct, stored_kernel, Assignment::Swapped)
                    .unwrap(),
                stored
            );
            assert!(peripheral::correct_v850_phase_bus(&stored, &[], Assignment::Direct).is_err());
            assert!(peripheral::correct_v850_phase_bus(
                &stored[..stored.len() - 1],
                stored_kernel,
                Assignment::Direct
            )
            .is_err());
            let site = &phase_by[component]["sites"][0];
            assert_eq!(site["order"], 1);
            let mut altered = raw.clone();
            altered[site["writer_offset"].as_u64().unwrap() as usize] ^= 1;
            assert!(matches!(
                peripheral::v850_phase_native(&altered, kernel.as_deref()),
                Observation::Unresolved(_)
            ));
            assert!(matches!(
                peripheral::v850_host_native(&raw, None),
                Observation::Unresolved(_)
            ));
            known += 1;
        } else {
            assert!(matches!(phase, Observation::Unresolved(_)), "{component}");
            assert!(matches!(actual, Observation::Unresolved(_)), "{component}");
            assert!(matches!(decoded, Observation::Unresolved(_)), "{component}");
            missing += 1;
        }
    }
    assert_eq!((known, missing), (49, 22));
}

#[test]
#[ignore = "requires PIONEER_PHASE_AUDIT and PIONEER_ATA_AUDIT"]
fn v850_channel_correction_round_trips_every_native_pair() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_AUDIT").unwrap());
    let native =
        std::path::PathBuf::from(std::env::var("PIONEER_ATA_AUDIT").unwrap()).join("v850/native");
    let rows: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("native-replay/v850/phase-contracts.json")).unwrap(),
    )
    .unwrap();
    let mut count = 0;
    for row in rows.as_array().unwrap() {
        let component = row["sha"].as_str().unwrap();
        let raw = std::fs::read(native.join(format!("{component}.bin"))).unwrap();
        let direct = peripheral::correct_v850_phase_pair(&raw, Assignment::Direct)
            .unwrap_or_else(|e| panic!("{component}: {e:?}"));
        let mut expected = Vec::new();
        for site in row["sites"].as_array().unwrap() {
            let at = site["offset"].as_u64().unwrap() as usize;
            expected.extend_from_slice(&[at + 2, at + 24]);
        }
        expected.sort_unstable();
        let changed: Vec<_> = raw
            .iter()
            .zip(&direct)
            .enumerate()
            .filter_map(|(i, (a, b))| (a != b).then_some(i))
            .collect();
        assert_eq!(changed, expected, "{component}");
        assert_eq!(
            peripheral::correct_v850_phase_pair(&direct, Assignment::Direct).unwrap(),
            direct
        );
        assert_eq!(
            peripheral::correct_v850_phase_pair(&direct, Assignment::Swapped).unwrap(),
            raw
        );
        let mut bad = raw.clone();
        bad[expected[0]] = 0;
        assert!(peripheral::correct_v850_phase_pair(&bad, Assignment::Direct).is_err());
        count += 1;
    }
    assert_eq!(count, 71);
}

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn v850_complete_phase_correction_matches_independent_checksum_oracle() {
    use sha2::{Digest, Sha256};
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let rows: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("v850-phase-corrected-oracle.json")).unwrap(),
    )
    .unwrap();
    for row in rows.as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let original = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let kernel = std::fs::read(
            corpus
                .parent()
                .unwrap()
                .join("kernel")
                .join(format!("{}.bin", row["kernel"].as_str().unwrap())),
        )
        .unwrap();
        let corrected =
            peripheral::correct_v850_normal_phase(&original, &kernel, Assignment::Direct)
                .unwrap_or_else(|e| panic!("{component}: {e:?}"));
        assert_eq!(
            format!("{:x}", Sha256::digest(&corrected)),
            row["expected_sha256"].as_str().unwrap(),
            "{component}"
        );
        assert_eq!(
            peripheral::correct_v850_normal_phase(&corrected, &kernel, Assignment::Direct).unwrap(),
            corrected
        );
        assert_eq!(
            peripheral::correct_v850_normal_phase(&corrected, &kernel, Assignment::Swapped)
                .unwrap(),
            original
        );
        use pioneer_optical::compatibility::{self, Firmware};
        let context = |normal| Firmware {
            hardware: "ATA 0009",
            normal,
            kernel: Some(kernel.as_slice()),
        };
        let planned = compatibility::plan(context(&original), context(&corrected)).unwrap();
        assert_eq!(
            planned.prepare_normal().unwrap(),
            Some(original.clone()),
            "{component}: reverse plan"
        );
        let planned = compatibility::plan(context(&corrected), context(&original)).unwrap();
        assert_eq!(
            planned.prepare_normal().unwrap(),
            Some(corrected.clone()),
            "{component}: direct plan"
        );
        let missing = Firmware {
            hardware: "ATA 0009",
            normal: &original,
            kernel: None,
        };
        assert!(compatibility::plan(missing, context(&corrected)).is_err());
        let mut corrupt = original.clone();
        corrupt[0x800] ^= 1;
        assert!(
            peripheral::correct_v850_normal_phase(&corrupt, &kernel, Assignment::Direct).is_err()
        );
        assert!(peripheral::correct_v850_normal_phase(&original, &[], Assignment::Direct).is_err());
    }
    assert_eq!(rows.as_array().unwrap().len(), 49);
}

#[test]
#[cfg(feature = "envelope")]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn v850_plan_rebuilds_sparse_file_without_granting_transfer_support() {
    use pioneer_optical::{
        compatibility::{self, Firmware},
        envelope::{Envelope, Layout, Update, UpdateError},
        ComponentKind,
    };
    use sha2::{Digest, Sha256};
    fn wrapper(kind: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![255; 0x10000];
        let header=format!("********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER TEST\r\nFile Type : {kind}\r\nHardware Version : ATA 0009\r\nDestination : TEST\r\nKernel Version : TEST\r\nKernel Version2 : 0001\r\n");
        out[..header.len()].copy_from_slice(header.as_bytes());
        let sum = payload.chunks_exact(4).fold(0u32, |s, w| {
            s.wrapping_sub(u32::from_le_bytes(w.try_into().unwrap()))
        });
        out[0x8000..0x8004].copy_from_slice(&sum.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let rows: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("v850-phase-corrected-oracle.json")).unwrap(),
    )
    .unwrap();
    let row = &rows[0];
    let original =
        std::fs::read(corpus.join(format!("{}.bin", row["component"].as_str().unwrap()))).unwrap();
    let kernel = std::fs::read(
        corpus
            .parent()
            .unwrap()
            .join("kernel")
            .join(format!("{}.bin", row["kernel"].as_str().unwrap())),
    )
    .unwrap();
    let corrected =
        peripheral::correct_v850_normal_phase(&original, &kernel, Assignment::Direct).unwrap();
    let target = Envelope::load(&wrapper("Normal", &original)).unwrap();
    let resident = Envelope::load(&wrapper("Kernel", &kernel)).unwrap();
    let plan = compatibility::plan(
        Firmware {
            hardware: "ATA 0009",
            normal: &corrected,
            kernel: Some(&kernel),
        },
        Firmware {
            hardware: "ATA 0009",
            normal: &original,
            kernel: Some(&kernel),
        },
    )
    .unwrap();
    let file = plan
        .prepare_file(&target, Some(&resident))
        .unwrap()
        .unwrap();
    let decoded = Envelope::load_with_kernel(&file, &resident).unwrap();
    assert_eq!(decoded.image, corrected);
    assert_eq!(
        format!("{:x}", Sha256::digest(&decoded.image)),
        row["expected_sha256"].as_str().unwrap()
    );
    assert_eq!(
        &file[..0x8000],
        &target.repack(&original).unwrap()[..0x8000]
    );
    assert!(decoded.normal_transfer_image().is_none());
    assert_eq!(
        Update::load(&wrapper("Kernel", &kernel), &file).unwrap_err(),
        UpdateError::Representation {
            component: ComponentKind::Kernel,
            layout: Layout::SparseChecksum
        }
    );
    assert_eq!(
        plan.prepare_file(&resident, Some(&target)),
        Err(compatibility::Error::ComponentMismatch)
    );
}

#[test]
#[ignore = "requires PIONEER_PHASE_AUDIT, PIONEER_ATA_AUDIT, PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn m32c_phase_corrections_match_all_99_bound_programs() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_AUDIT").unwrap());
    let ata = std::path::PathBuf::from(std::env::var("PIONEER_ATA_AUDIT").unwrap());
    let layout = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let phases: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("native-replay/m32c/phase-contracts.json")).unwrap(),
    )
    .unwrap();
    let inventory: serde_json::Value =
        serde_json::from_slice(&std::fs::read(ata.join("m32c/component-inventory.json")).unwrap())
            .unwrap();
    let operands: serde_json::Value = serde_json::from_slice(
        &std::fs::read(layout.join("m32c-indexed-phase-operands.json")).unwrap(),
    )
    .unwrap();
    let direct_operands: serde_json::Value = serde_json::from_slice(
        &std::fs::read(layout.join("m32c-direct-phase-operands.json")).unwrap(),
    )
    .unwrap();
    let mut matched = 0;
    for row in phases["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let entry = inventory
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["component"] == component)
            .unwrap();
        let base = u32::from_str_radix(
            entry["base_candidate"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let native_assignment = if row["phase_order"] == 0 {
            Assignment::Direct
        } else {
            Assignment::Swapped
        };
        let opposite = if native_assignment == Assignment::Direct {
            Assignment::Swapped
        } else {
            Assignment::Direct
        };
        let corrected = peripheral::correct_m32c_phase_pair(&raw, base, opposite);
        let direct = corrected.unwrap_or_else(|e| panic!("{component}: {e:?}"));
        let indexed = peripheral::correct_m32c_indexed_phase(&raw, base, opposite);
        if row["interface"].as_str().unwrap().starts_with("indexed") {
            assert_eq!(indexed.unwrap(), direct);
        } else {
            assert!(indexed.is_err());
        }
        let native = operands
            .as_array()
            .unwrap()
            .iter()
            .chain(direct_operands.as_array().unwrap().iter())
            .find(|r| r["component"] == component)
            .unwrap();
        let at = native["function"].as_u64().unwrap() as usize;
        let expected: Vec<_> = native["operands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| at + v.as_u64().unwrap() as usize)
            .collect();
        let changed: Vec<_> = raw
            .iter()
            .zip(&direct)
            .enumerate()
            .filter_map(|(i, (a, b))| (a != b).then_some(i))
            .collect();
        assert_eq!(changed, expected, "{component}");
        let Observation::Known(after) = peripheral::m32c_phase(&direct, base) else {
            panic!("{component}: reextract");
        };
        assert_eq!(after.assignment, opposite);
        assert_eq!(
            peripheral::correct_m32c_phase_pair(&direct, base, opposite).unwrap(),
            direct
        );
        assert_eq!(
            peripheral::correct_m32c_phase_pair(&direct, base, native_assignment).unwrap(),
            raw
        );
        let mut broken = raw.clone();
        broken[expected[0]] = 0;
        assert!(peripheral::correct_m32c_phase_pair(&broken, base, Assignment::Direct).is_err());
        matched += 1;
    }
    assert_eq!(matched, 99);
}

#[test]
#[cfg(feature = "envelope")]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn m32c_available_phase_files_repair_checksums_and_missing_keys_fail_closed() {
    use pioneer_optical::envelope::{Envelope, Layout};
    use sha2::{Digest, Sha256};
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let files = audit.join("m32c-envelope-corpus");
    let rows: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("m32c-checksummed-phase-oracle.json")).unwrap(),
    )
    .unwrap();
    let mut counts = [0usize; 3];
    for row in rows.as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let bytes = std::fs::read(files.join(format!("{component}.enc"))).unwrap();
        let kernel = row["kernel"].as_str().map(|sha| {
            Envelope::load(&std::fs::read(files.join(format!("{sha}.enc"))).unwrap()).unwrap()
        });
        let load = |file: &[u8]| match &kernel {
            Some(k) => Envelope::load_with_kernel(file, k),
            None => Envelope::load(file),
        };
        if kernel.is_none() && row["base"] == 0xf80000 {
            assert!(
                matches!(
                    load(&bytes),
                    Err(pioneer_optical::envelope::DecodeError::UnsupportedLayout)
                ),
                "{component}"
            );
            counts[2] += 1;
            continue;
        }
        let original = load(&bytes).unwrap_or_else(|e| panic!("{component}: {e:?}"));
        assert_eq!(
            original.image,
            std::fs::read(corpus.join(format!("{component}.bin"))).unwrap()
        );
        match original.info().layout {
            Layout::NormalTailKey => counts[0] += 1,
            Layout::NormalBootKey => counts[1] += 1,
            _ => panic!("{component}: unexpected codec"),
        }
        let base = row["base"].as_u64().unwrap() as u32;
        let Observation::Known(before) = peripheral::m32c_phase(&original.image, base) else {
            panic!("native phase")
        };
        let opposite = match before.assignment {
            Assignment::Direct => Assignment::Swapped,
            Assignment::Swapped => Assignment::Direct,
        };
        let modified =
            peripheral::correct_m32c_phase_pair(&original.image, base, opposite).unwrap();
        let file = original.repack_with_checksum(&modified).unwrap();
        let corrected = load(&file).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&corrected.image)),
            row["expected_image_sha256"].as_str().unwrap(),
            "{component}"
        );
        assert_eq!(
            corrected.repack_with_checksum(&corrected.image).unwrap(),
            file
        );
        let reverse =
            peripheral::correct_m32c_phase_pair(&corrected.image, base, before.assignment).unwrap();
        assert_eq!(
            corrected.repack_with_checksum(&reverse).unwrap(),
            bytes,
            "{component}: exact reverse file"
        );
        use pioneer_optical::compatibility::{self, Firmware};
        let hardware = original.info().hardware_version.as_str();
        let kernel_image = kernel.as_ref().map(|k| k.image.as_slice());
        let forward = compatibility::plan(
            Firmware {
                hardware,
                normal: &corrected.image,
                kernel: kernel_image,
            },
            Firmware {
                hardware,
                normal: &original.image,
                kernel: kernel_image,
            },
        )
        .unwrap();
        assert_eq!(
            forward.prepare_normal(),
            Err(compatibility::Error::Unsupported)
        );
        assert_eq!(
            forward.prepare_file(&original, kernel.as_ref()).unwrap(),
            Some(file.clone()),
            "{component}: forward plan"
        );
        let backward = compatibility::plan(
            Firmware {
                hardware,
                normal: &original.image,
                kernel: kernel_image,
            },
            Firmware {
                hardware,
                normal: &corrected.image,
                kernel: kernel_image,
            },
        )
        .unwrap();
        assert_eq!(
            backward.prepare_file(&corrected, kernel.as_ref()).unwrap(),
            Some(bytes.clone()),
            "{component}: backward plan"
        );
        assert_eq!(
            forward.prepare_file(&corrected, kernel.as_ref()),
            Err(compatibility::Error::ComponentMismatch)
        );
    }
    assert_eq!(counts, [86, 12, 1]);
}
