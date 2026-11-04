//! Independent native geometry extraction against the audited SAT matrix.
#![cfg(feature = "image")]
use pioneer_optical::image::{
    geometry::{discover_sat, Geometry},
    layout::Observation,
};

#[test]
#[ignore = "requires PIONEER_PHASE_AUDIT, PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn all_sat_geometry_values_match_and_other_platforms_do_not_match() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_AUDIT").unwrap());
    let layout = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let bank: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("bank-complete.json")).unwrap()).unwrap();
    let all: serde_json::Value =
        serde_json::from_slice(&std::fs::read(layout.join("all-platform-layouts.json")).unwrap())
            .unwrap();
    let rows: std::collections::BTreeMap<_, _> = bank["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["component"].as_str().unwrap(), r))
        .collect();
    let mut known = 0;
    for component in all["images"].as_object().unwrap().keys() {
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let row = rows.get(component.as_str());
        let kernel = row
            .and_then(|r| r["contract"]["pair"]["kernel_component"].as_str())
            .map(|s| {
                std::fs::read(
                    corpus
                        .parent()
                        .unwrap()
                        .join("kernel")
                        .join(format!("{s}.bin")),
                )
                .unwrap()
            });
        let result = discover_sat(&raw, kernel.as_deref());
        assert_eq!(
            matches!(result, Observation::Known(_)),
            row.is_some(),
            "{component}: {result:?}"
        );
        if let Observation::Known(value) = result {
            let actual = match value {
                Geometry::MarkerBanks { marker, stride } => format!("{marker:08X}/{stride:X}"),
                Geometry::NativeBanks {
                    bases: [a, b],
                    stride,
                } => format!("Native banks {a:X}/{b:X}; stride {stride:X}"),
            };
            assert_eq!(
                actual,
                row.unwrap()["value"].as_str().unwrap(),
                "{component}"
            );
            known += 1;
            if let Some(mut bad) = kernel {
                assert!(!matches!(discover_sat(&raw, None), Observation::Known(_)));
                bad[0x46fa] ^= 1;
                assert!(!matches!(
                    discover_sat(&raw, Some(&bad)),
                    Observation::Known(_)
                ));
            }
        }
    }
    assert_eq!(known, 530);
}

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn peripheral_geometry_preserves_every_audited_region_and_serial_address() {
    use pioneer_optical::image::{
        geometry::{peripheral_geometry, PeripheralGeometry},
        layout::*,
    };
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("all-platform-layouts.json")).unwrap())
            .unwrap();
    let v850: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("v850-header-binding.json")).unwrap())
            .unwrap();
    let kernels: std::collections::BTreeMap<_, _> = v850["images"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["component"].as_str().unwrap(),
                r["kernel_backend"]["component"].as_str(),
            )
        })
        .collect();
    let mut count = 0;
    for (component, obs) in manifest["images"].as_object().unwrap() {
        let Some(name) = obs["layout"].as_str() else {
            continue;
        };
        let contract = &manifest["contracts"][name];
        if !matches!(
            contract[0].as_str(),
            Some("native_fixed_record_regions" | "serial_word_range" | "serial_selected_records")
        ) {
            continue;
        }
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let layout = match name {
            "m32c_three_regions" | "m32c_two_regions" => discover_m32c_records(&raw),
            "m32c_serial_mechanical" => discover_m32c_serial(&raw, 0xf80000),
            "ata_serial_selected" => discover_m7900_ata(&raw, 0x3800),
            "scsi_serial_selected" => discover_m7900_scsi(&raw, 0x3800),
            "v850_three_regions" => {
                let kernel = kernels[component.as_str()].map(|s| {
                    std::fs::read(
                        corpus
                            .parent()
                            .unwrap()
                            .join("kernel")
                            .join(format!("{s}.bin")),
                    )
                    .unwrap()
                });
                discover_v850_bus(&raw, kernel.as_deref())
            }
            _ => panic!("unexpected peripheral layout {name}"),
        };
        let Observation::Known(layout) = layout else {
            panic!("{component}: {layout:?}");
        };
        let Observation::Known(geometry) = peripheral_geometry(&layout) else {
            panic!("{component}");
        };
        match geometry {
            PeripheralGeometry::FlashRecords(regions) => {
                let expected: Vec<_> = contract[2]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| (r[0].as_u64().unwrap() as u32, r[2].as_u64().unwrap() as u32))
                    .collect();
                assert_eq!(regions, expected, "{component}");
            }
            PeripheralGeometry::SerialWords { first, last } => {
                assert_eq!(u64::from(first), contract[4].as_u64().unwrap());
                assert_eq!(
                    u64::from(last),
                    contract[4].as_u64().unwrap() + contract[5].as_u64().unwrap() - 1
                );
            }
            PeripheralGeometry::SerialRecords { bases, slots } => {
                assert_eq!(serde_json::json!(bases), contract[4]);
                assert_eq!(serde_json::json!(slots), contract[5]);
            }
        }
        count += 1;
    }
    assert_eq!(count, 157);
}
