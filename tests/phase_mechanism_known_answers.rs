//! Independent 0.17.3 reviewed outputs, never production correction recipes.
//! References: the reviewed definitions removed by e922789, recovered from
//! e922789^:src/filters/phase/mechanism/contracts.rs. This checks recognition
//! and bounded coil edits of those outputs, not full mechanism conversion.
#![cfg(feature = "envelope")]
use pioneer_optical::filters::phase::{bundle, native};
use sha2::{Digest, Sha256};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
#[ignore = "requires PIONEER_NORMAL_CORPUS with decoded Normal images named by SHA256"]
fn reviewed_ud02_outputs_bind_and_support_operand_only_phase_round_trips() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-mechanism-known-answers.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let hash = case["target"].as_str().unwrap();
        let original = std::fs::read(root.join(format!("{hash}.bin"))).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&original)),
            hash,
            "{id}: input"
        );
        let mut answer = original.clone();
        for replacement in case["reps"].as_array().unwrap() {
            let at = replacement[0].as_u64().unwrap() as usize;
            let before = hex(replacement[1].as_str().unwrap());
            let after = hex(replacement[2].as_str().unwrap());
            assert_eq!(before.len(), after.len(), "{id}: replacement width");
            assert_eq!(
                original[at..at + before.len()],
                before,
                "{id}: guard {at:#x}"
            );
            answer[at..at + after.len()].copy_from_slice(&after);
        }
        answer[16..20].fill(0);
        let sum = answer.chunks_exact(4).fold(0u32, |s, w| {
            s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
        });
        answer[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
        assert_eq!(
            format!("{:x}", Sha256::digest(&answer)),
            case["output"].as_str().unwrap(),
            "{id}: reviewed output"
        );
        let donor = std::fs::read(root.join(format!(
            "{}.bin",
            case["conversion_donor"].as_str().unwrap()
        )))
        .unwrap();
        let rewritten = bundle::conversions::rewrite(
            &original,
            &donor,
            [Some(0x400..0x440), Some(0x440..0x484), Some(0x484..0x4b8)],
        )
        .unwrap();
        let spans: Vec<_> = case["conversion_spans"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let start = v[0].as_u64().unwrap() as usize;
                start..start + v[1].as_u64().unwrap() as usize
            })
            .collect();
        for span in &spans {
            assert_eq!(
                rewritten[span.clone()],
                answer[span.clone()],
                "{id}: native conversion {span:?}"
            );
        }
        for (i, (a, b)) in original.iter().zip(&rewritten).enumerate() {
            assert!(
                a == b || spans.iter().any(|span| span.contains(&i)),
                "{id}: conversion escaped whitelist at {i:#x}"
            );
        }
        let controlled = bundle::conversions::rewrite_controls(&original, &donor).unwrap();
        let control_spans: Vec<_> = case["control_spans"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let start = v[0].as_u64().unwrap() as usize;
                start..start + v[1].as_u64().unwrap() as usize
            })
            .collect();
        for span in &control_spans {
            assert_eq!(
                controlled[span.clone()],
                answer[span.clone()],
                "{id}: control stage {span:?}"
            );
        }
        for (i, (a, b)) in original.iter().zip(&controlled).enumerate() {
            assert!(
                a == b || control_spans.iter().any(|span| span.contains(&i)),
                "{id}: control escaped whitelist {i:#x}"
            );
        }
        // The reviewed source-word exchange also exchanges which existing
        // coil entry receives each offset. Its step stage therefore flips the
        // original source selection before that exchange is composed.
        let stepped = bundle::rewrite_step_offsets(&original, 1).unwrap();
        let step_spans: Vec<_> = case["step_spans"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let start = v[0].as_u64().unwrap() as usize;
                start..start + v[1].as_u64().unwrap() as usize
            })
            .collect();
        for span in &step_spans {
            assert_eq!(
                stepped[span.clone()],
                answer[span.clone()],
                "{id}: step stage {span:?}"
            );
        }
        for (i, (a, b)) in original.iter().zip(&stepped).enumerate() {
            assert!(
                a == b || step_spans.iter().any(|span| span.contains(&i)),
                "{id}: step escaped whitelist {i:#x}"
            );
        }
        let required_assignment = if id.starts_with("pioneer.ud02-to-") {
            native::Assignment::Direct
        } else {
            native::Assignment::Swapped
        };
        let sourced =
            native::sources::rewrite(&original, required_assignment, Some(0x4fc..0x52c)).unwrap();
        let source_spans: Vec<_> = case["source_spans"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let start = v[0].as_u64().unwrap() as usize;
                start..start + v[1].as_u64().unwrap() as usize
            })
            .collect();
        for span in &source_spans {
            assert_eq!(
                sourced[span.clone()],
                answer[span.clone()],
                "{id}: source stage {span:?}"
            );
        }
        for (i, (a, b)) in original.iter().zip(&sourced).enumerate() {
            assert!(
                a == b || source_spans.iter().any(|span| span.contains(&i)),
                "{id}: source escaped whitelist {i:#x}"
            );
        }
        let calibration_donor = std::fs::read(root.join(format!(
            "{}.bin",
            case["calibration_donor"].as_str().unwrap()
        )))
        .unwrap();
        let calibrated =
            native::calibration::rewrite(&original, &calibration_donor, Some(0x4b8..0x4fc))
                .unwrap();
        let calibration_spans: Vec<_> = case["calibration_spans"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let start = v[0].as_u64().unwrap() as usize;
                start..start + v[1].as_u64().unwrap() as usize
            })
            .collect();
        for span in &calibration_spans {
            assert_eq!(
                calibrated[span.clone()],
                answer[span.clone()],
                "{id}: calibration stage {span:?}"
            );
        }
        for (i, (a, b)) in original.iter().zip(&calibrated).enumerate() {
            assert!(
                a == b || calibration_spans.iter().any(|span| span.contains(&i)),
                "{id}: calibration escaped whitelist {i:#x}"
            );
        }
        if id.starts_with("pioneer.ud02-to-") {
            let ud02 = std::fs::read(root.join(format!(
                "{}.bin",
                case["calibration_donor"].as_str().unwrap()
            )))
            .unwrap();
            let reviewed_tables: Vec<_> = case["reps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| hex(v[2].as_str().unwrap()))
                .filter(|v| v.len() == 72)
                .collect();
            for address in [0x59f088usize, 0x59f0d0] {
                let at = address - 0x410000;
                let table: &[u8; 72] = ud02[at..at + 72].try_into().unwrap();
                let normalized = bundle::waveforms::plain_coefficients(
                    table,
                    bundle::Loader::AscendingNegated17,
                );
                assert!(
                    reviewed_tables.iter().any(|t| t.as_slice() == normalized),
                    "{id}: native coefficient sequence"
                );
            }
        }
        let loader_tables = [
            case["loader_tables"][0].as_u64().unwrap() as u32,
            case["loader_tables"][1].as_u64().unwrap() as u32,
        ];
        let direction = if id.starts_with("pioneer.ud02-to-") {
            bundle::Loader::Ascending
        } else {
            bundle::Loader::Descending
        };
        let loaded =
            bundle::waveforms::loader::rewrite(&original, direction, loader_tables, None).unwrap();
        let loader_start = case["loader_span"][0].as_u64().unwrap() as usize;
        let loader_end = loader_start + case["loader_span"][1].as_u64().unwrap() as usize;
        assert_eq!(
            loaded[loader_start..loader_end],
            answer[loader_start..loader_end],
            "{id}: complete loader program"
        );
        for (i, (a, b)) in original.iter().zip(&loaded).enumerate() {
            assert!(
                a == b || (loader_start..loader_end).contains(&i),
                "{id}: loader escaped whitelist {i:#x}"
            );
        }
        let bound = bundle::bind(&answer).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let forward = id.starts_with("pioneer.ud02-to-");
        assert_eq!(
            bound.coil,
            if forward {
                native::Assignment::Direct
            } else {
                native::Assignment::Swapped
            },
            "{id}"
        );
        assert_eq!(
            bound.without_coil(),
            if forward {
                [0, 0, 0, 0, 0, 0, 0, 0]
            } else {
                [0, 2, 1, 1, 1, 1, 1, 1]
            },
            "{id}"
        );
        let opposite = if forward {
            native::Assignment::Swapped
        } else {
            native::Assignment::Direct
        };
        let changed = native::correct_pair(&answer, opposite).unwrap();
        assert_eq!(
            native::correct_pair(&changed, bound.coil).unwrap(),
            answer,
            "{id}: round trip"
        );
        let pioneer_optical::image::layout::Observation::Known(proof) =
            native::discover_pair(&answer)
        else {
            panic!("{id}: pair")
        };
        let mut expected: Vec<_> = proof.operands.into_iter().flatten().collect();
        expected.sort_unstable();
        let actual: Vec<_> = answer
            .iter()
            .zip(&changed)
            .enumerate()
            .filter_map(|(i, (a, b))| (a != b).then_some(i))
            .collect();
        assert_eq!(actual, expected, "{id}: diff whitelist");
    }
}

#[test]
#[ignore = "requires PIONEER_NORMAL_CORPUS with decoded XD08/XS08U Normal images named by SHA256"]
fn sat9_parameter_conversion_stage_works_in_both_directions_without_family_admission() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    // Held XD08 9330 and XS08U 9621; hashes bind the exact input files.
    let hashes = [
        "3711cd5cdde5b5e7f288ccd7bc7fe1100eb6de5e40f3d0ffdcc528fb93ebeb46",
        "c93736b1fc66c7ada2d586044bf5d8a50a622b65e2f1fe6e74ad212f254adc1b",
    ];
    let images: Vec<_> = hashes
        .iter()
        .map(|hash| {
            let bytes = std::fs::read(root.join(format!("{hash}.bin"))).unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(&bytes)), *hash);
            bytes
        })
        .collect();
    for (target, installed) in [(&images[0], &images[1]), (&images[1], &images[0])] {
        let before = bundle::bind(target).unwrap();
        let desired = bundle::bind(installed).unwrap();
        let changed = bundle::conversions::rewrite(
            target,
            installed,
            [Some(0x400..0x440), Some(0x440..0x484), Some(0x484..0x4b8)],
        )
        .unwrap();
        let after = bundle::bind(&changed).unwrap();
        assert_eq!(after.calibration_base, desired.calibration_base);
        assert_eq!(after.calibration_offset, desired.calibration_offset);
        assert_eq!(after.calibration_step, desired.calibration_step);
        // This test deliberately covers only the conversion stage. It must not
        // accidentally change the remaining, not-yet-composed bundle elements.
        assert_eq!(
            bundle::Bundle {
                calibration_base: before.calibration_base,
                calibration_offset: before.calibration_offset,
                calibration_step: before.calibration_step,
                ..after
            },
            before
        );
        assert_eq!(changed[16..20], target[16..20]);
        let controlled = bundle::conversions::rewrite_controls(target, installed).unwrap();
        let controls = bundle::bind(&controlled).unwrap();
        assert_eq!(controls.mode_sign, desired.mode_sign);
        assert_eq!(controls.controller_mode, desired.controller_mode);
        assert_eq!(
            bundle::Bundle {
                mode_sign: before.mode_sign,
                controller_mode: before.controller_mode,
                ..controls
            },
            before
        );
        assert_eq!(
            bundle::conversions::rewrite_controls(&controlled, target).unwrap(),
            *target
        );
    }
}

#[path = "../examples/hardware_matrix/page.rs"]
mod page;

#[test]
#[ignore = "requires PIONEER_HOARD"]
fn source_exchange_stage_covers_every_held_h8_normal_without_family_admission() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").unwrap());
    let (packages, _) = page::hoard_packages(&root).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    let mut failures = Vec::new();
    let (mut checked, mut sat9) = (0, 0);
    for package in packages {
        if !(package.hardware.starts_with("SAT 8") || package.hardware.starts_with("SAT 9"))
            || !seen.insert(package.component.clone())
        {
            continue;
        }
        let decoded = page::decode(&root, &package).unwrap();
        let original = &decoded.normal.image;
        let pioneer_optical::image::layout::Observation::Known(before) =
            native::discover_pair(original)
        else {
            failures.push(format!(
                "{} {} {}: no native pair",
                package.model, package.hardware, package.revision
            ));
            continue;
        };
        let target = match before.assignment {
            native::Assignment::Direct => native::Assignment::Swapped,
            native::Assignment::Swapped => native::Assignment::Direct,
        };
        match native::sources::rewrite(original, target, Some(0x600..0x640)) {
            Ok(changed) => {
                assert!(
                    matches!(native::discover_pair(&changed),pioneer_optical::image::layout::Observation::Known(p) if p.assignment==target)
                );
                assert_eq!(changed[..24], original[..24]);
                checked += 1;
                sat9 += usize::from(package.hardware.starts_with("SAT 9"));
            }
            Err(e) => failures.push(format!(
                "{} {} {}: {e:?}",
                package.model, package.hardware, package.revision
            )),
        }
    }
    println!(
        "source exchange: {checked} H8 Normals, including {sat9} SAT9; {} failures",
        failures.len()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(checked > 0 && sat9 > 0);
}

#[test]
#[ignore = "exports decoded references from PIONEER_HOARD into PIONEER_NORMAL_CORPUS"]
fn export_reference_normals_from_hoard() {
    let hoard = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").unwrap());
    let output = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    std::fs::create_dir_all(&output).unwrap();
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-mechanism-known-answers.json")).unwrap();
    let mut needed = std::collections::BTreeSet::new();
    for case in cases.as_array().unwrap() {
        for key in ["target", "conversion_donor", "calibration_donor"] {
            needed.insert(case[key].as_str().unwrap().to_owned());
        }
    }
    needed.extend([
        "3711cd5cdde5b5e7f288ccd7bc7fe1100eb6de5e40f3d0ffdcc528fb93ebeb46".to_owned(),
        "c93736b1fc66c7ada2d586044bf5d8a50a622b65e2f1fe6e74ad212f254adc1b".to_owned(),
    ]);
    let (packages, _) = page::hoard_packages(&hoard).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for package in packages {
        if !seen.insert(package.component.clone()) {
            continue;
        }
        let Ok(decoded) = page::decode(&hoard, &package) else {
            continue;
        };
        let hash = format!("{:x}", Sha256::digest(&decoded.normal.image));
        if needed.remove(&hash) {
            std::fs::write(output.join(format!("{hash}.bin")), &decoded.normal.image).unwrap();
        }
        if needed.is_empty() {
            break;
        }
    }
    assert!(
        needed.is_empty(),
        "Missing decoded reference images: {needed:?}"
    );
}
