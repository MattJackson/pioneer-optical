//! Native Startup refusal and scoped preservation through the actual owner.
#![cfg(feature = "envelope")]
use pioneer_optical::{
    compatibility::Firmware,
    filters::{self, Context, Filter, Preparation, Transition},
    image::layout::Observation,
    startup,
};
#[path = "../examples/hardware_matrix/page.rs"]
mod page;

#[test]
#[ignore = "requires PIONEER_HOARD; native unchanged-comparison lifecycle boundary"]
fn held_native_startup_gates_refuse_changed_comparisons_without_writer_lifecycle_proof() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").unwrap());
    let (packages, _) = page::hoard_packages(&root).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    let mut images = Vec::new();
    for package in packages {
        if !package.hardware.starts_with("SAT ") || !seen.insert(package.component.clone()) {
            continue;
        }
        let Ok(decoded) = page::decode(&root, &package) else {
            continue;
        };
        if let Observation::Known(bound) = startup::bound_selection(&decoded.normal.image) {
            images.push((package, decoded, bound));
        }
    }
    let owner = &filters::startup::FILTER;
    let mut refused = 0;
    for (package, target, bound) in &images {
        let Some((donor_package, donor, _)) = images.iter().find(|(_, _, other)| {
            other.layout == bound.layout && other.requirement.required != bound.requirement.required
        }) else {
            continue;
        };
        let installed = Context::new(Firmware {
            hardware: &donor_package.hardware,
            normal: &donor.normal.image,
            kernel: donor.kernel.as_ref().map(|k| k.image.as_slice()),
        });
        let requested = Context::new(Firmware {
            hardware: &package.hardware,
            normal: &target.normal.image,
            kernel: target.kernel.as_ref().map(|k| k.image.as_slice()),
        });
        assert!(
            matches!(
                owner.plan(
                    &Transition {
                        installed: &installed,
                        target: &requested
                    },
                    &owner.inspect(&installed),
                    &owner.inspect(&requested),
                ),
                Err(pioneer_optical::compatibility::Error::Unsupported)
            ),
            "{}: changed CMP has no writer-lifecycle proof",
            package.component
        );
        refused += 1;
    }
    assert!(refused > 0);
    eprintln!("startup changed-comparison lifecycle refusals={refused}");
}

#[test]
#[ignore = "requires PIONEER_NORMAL_CORPUS; native copied startup checksum proof"]
fn native_startup_checksum_is_copied_code_not_an_opaque_rom_service() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let mut count = 0;
    for path in std::fs::read_dir(root).unwrap().flatten() {
        if path.file_name().to_string_lossy().len() != 68 {
            continue;
        }
        let normal = std::fs::read(path.path()).unwrap();
        for at in (0..normal.len().saturating_sub(14)).step_by(2) {
            let b = &normal[at..at + 14];
            if b[0] != 0x5e || b[4..10] != [0x0f, 0x80, 0x47, 0x0c, 0xf8, 1] || b[10] != 0x5e {
                continue;
            }
            let entry = u32::from_be_bytes([0, b[1], b[2], b[3]]);
            if entry >= 0x10000 {
                continue;
            }
            let found = startup::coverage::copied_checksum::discover(&normal, entry);
            eprintln!(
                "{} at {at:#x}, entry {entry:#x}: {found:?}",
                path.file_name().to_string_lossy()
            );
            let Observation::Known(found) = found else {
                panic!("checksum unresolved")
            };
            for mutation in [found.helpers[1].start + 25, found.body.start + 5] {
                let mut changed = normal.clone();
                changed[mutation] ^= 1;
                assert!(!matches!(
                    startup::coverage::copied_checksum::discover(&changed, entry),
                    Observation::Known(_)
                ));
            }
            // Partial overwrite by the native clear pass must not count as a
            // unique full copy even though the selected checksum bytes match.
            let mut changed = normal.clone();
            let init = found.initializer.start;
            changed[init + 42..init + 46].copy_from_slice(&(entry + 2).to_be_bytes());
            changed[init + 48..init + 52].copy_from_slice(&(entry + 4).to_be_bytes());
            assert!(matches!(
                startup::coverage::copied_checksum::discover(&changed, entry),
                Observation::Conflicting
            ));
            let wrapper = u32::from_be_bytes([0, b[11], b[12], b[13]]);
            let calls: Vec<_> = normal
                .windows(4)
                .enumerate()
                .filter_map(|(at, bytes)| {
                    (at & 1 == 0 && bytes[0] == 0x5e && bytes[1..] == wrapper.to_be_bytes()[1..])
                        .then_some(at)
                })
                .collect();
            let host: Vec<_> = calls
                .iter()
                .filter_map(|&at| startup::coverage::sinks::write_buffer(&normal, at))
                .collect();
            eprintln!("host callbacks {}", host.len());
            assert_eq!(host.len(), 1);
            assert!(
                startup::coverage::sinks::discover(&normal).is_some(),
                "complete sink certificate {}",
                path.file_name().to_string_lossy()
            );
            count += 1;
        }
    }
    assert_eq!(count, 6);
}

#[test]
#[ignore = "requires PIONEER_NORMAL_CORPUS; actual phase and startup shared pipeline"]
fn native_startup_preservation_composes_with_phase_in_all_reference_directions() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-mechanism-known-answers.json")).unwrap();
    let mut pairs: Vec<_> = fixtures
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            (
                case["target"].as_str().unwrap().to_owned(),
                case["calibration_donor"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let sat9 = [
        "3711cd5cdde5b5e7f288ccd7bc7fe1100eb6de5e40f3d0ffdcc528fb93ebeb46",
        "c93736b1fc66c7ada2d586044bf5d8a50a622b65e2f1fe6e74ad212f254adc1b",
    ];
    pairs.extend([
        (sat9[0].into(), sat9[1].into()),
        (sat9[1].into(), sat9[0].into()),
    ]);
    let registry: &[&dyn Filter] = &[&filters::startup::FILTER, &filters::phase::FILTER];
    for (target_hash, source_hash) in pairs {
        let source = std::fs::read(root.join(format!("{source_hash}.bin"))).unwrap();
        let normal = std::fs::read(root.join(format!("{target_hash}.bin"))).unwrap();
        let source_kernel = std::fs::read(root.join(format!("{source_hash}.kernel.bin"))).unwrap();
        let target_kernel = std::fs::read(root.join(format!("{target_hash}.kernel.bin"))).unwrap();
        let installed = Context::new(Firmware {
            hardware: "SAT 8000",
            normal: &source,
            kernel: Some(&source_kernel),
        });
        let target = Context::new(Firmware {
            hardware: "SAT 8000",
            normal: &normal,
            kernel: Some(&target_kernel),
        });
        let plan = filters::runner::plan_with(
            &installed,
            &target,
            filters::runner::Policy::Strict,
            registry,
        )
        .unwrap_or_else(|e| panic!("{source_hash} → {target_hash}: {e:?}"));
        assert!(!plan
            .required_words()
            .unwrap()
            .iter()
            .any(|word| word.word.parameter == 0x9f));
        let preparation = Preparation {
            target: target.firmware,
            normal: None,
            kernel: None,
        };
        let changed = plan
            .prepare_with(&preparation, registry)
            .unwrap_or_else(|e| panic!("prepare {source_hash} → {target_hash}: {e:?}"))
            .unwrap();
        plan.verify_with(&preparation, &changed, registry).unwrap();
        assert_ne!(changed, normal);
        eprintln!("phase + startup verified {source_hash} → {target_hash}");
    }
}

#[test]
#[ignore = "exports held native startup instruction spans for CI"]
fn export_startup_sink_spans() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let mut fixtures = Vec::new();
    for entry in std::fs::read_dir(root).unwrap().flatten() {
        let hash = entry.file_name().to_string_lossy().into_owned();
        if hash.len() != 68 {
            continue;
        }
        let normal = std::fs::read(entry.path()).unwrap();
        let certificate = startup::coverage::sinks::discover(&normal).unwrap();
        let mut spans = certificate.protected;
        spans.push(0..24);
        spans.sort_by_key(|span| (span.start, span.end));
        let mut merged: Vec<std::ops::Range<usize>> = Vec::new();
        for span in spans {
            if let Some(previous) = merged.last_mut() {
                if span.start <= previous.end {
                    previous.end = previous.end.max(span.end);
                    continue;
                }
            }
            merged.push(span);
        }
        let spans: Vec<_> = merged
            .into_iter()
            .map(|span| {
                serde_json::json!([
                    span.start,
                    normal[span]
                        .iter()
                        .map(|v| format!("{v:02x}"))
                        .collect::<String>()
                ])
            })
            .collect();
        fixtures.push(serde_json::json!({"original_sha256":hash.trim_end_matches(".bin"),"size":normal.len(),"spans":spans}));
    }
    fixtures.sort_by_key(|f| f["original_sha256"].as_str().unwrap().to_owned());
    std::fs::write(
        "tests/fixtures/startup-native-sinks.json",
        serde_json::to_string_pretty(&fixtures).unwrap() + "\n",
    )
    .unwrap();
}

fn startup_sink_fixtures() -> Vec<Vec<u8>> {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/startup-native-sinks.json")).unwrap();
    fixtures
        .as_array()
        .unwrap()
        .iter()
        .map(|fixture| {
            let mut normal = vec![0xff; fixture["size"].as_u64().unwrap() as usize];
            for span in fixture["spans"].as_array().unwrap() {
                let at = span[0].as_u64().unwrap() as usize;
                let hex = span[1].as_str().unwrap();
                let bytes: Vec<_> = (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect();
                normal[at..at + bytes.len()].copy_from_slice(&bytes);
            }
            normal
        })
        .collect()
}

#[test]
fn native_startup_sink_certificates_verify_real_instructions_and_refuse_new_sinks() {
    let fixtures = startup_sink_fixtures();
    assert_eq!(fixtures.len(), 6);
    // Compact native instructions retain the generation predicate. Supply its
    // matching header bytes without claiming these are authenticated Kernels.
    let kernels: Vec<_> = fixtures
        .iter()
        .map(|normal| {
            let mut kernel = [0xff; 0x100];
            kernel[0xfe] = normal[0x28];
            kernel
        })
        .collect();
    let owner = &filters::startup::FILTER;
    let registry: &[&dyn Filter] = &[owner];
    for (index, normal) in fixtures.iter().enumerate() {
        let certificate =
            startup::coverage::sinks::discover(normal).unwrap_or_else(|| panic!("fixture {index}"));
        let installed = Context::new(Firmware {
            hardware: "SAT 8000",
            normal: &fixtures[(index + 1) % fixtures.len()],
            kernel: Some(&kernels[(index + 1) % fixtures.len()]),
        });
        let target = Context::new(Firmware {
            hardware: "SAT 8000",
            normal,
            kernel: Some(&kernels[index]),
        });
        let plan = filters::runner::plan_with(
            &installed,
            &target,
            filters::runner::Policy::Strict,
            registry,
        )
        .unwrap();
        let preparation = Preparation {
            target: target.firmware,
            normal: None,
            kernel: None,
        };
        assert!(plan.required_words().unwrap().is_empty());
        assert!(owner.parameters(&target).unwrap().is_empty());
        assert!(plan.prepare_with(&preparation, registry).unwrap().is_none());
        let mut disjoint = normal.clone();
        disjoint[0x2200] ^= 1;
        plan.verify_with(&preparation, &disjoint, registry).unwrap();
        let wrapper = *certificate
            .entries
            .iter()
            .find(|&&address| {
                let at = (address - 0x410000) as usize;
                normal[at..at + 6] == [0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]
            })
            .unwrap();
        let call = [
            0x5e,
            wrapper.to_be_bytes()[1],
            wrapper.to_be_bytes()[2],
            wrapper.to_be_bytes()[3],
        ];
        let mut new_sink = normal.clone();
        new_sink[0x2200..0x2202].copy_from_slice(&[0xf8, 1]);
        new_sink[0x2202..0x2206].copy_from_slice(&call);
        assert!(startup::coverage::sinks::discover(&new_sink).is_none());
        assert!(plan.verify_with(&preparation, &new_sink, registry).is_err());
        let predicate = normal
            .windows(10)
            .enumerate()
            .find_map(|(at, b)| {
                (at & 1 == 0 && b[0] == 0x5e && b[4..] == [0x0f, 0x80, 0x47, 0x0c, 0xf8, 1])
                    .then_some(at)
            })
            .unwrap();
        let mut bypass = normal.clone();
        bypass[0x2200] = 0x5a;
        bypass[0x2201..0x2204]
            .copy_from_slice(&(0x410000 + predicate as u32 + 8).to_be_bytes()[1..]);
        assert!(startup::coverage::sinks::discover(&bypass).is_none());
        assert!(plan.verify_with(&preparation, &bypass, registry).is_err());
        let mut pointer = normal.clone();
        pointer[0x2200..0x2202].copy_from_slice(&[0x7a, 0]);
        pointer[0x2202..0x2206].copy_from_slice(&wrapper.to_be_bytes());
        assert!(startup::coverage::sinks::discover(&pointer).is_none());
        let mut relative = normal.clone();
        let at = (wrapper - 0x410000) as usize + 0x20;
        relative[at..at + 2].copy_from_slice(&[0x55, (-0x22i8) as u8]);
        assert!(startup::coverage::sinks::discover(&relative).is_none());
        assert!(!certificate.accepts_kernel(&call));
        assert!(!certificate.accepts_kernel(&wrapper.to_be_bytes()));
        let mut vector = normal.clone();
        vector[0x2000] ^= 1;
        assert!(startup::coverage::sinks::discover(&vector).is_none());
        assert!(plan.verify_with(&preparation, &vector, registry).is_err());
    }
}
