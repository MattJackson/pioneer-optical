//! Native phase proof and byte-exact bidirectional correction checks.
#![cfg(feature = "image")]
#![cfg(feature = "internals")]
use pioneer_optical::image::{
    layout::Observation,
    phase::{correct_normal, correct_pair, discover_pair, Assignment, CorrectionError},
};

#[test]
#[ignore = "requires PIONEER_PHASE_AUDIT and PIONEER_NORMAL_CORPUS"]
fn paired_phase_corrections_round_trip_every_audited_image() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("phase-reextraction.json")).unwrap())
            .unwrap();
    let mut matched = 0;
    let mut swapped_count = 0;
    let mut valid_checksums = 0;
    for row in manifest["results"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let expected_pair = row["hits"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["recognizer"] == "paired_output_functions");
        let result = discover_pair(&raw);
        assert_eq!(
            matches!(result, Observation::Known(_)),
            expected_pair.is_some(),
            "{component}: {result:?}"
        );
        if let Observation::Known(proof) = result {
            matched += 1;
            let expected = if row["expected"] == "0" {
                Assignment::Direct
            } else {
                Assignment::Swapped
            };
            assert_eq!(proof.assignment, expected, "{component}");
            swapped_count += usize::from(expected == Assignment::Swapped);
            let mut offsets: Vec<_> = expected_pair.unwrap()["offsets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap() as usize)
                .collect();
            offsets.sort_unstable();
            let mut actual = proof.functions;
            actual.sort_unstable();
            assert_eq!(actual.as_slice(), offsets.as_slice(), "{component}");
            let target = if expected == Assignment::Direct {
                Assignment::Swapped
            } else {
                Assignment::Direct
            };
            let corrected = correct_pair(&raw, target).unwrap();
            let sum = |b: &[u8]| {
                b.chunks_exact(4).fold(0u32, |sum, w| {
                    sum.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
                })
            };
            if sum(&raw) == 0 {
                valid_checksums += 1;
                let complete = correct_normal(&raw, target).unwrap();
                assert_eq!(sum(&complete), 0, "{component}");
                assert!(
                    correct_normal(&complete, expected).unwrap() == raw,
                    "{component}: complete round trip"
                );
                for (i, (&a, &b)) in complete.iter().zip(&corrected).enumerate() {
                    assert!(
                        a == b || (16..20).contains(&i),
                        "{component}: unexpected checksum edit {i}"
                    );
                }
            } else {
                assert_eq!(
                    correct_normal(&raw, target),
                    Err(CorrectionError::InvalidNormal),
                    "{component}"
                );
            }
            let differences: Vec<_> = raw
                .iter()
                .zip(&corrected)
                .enumerate()
                .filter_map(|(i, (a, b))| (a != b).then_some(i))
                .collect();
            let mut sites: Vec<_> = proof.operands.into_iter().flatten().collect();
            sites.sort_unstable();
            assert_eq!(differences, sites, "{component}");
            assert_eq!(
                correct_pair(&corrected, expected).unwrap(),
                raw,
                "{component}"
            );
            assert_eq!(
                correct_pair(&corrected, target).unwrap(),
                corrected,
                "{component}"
            );
        }
    }
    assert_eq!((matched, swapped_count), (457, 58));
    assert_eq!(valid_checksums, 346);
}

#[test]
#[ignore = "requires PIONEER_PHASE_AUDIT and PIONEER_NORMAL_CORPUS"]
fn all_sat_phase_assignments_match_native_audit() {
    use pioneer_optical::image::phase::{discover, Interface};
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("phase-reextraction.json")).unwrap())
            .unwrap();
    let mut count = 0;
    for row in manifest["results"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let result = discover(&raw);
        let Observation::Known(phase) = result else {
            panic!("{component}: {result:?}");
        };
        assert_eq!(
            phase.assignment,
            if row["expected"] == "0" {
                Assignment::Direct
            } else {
                Assignment::Swapped
            },
            "{component}"
        );
        for hit in row["hits"].as_array().unwrap() {
            assert_eq!(
                phase.interface,
                if hit["interface"] == "split_word" {
                    Interface::SplitWord
                } else {
                    Interface::BytePair
                },
                "{component}"
            );
        }
        count += 1;
    }
    assert_eq!(count, 530);
}

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT, PIONEER_PHASE_AUDIT and PIONEER_NORMAL_CORPUS"]
fn sat_recognizers_do_not_assign_phase_to_other_architectures() {
    use pioneer_optical::image::phase::discover;
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_AUDIT").unwrap());
    let layouts = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let phases: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("phase-reextraction.json")).unwrap())
            .unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(layouts.join("all-platform-layouts.json")).unwrap())
            .unwrap();
    let sat: std::collections::BTreeSet<_> = phases["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["component"].as_str().unwrap())
        .collect();
    let mut count = 0;
    for component in manifest["images"].as_object().unwrap().keys() {
        if sat.contains(component.as_str()) {
            continue;
        }
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        assert!(
            !matches!(discover(&raw), Observation::Known(_)),
            "{component}"
        );
        count += 1;
    }
    assert_eq!(count, 192);
}

#[test]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn all_sat1_forms_match_independent_operand_and_checksum_oracles() {
    use pioneer_optical::image::phase::{correct_legacy, discover, Interface, Phase};
    use sha2::{Digest, Sha256};
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("sat1-phase-correction-contracts.json")).unwrap(),
    )
    .unwrap();
    let rows = manifest["images"].as_array().unwrap();
    assert_eq!(rows.len(), 73);
    let mut complete = 0;
    let mut duplicates = 0;
    let mut deferred = 0;
    for row in rows {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let native = &row["hits"][0];
        let assignment = if native["order"] == 0 {
            Assignment::Direct
        } else {
            Assignment::Swapped
        };
        let target = if assignment == Assignment::Direct {
            Assignment::Swapped
        } else {
            Assignment::Direct
        };
        let interface = if native["interface"] == "split_word" {
            Interface::SplitWord
        } else {
            Interface::BytePair
        };
        let before = Phase {
            assignment,
            interface,
        };
        assert_eq!(
            discover(&raw).compare(&Observation::Known(before)),
            Some(true),
            "{component}"
        );
        assert_eq!(correct_legacy(&raw, assignment).unwrap(), raw);
        duplicates += usize::from(row["hits"].as_array().unwrap().len() > 1);
        complete += usize::from(row["complete_normal_checksum_valid"] == true);
        if row["patches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["kind"] == "inline_leaf")
        {
            deferred += 1;
            assert_eq!(
                correct_legacy(&raw, target),
                Err(CorrectionError::Unresolved),
                "{component}"
            );
            assert_eq!(
                correct_normal(&raw, target),
                Err(if row["complete_normal_checksum_valid"] == true {
                    CorrectionError::Unresolved
                } else {
                    CorrectionError::InvalidNormal
                }),
                "{component}"
            );
            continue;
        }
        let corrected =
            correct_legacy(&raw, target).unwrap_or_else(|e| panic!("{component}: {e:?}"));
        assert_eq!(
            format!("{:x}", Sha256::digest(&corrected)),
            row["expected_operand_sha256"].as_str().unwrap(),
            "{component}"
        );
        assert_eq!(
            discover(&corrected).compare(&Observation::Known(Phase {
                assignment: target,
                interface
            })),
            Some(true),
            "{component}"
        );
        assert_eq!(
            correct_legacy(&corrected, assignment).unwrap(),
            raw,
            "{component}: inverse"
        );
        assert_eq!(
            correct_legacy(&corrected, target).unwrap(),
            corrected,
            "{component}: idempotent"
        );
        assert_eq!(
            correct_legacy(&raw, assignment).unwrap(),
            raw,
            "{component}: native no-op"
        );
        if row["complete_normal_checksum_valid"] == true {
            let image = correct_normal(&raw, target).unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(&image)),
                row["expected_corrected_sha256"].as_str().unwrap(),
                "{component}"
            );
            assert_eq!(
                correct_normal(&image, assignment).unwrap(),
                raw,
                "{component}: complete inverse"
            );
        } else {
            assert_eq!(
                correct_normal(&raw, target),
                Err(CorrectionError::InvalidNormal),
                "{component}"
            );
        }
    }
    assert_eq!((complete, duplicates), (52, 6));
    assert_eq!(deferred, 42);
}

#[test]
#[cfg(feature = "envelope")]
#[ignore = "requires PIONEER_LAYOUT_AUDIT and SHA-verified sat1-envelope-corpus"]
fn sat1_original_files_follow_independent_operand_oracle_and_round_trip() {
    use pioneer_optical::{
        compatibility::{self, Firmware},
        envelope::{Envelope, Layout},
        image::{
            matrix,
            phase::{correct_legacy, discover},
        },
    };
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let files = audit.join("sat1-envelope-corpus");
    let rows: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("sat1-envelope-corpus.json")).unwrap())
            .unwrap();
    let contracts: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("sat1-phase-correction-contracts.json")).unwrap(),
    )
    .unwrap();
    let hex = |text: &str| -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    };
    let sum = |bytes: &[u8]| {
        bytes.chunks_exact(4).fold(0u32, |s, w| {
            s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
        })
    };
    let mut complete = 0;
    let mut scaled = 0;
    let mut unresolved_identity = 0;
    let mut invalid_standalone = 0;
    let mut deferred = 0;
    let mut deferred_valid = 0;
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|worker| {
                let (rows, contracts, files) = (&rows, &contracts, &files);
                scope.spawn(move || {
                    let mut complete = 0;
                    let mut scaled = 0;
                    let mut unresolved_identity = 0;
                    let mut invalid_standalone = 0;
                    let mut deferred = 0;
                    let mut deferred_valid = 0;
                    for row in rows.as_array().unwrap().iter().skip(worker).step_by(8) {
                        let component = row["component"].as_str().unwrap();
                        let bytes = std::fs::read(files.join(format!("{component}.enc"))).unwrap();
                        let kernel = row["kernel"].as_str().map(|sha| {
                            Envelope::load(
                                &std::fs::read(files.join(format!("{sha}.enc"))).unwrap(),
                            )
                            .unwrap()
                        });
                        let load = |file: &[u8]| match &kernel {
                            Some(k) => Envelope::load_with_kernel(file, k),
                            None => Envelope::load(file),
                        };
                        let original =
                            load(&bytes).unwrap_or_else(|e| panic!("{component}: {e:?}"));
                        let contract = contracts["images"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|r| r["component"] == component)
                            .unwrap();
                        let Observation::Known(before) = discover(&original.image) else {
                            panic!("{component}: phase");
                        };
                        let target = match before.assignment {
                            Assignment::Direct => Assignment::Swapped,
                            Assignment::Swapped => Assignment::Direct,
                        };
                        // The expected result comes from the independent disassembly manifest,
                        // rather than the production recognizer's returned patch positions.
                        let mut expected = original.image.clone();
                        for patch in contract["patches"].as_array().unwrap() {
                            let at = patch["offset"].as_u64().unwrap() as usize;
                            let old = hex(patch["before"].as_str().unwrap());
                            let new = hex(patch["after"].as_str().unwrap());
                            assert_eq!(
                                expected[at..at + old.len()],
                                old,
                                "{component}: oracle binding"
                            );
                            expected[at..at + new.len()].copy_from_slice(&new);
                        }
                        if contract["patches"].as_array().unwrap().iter().any(|p| p["kind"] == "inline_leaf") {
                            // The independent historical oracle still describes
                            // a recognizable assignment, but deleting JSR/RTS
                            // lacks timing and temporary stack preservation proof.
                            assert_eq!(correct_legacy(&original.image, before.assignment).unwrap(), original.image);
                            assert_eq!(correct_legacy(&original.image, target), Err(CorrectionError::Unresolved));
                            assert!(matches!(discover(&expected), Observation::Known(p) if p.assignment == target && p.interface == before.interface));
                            assert_eq!(correct_legacy(&expected, before.assignment), Err(CorrectionError::Unresolved));
                            deferred += 1;
                            if sum(&original.image) != 0 {
                                assert!(kernel.is_none());
                                assert_eq!(correct_normal(&original.image, target), Err(CorrectionError::InvalidNormal));
                                invalid_standalone += 1;
                            } else {
                                assert_eq!(correct_normal(&original.image, target), Err(CorrectionError::Unresolved));
                                deferred_valid += 1;
                                scaled += usize::from(original.info().layout == Layout::NormalScaledKey);
                            }
                            continue;
                        }
                        if sum(&original.image) != 0 {
                            assert!(
                                kernel.is_none(),
                                "{component}: invalid sum with exact Kernel"
                            );
                            let modified = correct_legacy(&original.image, target).unwrap();
                            assert_eq!(modified, expected, "{component}: raw operand oracle");
                            assert!(original.repack_with_checksum(&modified).is_none());
                            assert_eq!(
                                correct_normal(&original.image, target),
                                Err(CorrectionError::InvalidNormal)
                            );
                            let hardware = original.info().hardware_version.as_str();
                            let installed = Firmware {
                                hardware,
                                normal: &modified,
                                kernel: None,
                            };
                            let destination = Firmware {
                                hardware,
                                normal: &original.image,
                                kernel: None,
                            };
                            if matrix::discover(hardware, &original.image, None).is_none() {
                                assert!(matches!(
                                    compatibility::plan(installed, destination),
                                    Err(compatibility::Error::UnresolvedIdentity)
                                ));
                                unresolved_identity += 1;
                            } else {
                                // SAT1 phase correction is suspended by the hardware matrix.
                                assert!(matches!(
                                    compatibility::plan(installed, destination),
                                    Err(compatibility::Error::Unsupported)
                                ));
                            }
                            invalid_standalone += 1;
                            continue;
                        }

                        let old = u32::from_be_bytes(original.image[16..20].try_into().unwrap());
                        let compensation = old.wrapping_sub(sum(&expected));
                        expected[16..20].copy_from_slice(&compensation.to_be_bytes());
                        let modified = correct_legacy(&original.image, target).unwrap();
                        let file = if original.info().layout == Layout::NormalScaledKey {
                            scaled += 1;
                            original.repack_with_checksum(&modified).unwrap()
                        } else {
                            original
                                .repack(&correct_normal(&original.image, target).unwrap())
                                .unwrap()
                        };
                        let corrected = load(&file).unwrap();
                        assert!(
                            corrected.image == expected,
                            "{component}: independent complete image"
                        );
                        assert_eq!(sum(&corrected.image), 0);
                        assert_eq!(
                            discover(&corrected.image).compare(&Observation::Known(
                                pioneer_optical::image::phase::Phase {
                                    assignment: target,
                                    interface: before.interface
                                }
                            )),
                            Some(true)
                        );
                        let reverse = correct_legacy(&corrected.image, before.assignment).unwrap();
                        let reverse_file = if original.info().layout == Layout::NormalScaledKey {
                            corrected.repack_with_checksum(&reverse).unwrap()
                        } else {
                            corrected
                                .repack(
                                    &correct_normal(&corrected.image, before.assignment).unwrap(),
                                )
                                .unwrap()
                        };
                        assert_eq!(reverse_file, bytes, "{component}: byte-exact original file");
                        let hardware = original.info().hardware_version.as_str();
                        let kernel_image = kernel.as_ref().map(|k| k.image.as_slice());
                        let installed = Firmware {
                            hardware,
                            normal: &corrected.image,
                            kernel: kernel_image,
                        };
                        let destination = Firmware {
                            hardware,
                            normal: &original.image,
                            kernel: kernel_image,
                        };
                        if matrix::discover(hardware, &original.image, kernel_image).is_none() {
                            assert!(
                                kernel.is_none(),
                                "{component}: unexpected unresolved identity with exact Kernel"
                            );
                            assert!(matches!(
                                compatibility::plan(installed, destination),
                                Err(compatibility::Error::UnresolvedIdentity)
                            ));
                            unresolved_identity += 1;
                        } else {
                            // SAT1 phase correction is suspended by the hardware matrix; the
                            // native operand oracle above stays proven, admission refuses.
                            assert!(
                                matches!(
                                    compatibility::plan(installed, destination),
                                    Err(compatibility::Error::Unsupported)
                                ),
                                "{component}: SAT1 phase correction must refuse"
                            );
                        }
                        complete += 1;
                        if complete % 10 == 0 {
                            eprintln!("SAT1 complete original files proved: {complete}");
                        }
                    }
                    (complete, scaled, unresolved_identity, invalid_standalone, deferred, deferred_valid)
                })
            })
            .collect();
        for handle in handles {
            let (c, s, u, i, d, v) = handle.join().expect("SAT1 proof worker failed");
            complete += c;
            scaled += s;
            unresolved_identity += u;
            invalid_standalone += i;
            deferred += d;
            deferred_valid += v;
        }
    });
    assert_eq!(complete + deferred_valid, 58);
    assert_eq!(deferred, 42);
    assert_eq!(scaled, 6);
    assert_eq!(invalid_standalone, 15);
    assert_eq!(unresolved_identity, 3);
}

#[test]
#[cfg(feature = "envelope")]
#[ignore = "requires PIONEER_LAYOUT_AUDIT, PIONEER_NORMAL_CORPUS and SHA-verified sat-paired-envelope-corpus"]
fn every_paired_original_file_proves_preparation_or_missing_kernel_boundary() {
    use pioneer_optical::{
        compatibility::{self, Firmware},
        envelope::{builder::NORMAL_SIGNATURE_RANGE, Envelope},
    };
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let files = audit.join("sat-paired-envelope-corpus");
    let rows: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("sat-paired-envelope-corpus.json")).unwrap(),
    )
    .unwrap();
    let mut valid = 0;
    let mut missing_authority = 0;
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|worker| {
                let (rows, files, corpus) = (&rows, &files, &corpus);
                scope.spawn(move || {
                    let mut valid = 0;
                    let mut missing_authority = 0;
                    for row in rows.as_array().unwrap().iter().skip(worker).step_by(8) {
                        let component = row["component"].as_str().unwrap();
                        let original_file =
                            std::fs::read(files.join(format!("{component}.enc"))).unwrap();
                        let kernel = row["kernel"].as_str().map(|sha| {
                            Envelope::load(
                                &std::fs::read(files.join(format!("{sha}.enc"))).unwrap(),
                            )
                            .unwrap()
                        });
                        let load = |bytes: &[u8]| match &kernel {
                            Some(k) => Envelope::load_with_kernel(bytes, k),
                            None => Envelope::load(bytes),
                        };
                        let original = load(&original_file)
                            .unwrap_or_else(|e| panic!("{component}: original {e:?}"));
                        assert!(
                            original.image
                                == std::fs::read(corpus.join(format!("{component}.bin"))).unwrap(),
                            "{component}: actual wrapper/cache bridge"
                        );
                        let sum = original.image.chunks_exact(4).fold(0u32, |s, w| {
                            s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
                        });
                        if sum != 0 {
                            assert!(
                                kernel.is_none(),
                                "{component}: invalid checksum despite exact Kernel"
                            );
                            assert!(!row["kernel_selection_reason"].as_str().unwrap().is_empty());
                            assert_eq!(
                                correct_normal(&original.image, Assignment::Direct),
                                Err(CorrectionError::InvalidNormal)
                            );
                            assert_eq!(
                                correct_normal(&original.image, Assignment::Swapped),
                                Err(CorrectionError::InvalidNormal)
                            );
                            missing_authority += 1;
                            continue;
                        }
                        assert!(
                            kernel.is_some(),
                            "{component}: expected associated Kernel authority"
                        );
                        let Observation::Known(before) = discover_pair(&original.image) else {
                            panic!("{component}: paired program");
                        };
                        let opposite = match before.assignment {
                            Assignment::Direct => Assignment::Swapped,
                            Assignment::Swapped => Assignment::Direct,
                        };
                        let hardware = original.info().hardware_version.as_str();
                        let kernel_image = kernel.as_ref().map(|k| k.image.as_slice());
                        // Build an independent expected byte result from the four proven native
                        // output operands and the additive checksum equation.
                        let mut expected = original.image.clone();
                        for offset in before.operands.iter().flatten() {
                            expected[*offset] ^= 1;
                        }
                        let changed_sum = expected.chunks_exact(4).fold(0u32, |s, w| {
                            s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
                        });
                        let old = u32::from_be_bytes(original.image[16..20].try_into().unwrap());
                        expected[16..20]
                            .copy_from_slice(&old.wrapping_sub(changed_sum).to_be_bytes());
                        let installed = Firmware {
                            hardware,
                            normal: &expected,
                            kernel: kernel_image,
                        };
                        let target = Firmware {
                            hardware,
                            normal: &original.image,
                            kernel: kernel_image,
                        };
                        // Phase correction is admitted by the native channel-swap, not a
                        // mechanism bundle; a pair the filter cannot support is a valid refusal.
                        let plan = match compatibility::plan(installed, target) {
                            Ok(plan) => plan,
                            Err(compatibility::Error::Unsupported) => continue,
                            Err(e) => panic!("{component}: plan {e:?}"),
                        };
                        let file = plan
                            .prepare_file(&original, kernel.as_ref())
                            .unwrap_or_else(|e| panic!("{component}: prepare {e:?}"))
                            .unwrap();
                        let corrected = load(&file).unwrap();
                        assert!(
                            corrected.image == expected,
                            "{component}: exact corrected oracle"
                        );
                        let raw_repack = original.repack(&expected).unwrap();
                        assert_eq!(file.len(), raw_repack.len());
                        assert!(
                            file.iter()
                                .zip(&raw_repack)
                                .enumerate()
                                .all(|(offset, (a, b))| a == b
                                    || NORMAL_SIGNATURE_RANGE.contains(&offset)),
                            "{component}: exact signature-only wrapper rewrite"
                        );
                        assert!(
                            correct_normal(&corrected.image, before.assignment).unwrap()
                                == original.image,
                            "{component}: complete reverse image"
                        );
                        assert!(
                            correct_normal(&corrected.image, opposite).unwrap() == corrected.image,
                            "{component}: complete idempotence"
                        );
                        valid += 1;
                        if valid % 50 == 0 {
                            eprintln!("paired original files proved: {valid}");
                        }
                    }
                    (valid, missing_authority)
                })
            })
            .collect();
        for handle in handles {
            let (v, m) = handle.join().expect("paired-file proof worker failed");
            valid += v;
            missing_authority += m;
        }
    });
    assert_eq!((valid, missing_authority), (346, 111));
}
