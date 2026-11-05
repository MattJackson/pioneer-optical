//! Independent 0.17.3 reviewed outputs, never production correction recipes.
//! References: the reviewed definitions removed by e922789, recovered from
//! e922789^:src/filters/phase/mechanism/contracts.rs. Sparse native fixtures run
//! in CI; optional corpus tests also prove complete original/output SHA values.
#![cfg(feature = "envelope")]
use pioneer_optical::filters::phase::{bundle, native};
use sha2::{Digest, Sha256};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn native_spans(hash: &str) -> Vec<u8> {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-native-spans.json")).unwrap();
    let fixture = fixtures
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["original_sha256"].as_str() == Some(hash))
        .unwrap();
    let mut image = vec![0xff; fixture["size"].as_u64().unwrap() as usize];
    for span in fixture["spans"].as_array().unwrap() {
        let at = span[0].as_u64().unwrap() as usize;
        let bytes = hex(span[1].as_str().unwrap());
        image[at..at + bytes.len()].copy_from_slice(&bytes);
    }
    image
}

#[test]
fn native_oem_composition_preserves_donor_conventions_in_both_sat9_directions() {
    let images = [
        native_spans("3711cd5cdde5b5e7f288ccd7bc7fe1100eb6de5e40f3d0ffdcc528fb93ebeb46"),
        native_spans("c93736b1fc66c7ada2d586044bf5d8a50a622b65e2f1fe6e74ad212f254adc1b"),
    ];
    for (target, donor) in [(&images[0], &images[1]), (&images[1], &images[0])] {
        let changed =
            bundle::composition::transplant(target, donor, test_space(), Some(0x600..0x700))
                .unwrap();
        let mut expected = bundle::bind(donor).unwrap();
        expected.table_select_0x28f = bundle::bind(target).unwrap().table_select_0x28f;
        assert_eq!(bundle::bind(&changed).unwrap(), expected);
        assert_eq!(
            native::calibration::observe(&changed).unwrap(),
            native::calibration::observe(donor).unwrap()
        );
        assert_eq!(&changed[..24], &target[..24]);
        let destination = bundle::waveforms::resources::observe(target).unwrap();
        let source = bundle::waveforms::resources::observe(donor).unwrap();
        for (to, from) in destination
            .selected
            .motion
            .iter()
            .chain(&destination.selected.coefficients)
            .zip(
                source
                    .selected
                    .motion
                    .iter()
                    .chain(&source.selected.coefficients),
            )
        {
            assert_eq!(&changed[to.clone()], &donor[from.clone()]);
        }
    }
}

#[test]
fn native_source_transplants_copy_donor_bodies_and_keep_target_helpers() {
    use h8_asm::{isa::decode_insn, Mode, Target};
    use pioneer_optical::image::layout::Observation;
    let body = |image: &[u8], start: usize| {
        let mut at = start;
        let mut calls = Vec::new();
        loop {
            let decoded = decode_insn(&image[at..], Target::H8S2000, Mode::Advanced).unwrap();
            if decoded.insn.mnemonic == "JSR" {
                calls.push(at - start + 1);
            }
            at += decoded.len;
            if decoded.insn.mnemonic == "RTS" {
                break;
            }
            assert!(at - start < 128);
        }
        (image[start..at].to_vec(), calls)
    };
    for hashes in [
        [
            "3711cd5cdde5b5e7f288ccd7bc7fe1100eb6de5e40f3d0ffdcc528fb93ebeb46",
            "c93736b1fc66c7ada2d586044bf5d8a50a622b65e2f1fe6e74ad212f254adc1b",
        ],
        [
            "84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750",
            "87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1",
        ],
    ] {
        let images = hashes.map(native_spans);
        for (target, donor) in [(&images[0], &images[1]), (&images[1], &images[0])] {
            let Observation::Known(before) = native::discover_pair(target) else {
                panic!("target pair");
            };
            let Observation::Known(source) = native::discover_pair(donor) else {
                panic!("donor pair");
            };
            let changed = native::sources::transplant(target, donor, Some(0x600..0x640)).unwrap();
            let Observation::Known(after) = native::discover_pair(&changed) else {
                panic!("output pair");
            };
            assert_eq!(after.assignment, source.assignment);
            for word in 0..2 {
                let output = donor[source.operands[word][1]];
                let role = before
                    .operands
                    .iter()
                    .position(|operands| target[operands[1]] == output)
                    .unwrap();
                let (old, old_calls) = body(target, before.functions[role]);
                let (mut expected, donor_calls) = body(donor, source.functions[word]);
                assert_eq!(old_calls.len(), donor_calls.len());
                for (from, to) in old_calls.into_iter().zip(donor_calls) {
                    expected[to..to + 3].copy_from_slice(&old[from..from + 3]);
                }
                assert_eq!(body(&changed, after.functions[word]).0, expected);
            }
            for (at, (old, new)) in target.iter().zip(&changed).enumerate() {
                if old != new {
                    assert!(
                        (0x600..0x640).contains(&at)
                            || before
                                .functions
                                .iter()
                                .any(|start| (*start..*start + body(target, *start).0.len())
                                    .contains(&at))
                    );
                }
            }
        }
    }
}

#[test]
fn native_plain_loader_transplants_oem_bytes_with_only_address_relocations() {
    use bundle::waveforms::loader::{self, Table};
    let images = [
        native_spans("3711cd5cdde5b5e7f288ccd7bc7fe1100eb6de5e40f3d0ffdcc528fb93ebeb46"),
        native_spans("c93736b1fc66c7ada2d586044bf5d8a50a622b65e2f1fe6e74ad212f254adc1b"),
    ];
    for (target, donor) in [(&images[0], &images[1]), (&images[1], &images[0])] {
        let before = loader::observe(target).unwrap();
        let source = loader::observe(donor).unwrap();
        let changed =
            loader::transplant_plain(target, donor, before.tables.unwrap(), Some(0x600..0x700))
                .unwrap();
        let after = loader::observe(&changed).unwrap();
        assert_eq!(after.loader, source.loader);
        let mut expected = donor[source.program.clone()].to_vec();
        let mut relocations = vec![
            (source.coefficient_getter, before.coefficient_getter, 3),
            (source.writer, before.writer, 4),
            (source.readback, before.readback, 3),
        ];
        for (from, to) in source
            .tables
            .unwrap()
            .into_iter()
            .zip(before.tables.unwrap())
        {
            let (Table::Literal(from), Table::Literal(to)) = (from, to) else {
                panic!("literal SAT9 tables");
            };
            relocations.push((from, to, 4));
        }
        // These held native bodies contain only the listed address operands.
        // Match against the immutable donor so relocation values cannot cascade.
        let original = expected.clone();
        for (from, to, width) in relocations {
            let from = from.to_be_bytes();
            let to = to.to_be_bytes();
            let mut count = 0;
            for at in 0..=original.len() - width {
                if original[at..at + width] == from[4 - width..] {
                    expected[at..at + width].copy_from_slice(&to[4 - width..]);
                    count += 1;
                }
            }
            assert!(count > 0);
        }
        assert_eq!(&changed[after.program.clone()], &expected);
        for (at, (old, new)) in target.iter().zip(&changed).enumerate() {
            if old != new {
                assert!(before.program.contains(&at) || (0x600..0x700).contains(&at));
            }
        }
        assert_eq!(&changed[..24], &target[..24]);
    }
}

#[test]
fn computed_loader_transplant_retains_oem_instructions_and_target_calls() {
    use bundle::waveforms::loader::{self, Table};
    let original = native_spans("84b76c71728dd9c27d27c3cb974f062b55c59a7a26145c858dc45cc1a79db66a");
    let before = loader::observe(&original).unwrap();
    let Some([Table::Literal(table), _]) = before.tables else {
        panic!("computed table");
    };
    assert_eq!(
        loader::transplant_computed(&original, &original, table).unwrap(),
        original
    );
    // Relocate the donor's multiply helper consistently, proving its addresses
    // are not transplanted into the target. No algorithm bytes are regenerated.
    let mut donor = original.clone();
    for field in [49, 95, 199] {
        donor[before.program.start + field + 2] ^= 2;
    }
    loader::observe(&donor).unwrap();
    assert_eq!(
        loader::transplant_computed(&original, &donor, table).unwrap(),
        original
    );
    for direction in [bundle::Loader::Ascending, bundle::Loader::Descending] {
        assert_eq!(
            loader::rewrite(&original, direction, [table; 2], None),
            Err(loader::Error::ComputedUnsupported)
        );
    }
}

#[test]
fn generated_evaluators_bind_basis_and_preserve_distinct_calibration_sources() {
    use bundle::waveforms::resources::evaluators;
    let first = native_spans("8037cdb3ae67e04a82aa3e9b7a0f52202e17f1e39d1f50b894158d9be0cec898");
    let second = native_spans("99ba77ae1cedc967096c770b21c066d04a5163f1c5a4aa82f27584c6faced796");
    let a = evaluators::observe(&first).unwrap();
    let b = evaluators::observe(&second).unwrap();
    assert_eq!(a.basis, 0x24eece..0x24efce);
    assert_eq!(b.basis, 0x1891b6..0x1892b6);
    assert_eq!(a.calibration_getter, 0x5d6fd0);
    assert_eq!(b.calibration_getter, 0x542ad4);
    // Held native data establishes a quarter-cycle basis difference; this is
    // not a claim that their calibration readers or complete mechanisms agree.
    for row in 0..64 {
        let x = a.basis.start + ((row + 48) % 64) * 4;
        let y = b.basis.start + row * 4;
        assert_eq!(&first[x..x + 4], &second[y..y + 4]);
    }
    assert_eq!(
        evaluators::calibration(&second, &b).unwrap().1,
        evaluators::Calibration::Constants([675, 1481, -646, -1476, 675, 1476, -657, -1486])
    );
    assert_eq!(
        evaluators::calibration(&first, &a).unwrap().1,
        evaluators::Calibration::Parameters {
            indices: [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37],
            defaults: [474, 1106, -523, -1205, 481, 1135, -495, -1136],
            helpers: [0x5ec50c, 0x5ecbfa],
        }
    );
    for (target, installed, binding, shift) in
        [(&first, &second, &a, 48), (&second, &first, &b, 16)]
    {
        let changed = evaluators::rewrite_basis(target, installed).unwrap();
        let mut expected = target.clone();
        for row in 0..64 {
            let from = binding.basis.start + ((row + shift) % 64) * 4;
            let to = binding.basis.start + row * 4;
            expected[to..to + 4].copy_from_slice(&target[from..from + 4]);
        }
        assert_eq!(changed, expected);
        assert_eq!(
            evaluators::calibration(&changed, binding).unwrap(),
            evaluators::calibration(target, binding).unwrap()
        );
    }
    for (image, binding, jump, helper) in [(&first, a, 33, 65), (&second, b, 43, 75)] {
        let program = binding.programs.last().unwrap();
        // Split form's last body has offsets four bytes later than its first.
        let (jump, helper) = if program.len() == 212 {
            (jump + 2, helper + 4)
        } else {
            (jump, helper)
        };
        let mut broken = image.clone();
        broken[program.start + jump + 2] ^= 2;
        assert!(evaluators::observe(&broken).is_err());
        let mut broken = image.clone();
        broken[program.start + helper + 2] ^= 2;
        assert!(evaluators::observe(&broken).is_err());
    }
}

#[test]
fn native_xd04_motion_roles_do_not_require_an_assumed_dsp_program() {
    let image = native_spans("4b390d0e70e2d1006b58b4a3c7653f4b0a77f6fcf1c752cbc21f3d420b2cea5c");
    let motion = bundle::waveforms::resources::observe_literal_motion(&image).unwrap();
    assert_eq!(motion.dispatch, 0x1c3f22..0x1c3fcc);
    assert_eq!(motion.ordinary, 0x24b3ee..0x24b4ee);
    assert_eq!(motion.motion, [0x24b4ee..0x24b5ee, 0x24b5ee..0x24b6ee]);
    let mut changed = image.clone();
    changed[motion.dispatch.start + 137] ^= 2;
    assert!(bundle::waveforms::resources::observe_literal_motion(&changed).is_err());
}

fn test_space() -> bundle::composition::Space {
    bundle::composition::Space {
        conversions: [Some(0x400..0x440), Some(0x440..0x484), Some(0x484..0x4b8)],
        calibration: Some(0x4b8..0x4fc),
        sources: Some(0x4fc..0x52c),
    }
}

#[test]
fn native_sparse_composition_matches_every_reviewed_changed_byte_in_ci() {
    // Native held code/data spans remain at their original addresses. All other
    // bytes are erased: these are incomplete test images, never flash inputs.
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-mechanism-known-answers.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let target = native_spans(case["target"].as_str().unwrap());
        let installed = native_spans(case["calibration_donor"].as_str().unwrap());
        let actual = bundle::composition::rewrite(&target, &installed, test_space())
            .unwrap_or_else(|e| panic!("{}: {e:?}", case["id"]));
        let mut expected = target.clone();
        for replacement in case["reps"].as_array().unwrap() {
            let at = replacement[0].as_u64().unwrap() as usize;
            let before = hex(replacement[1].as_str().unwrap());
            let after = hex(replacement[2].as_str().unwrap());
            assert_eq!(
                target[at..at + before.len()],
                before,
                "{}: native guard",
                case["id"]
            );
            expected[at..at + after.len()].copy_from_slice(&after);
        }
        assert_eq!(
            actual, expected,
            "{}: all output bytes and diff whitelist",
            case["id"]
        );
    }
}

#[test]
fn native_sparse_sat9_composes_both_directions_without_other_filter_admission() {
    let images = [
        native_spans("3711cd5cdde5b5e7f288ccd7bc7fe1100eb6de5e40f3d0ffdcc528fb93ebeb46"),
        native_spans("c93736b1fc66c7ada2d586044bf5d8a50a622b65e2f1fe6e74ad212f254adc1b"),
    ];
    for (target, installed) in [(&images[0], &images[1]), (&images[1], &images[0])] {
        let actual = bundle::composition::rewrite(target, installed, test_space()).unwrap();
        let desired = bundle::bind(installed).unwrap();
        let observed = bundle::bind(&actual).unwrap();
        assert_eq!(
            observed,
            bundle::Bundle {
                loader: if desired.loader == bundle::Loader::AscendingNegated17 {
                    bundle::Loader::Ascending
                } else {
                    desired.loader
                },
                ..desired
            }
        );
        assert_eq!(actual[..24], target[..24]);
        let roles = bundle::waveforms::resources::observe(target).unwrap();
        let donor = bundle::waveforms::resources::observe(installed).unwrap();
        for (to, from) in roles.selected.motion.iter().zip(donor.selected.motion) {
            assert_eq!(actual[to.clone()], installed[from]);
        }
    }
}

#[test]
fn native_sparse_resources_refuse_changed_branches_aliases_and_ambiguous_consumers() {
    let target = native_spans("84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750");
    let roles = bundle::waveforms::resources::observe(&target).unwrap();
    let initializer = roles.initializer.unwrap();
    for (offset, bytes) in [
        (roles.dispatch.start + 16, vec![0x59]),
        (initializer.start + 74, vec![0, 0, 0x31, 0x24]),
    ] {
        let mut changed = target.clone();
        changed[offset..offset + bytes.len()].copy_from_slice(&bytes);
        assert!(bundle::waveforms::resources::observe(&changed).is_err());
    }
    let mut duplicate = target.clone();
    duplicate[0x10000..0x10000 + roles.dispatch.len()]
        .copy_from_slice(&target[roles.dispatch.clone()]);
    assert!(bundle::waveforms::resources::observe(&duplicate).is_err());

    let installed =
        native_spans("87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1");
    let mut occupied = test_space();
    occupied.sources = Some(roles.selected.motion[0].clone());
    assert_eq!(
        bundle::composition::rewrite(&target, &installed, occupied),
        Err(bundle::composition::Error::VerificationFailed)
    );
}

#[test]
fn native_sparse_bundle_uses_complete_loader_negation_and_checks_resource_relationships() {
    for (hash, computed) in [
        (
            "368543ee7e7edb433c6378a0b75b9e761e810f97413bb9f617bbef421663c725",
            false,
        ),
        (
            "84b76c71728dd9c27d27c3cb974f062b55c59a7a26145c858dc45cc1a79db66a",
            true,
        ),
    ] {
        let image = native_spans(hash);
        let loader = bundle::waveforms::loader::observe(&image).unwrap();
        assert_eq!(loader.computed, computed);
        assert_eq!(loader.loader, bundle::Loader::AscendingNegated17);
        assert_eq!(bundle::bind(&image).unwrap().loader, loader.loader);
        let mut bad_leaf = image.clone();
        bad_leaf[loader.coefficient_getter as usize - 0x410000] ^= 1;
        assert_eq!(
            bundle::waveforms::loader::observe(&bad_leaf),
            Err(bundle::waveforms::loader::Error::ResourceMismatch)
        );
        if computed {
            for offset in [23, 165, 201, 221] {
                let mut mismatched = image.clone();
                mismatched[loader.program.start + offset] ^= 2;
                assert_eq!(
                    bundle::waveforms::loader::observe(&mismatched),
                    Err(bundle::waveforms::loader::Error::ResourceMismatch)
                );
            }
        }
    }
}

#[test]
fn native_sparse_software_dispatch_distinguishes_image_choices_from_runtime_producers() {
    use bundle::waveforms::resources::software::{self, Source};
    for (hash, modes, addresses, runtime) in [
        (
            "368543ee7e7edb433c6378a0b75b9e761e810f97413bb9f617bbef421663c725",
            [Some(1), Some(3), Some(4), None],
            [0x5b22b0, 0x5b23b0, 0x5b23b0, 0x5b21b0],
            false,
        ),
        (
            "8037cdb3ae67e04a82aa3e9b7a0f52202e17f1e39d1f50b894158d9be0cec898",
            [Some(1), Some(3), Some(2), None],
            [0xa078d6, 0xa07ad6, 0xa079d6, 0xa077d6],
            true,
        ),
        (
            "99ba77ae1cedc967096c770b21c066d04a5163f1c5a4aa82f27584c6faced796",
            [Some(1), Some(4), Some(3), None],
            [0xa06a2e, 0xa06c2e, 0xa06b2e, 0xa0692e],
            true,
        ),
    ] {
        let image = native_spans(hash);
        let binding = software::observe(&image).unwrap();
        assert_eq!(binding.choices.len(), 4);
        for ((mode, source), (expected_mode, address)) in
            binding.choices.iter().zip(modes.into_iter().zip(addresses))
        {
            assert_eq!(*mode, expected_mode);
            assert_eq!(
                source,
                &if runtime {
                    Source::Runtime(address)
                } else {
                    let at = (address - 0x410000) as usize;
                    Source::Image(at..at + 256)
                }
            );
        }
        if runtime {
            let producer = software::observe_producer(&image).unwrap();
            assert!(matches!(producer.program.len(), 274 | 328));
            let mut broken = image.clone();
            broken[producer.program.start + 125] ^= 1;
            assert!(software::observe_producer(&broken).is_err());
            let mut broken = image.clone();
            broken[producer.initializer.start + 13] ^= 1;
            assert!(software::observe_producer(&broken).is_err());
            let mut broken = image.clone();
            broken[producer.program.start + 46] ^= 1;
            assert!(software::observe_producer(&broken).is_err());
        }
        let mut mismatch = image.clone();
        let store = binding.selector.end - 3;
        mismatch[store] ^= 2;
        assert!(software::observe(&mismatch).is_err());
        let mut broken_branch = image.clone();
        broken_branch[binding.dispatch.start + 23] ^= 2;
        assert!(software::observe(&broken_branch).is_err());
    }
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
#[ignore = "requires PIONEER_NORMAL_CORPUS with the held phase references"]
fn native_table_roles_match_reviewed_data_without_model_or_address_recipes() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-mechanism-known-answers.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let read = |key: &str| {
            let hash = case[key].as_str().unwrap();
            let bytes = std::fs::read(root.join(format!("{hash}.bin"))).unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(&bytes)), hash);
            bytes
        };
        let target = read("target");
        let installed = read("calibration_donor");
        let mut composed = bundle::composition::rewrite(
            &target,
            &installed,
            bundle::composition::Space {
                conversions: [Some(0x400..0x440), Some(0x440..0x484), Some(0x484..0x4b8)],
                calibration: Some(0x4b8..0x4fc),
                sources: Some(0x4fc..0x52c),
            },
        )
        .unwrap_or_else(|e| panic!("{}: {e:?}", case["id"]));
        composed[16..20].fill(0);
        let sum = composed.chunks_exact(4).fold(0u32, |s, w| {
            s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
        });
        composed[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
        assert_eq!(
            format!("{:x}", Sha256::digest(&composed)),
            case["output"].as_str().unwrap(),
            "{}: complete composed image",
            case["id"]
        );
        let target_roles = bundle::waveforms::resources::observe(&target).unwrap();
        let installed_roles = bundle::waveforms::resources::observe(&installed).unwrap();
        let original = target.clone();
        let mut bad = target.clone();
        // A changed branch must invalidate the complete dispatch grammar.
        bad[target_roles.dispatch.start + 16] ^= 1;
        assert!(bundle::waveforms::resources::observe(&bad).is_err());
        assert_eq!(target, original);
        // Keep both callers and complete native templates present, but change
        // one motion-pointer initializer store. Its relationship must fail.
        if let Some(initializer) = &target_roles.initializer {
            let mut bad = target.clone();
            bad[initializer.start + 77] ^= 2;
            assert_eq!(
                bundle::waveforms::resources::observe(&bad),
                Err(bundle::waveforms::resources::Error::ResourceMismatch)
            );
        }
        let replacements = case["reps"].as_array().unwrap();
        let waveforms = bundle::waveforms::rewrite(&target, &installed).unwrap();
        let loader = bundle::waveforms::loader::observe(&target).unwrap();
        let allowed: Vec<_> = std::iter::once(loader.program)
            .chain(
                std::iter::once(&target_roles.selected)
                    .chain(&target_roles.erased_parameter)
                    .flat_map(|t| t.motion.clone()),
            )
            .chain(target_roles.selected.coefficients.clone())
            .collect();
        let mut reviewed = target.clone();
        for replacement in replacements {
            let at = replacement[0].as_u64().unwrap() as usize;
            let bytes = hex(replacement[2].as_str().unwrap());
            reviewed[at..at + bytes.len()].copy_from_slice(&bytes);
        }
        reviewed[16..20].copy_from_slice(&composed[16..20]);
        assert_eq!(
            composed, reviewed,
            "{}: every complete output byte",
            case["id"]
        );
        for range in &allowed {
            assert_eq!(
                waveforms[range.clone()],
                reviewed[range.clone()],
                "{}: waveform span {range:?}",
                case["id"]
            );
        }
        for (at, (before, after)) in target.iter().zip(&waveforms).enumerate() {
            assert!(
                before == after || allowed.iter().any(|range| range.contains(&at)),
                "{}: waveform escaped whitelist at {at:#x}",
                case["id"]
            );
        }
        for roles in std::iter::once(&target_roles.selected).chain(&target_roles.erased_parameter) {
            for (i, span) in roles.motion.iter().enumerate() {
                let replacement = replacements
                    .iter()
                    .find(|r| {
                        r[0].as_u64().unwrap() as usize == span.start
                            && hex(r[1].as_str().unwrap()).len() == span.len()
                    })
                    .expect("motion role has a reviewed replacement");
                assert_eq!(target[span.clone()], hex(replacement[1].as_str().unwrap()));
                assert_eq!(
                    installed[installed_roles.selected.motion[i].clone()],
                    hex(replacement[2].as_str().unwrap()),
                    "{}: motion role {i}",
                    case["id"]
                );
            }
        }
        if target_roles.initializer.is_none() {
            let convention = bundle::waveforms::loader::observe(&installed)
                .unwrap()
                .loader;
            for (i, span) in target_roles.selected.coefficients.iter().enumerate() {
                let replacement = replacements
                    .iter()
                    .find(|r| {
                        r[0].as_u64().unwrap() as usize == span.start
                            && hex(r[1].as_str().unwrap()).len() == span.len()
                    })
                    .expect("coefficient role has a reviewed replacement");
                let donor: &[u8; 72] = installed[installed_roles.selected.coefficients[i].clone()]
                    .try_into()
                    .unwrap();
                assert_eq!(
                    bundle::waveforms::plain_coefficients(donor, convention).as_slice(),
                    hex(replacement[2].as_str().unwrap())
                );
            }
        }
    }
    for hash in [
        "3711cd5cdde5b5e7f288ccd7bc7fe1100eb6de5e40f3d0ffdcc528fb93ebeb46",
        "c93736b1fc66c7ada2d586044bf5d8a50a622b65e2f1fe6e74ad212f254adc1b",
    ] {
        let bytes = std::fs::read(root.join(format!("{hash}.bin"))).unwrap();
        let binding = bundle::waveforms::resources::observe(&bytes).unwrap();
        assert!(
            binding.initializer.is_none(),
            "held SAT9 uses literal tables"
        );
    }
}

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

#[test]
#[ignore = "requires PIONEER_HOARD; targeted generated-waveform stage coverage"]
fn generated_basis_stage_covers_every_held_runtime_producer() {
    use bundle::waveforms::resources::{evaluators, software};
    let root = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").unwrap());
    let (packages, _) = page::hoard_packages(&root).unwrap();
    let donors = [
        native_spans("8037cdb3ae67e04a82aa3e9b7a0f52202e17f1e39d1f50b894158d9be0cec898"),
        native_spans("99ba77ae1cedc967096c770b21c066d04a5163f1c5a4aa82f27584c6faced796"),
    ];
    let bases: Vec<_> = donors
        .iter()
        .map(|image| {
            let binding = evaluators::observe(image).unwrap();
            image[binding.basis].to_vec()
        })
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut tested = 0;
    let mut parameters = 0;
    for package in packages {
        if !(package.hardware.starts_with("SAT 8") || package.hardware.starts_with("SAT 9"))
            || !seen.insert(package.component.clone())
        {
            continue;
        }
        let decoded = page::decode(&root, &package).unwrap();
        let target = &decoded.normal.image;
        let Ok(consumer) = software::observe(target) else {
            continue;
        };
        if !consumer
            .choices
            .iter()
            .any(|(_, source)| matches!(source, software::Source::Runtime(_)))
        {
            continue;
        }
        let binding = evaluators::observe(target)
            .unwrap_or_else(|error| panic!("{}: {error:?}", package.component));
        let calibration = evaluators::calibration(target, &binding).unwrap();
        parameters += usize::from(matches!(
            calibration.1,
            evaluators::Calibration::Parameters { .. }
        ));
        for (donor, basis) in donors.iter().zip(&bases) {
            let changed = evaluators::rewrite_basis(target, donor)
                .unwrap_or_else(|error| panic!("{}: {error:?}", package.component));
            assert_eq!(&changed[binding.basis.clone()], basis);
            assert_eq!(
                &changed[..binding.basis.start],
                &target[..binding.basis.start]
            );
            assert_eq!(&changed[binding.basis.end..], &target[binding.basis.end..]);
            assert_eq!(
                evaluators::calibration(&changed, &binding).unwrap(),
                calibration
            );
            let restored = evaluators::rewrite_basis(&changed, target).unwrap();
            assert_eq!(restored, *target);
        }
        tested += 1;
    }
    println!(
        "generated basis stage: {tested} images, {parameters} parameter-backed, {} image-constant",
        tested - parameters
    );
    assert!(
        tested >= 162,
        "held runtime-table coverage unexpectedly shrank"
    );
    assert!(parameters >= 68);
}
