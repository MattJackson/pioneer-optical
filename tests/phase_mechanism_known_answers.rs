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
fn native_oem_all_reference_pairs_compose_with_small_routine_spills() {
    for (id, target_hash, donor_hash) in native_oem_pairs() {
        let target = native_spans(&target_hash);
        let donor = native_spans(&donor_hash);
        let mut space = test_space();
        // Each reservation is smaller than every complete conversion routine.
        // Whole-body detours cannot satisfy this placement contract.
        space.conversions = [Some(0x400..0x418), Some(0x440..0x458), Some(0x484..0x49c)];
        space.calibration = Some(0x4b8..0x4ee);
        space.sources = None;
        use bundle::waveforms::loader;
        let before_loader = loader::observe(&target).unwrap();
        let source_loader = loader::observe(&donor).unwrap();
        let loader_space = if source_loader.program.len() > before_loader.program.len() {
            Some(
                if matches!(source_loader.tables, Some([loader::Table::Pointer(_), _])) {
                    0x600..0x620 // 22-byte suffix plus two four-byte pointer cells.
                } else {
                    0x600..0x610 // SAT9's 16-byte suffix.
                },
            )
        } else {
            None
        };
        let changed = bundle::composition::transplant(&target, &donor, space, loader_space.clone())
            .unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let after_loader = loader::observe(&changed).unwrap();
        if let Some(reservation) = loader_space {
            assert_eq!(after_loader.spans.len(), 2, "{id}");
            assert!(after_loader.program.len() <= before_loader.program.len());
            let spill = &after_loader.spans[1];
            assert!(spill.len() <= 22 && spill.len() < source_loader.program.len());
            assert!(spill.start >= reservation.start && spill.end <= reservation.end);
            // A detour into an instruction interior must not bind as OEM code.
            use h8_asm::{
                isa::{decode_insn, encode_insn, Ea, Operand},
                Mode, Target,
            };
            let at = after_loader.program.end - 4;
            let mut jump = decode_insn(&changed[at..], Target::H8S2000, Mode::Advanced)
                .unwrap()
                .insn;
            assert_eq!(jump.mnemonic, "JMP");
            if let Operand::Address(Ea::Absolute { value, .. }) = &mut jump.operands[0] {
                *value += 2;
            }
            let encoded = encode_insn(jump, Target::H8S2000, Mode::Advanced).unwrap();
            let mut broken = changed.clone();
            broken[at..at + encoded.len()].copy_from_slice(&encoded);
            assert!(
                loader::observe(&broken).is_err(),
                "{id}: corrupt split target"
            );
        }
        let mut expected = bundle::bind(&donor).unwrap();
        expected.table_select_0x28f = bundle::bind(&target).unwrap().table_select_0x28f;
        assert_eq!(bundle::bind(&changed).unwrap(), expected, "{id}");
        assert_eq!(&changed[..24], &target[..24]);
        // The unused remainder of each old whole-body reservation stays erased.
        for gap in [0x418..0x440, 0x458..0x484, 0x49c..0x4b8] {
            assert_eq!(&changed[gap.clone()], &target[gap], "{id}");
        }
    }
}

#[test]
fn corrected_table_graph_rebinds_literal_and_image_pointer_loaders() {
    use bundle::waveforms::{
        loader::{self, Table},
        resources,
    };
    for (id, target_hash, donor_hash) in native_oem_pairs() {
        let target = native_spans(&target_hash);
        let donor = native_spans(&donor_hash);
        let changed =
            bundle::composition::transplant(&target, &donor, test_space(), Some(0x600..0x700))
                .unwrap();
        let repeated = bundle::waveforms::transplant(&changed, &donor, None)
            .unwrap_or_else(|e| panic!("{id}: repeated waveform correction: {e:?}"));
        assert_eq!(repeated, changed, "{id}: waveform correction is idempotent");
        let repeated = bundle::composition::transplant(
            &changed,
            &donor,
            bundle::composition::Space::default(),
            None,
        )
        .unwrap_or_else(|e| panic!("{id}: repeated composition: {e:?}"));
        assert_eq!(
            repeated, changed,
            "{id}: complete composition is idempotent"
        );
        let graph = resources::observe(&changed).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let source = resources::observe(&donor).unwrap();
        for tables in std::iter::once(&graph.selected).chain(&graph.erased_parameter) {
            for (to, from) in tables.motion.iter().chain(&tables.coefficients).zip(
                source
                    .selected
                    .motion
                    .iter()
                    .chain(&source.selected.coefficients),
            ) {
                assert_eq!(
                    &changed[to.clone()],
                    &donor[from.clone()],
                    "{id}: consumed data"
                );
            }
        }
        if let Some(tables) = loader::observe(&changed).unwrap().tables {
            for table in tables {
                if let Table::Pointer(cell) = table {
                    if cell < 0x410000 {
                        continue;
                    }
                    let at = (cell - 0x410000) as usize;
                    let mut broken = changed.clone();
                    broken[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
                    assert!(
                        resources::observe(&broken).is_err(),
                        "{id}: bad image pointer"
                    );
                    broken[at..at + 4].copy_from_slice(&cell.to_be_bytes());
                    assert!(
                        resources::observe(&broken).is_err(),
                        "{id}: pointer cell overlaps consumed coefficient data"
                    );
                }
            }
        }
    }
}

#[test]
fn native_oem_ud02_composition_relocates_indirect_loads_without_new_instructions() {
    use bundle::waveforms::{loader, resources};
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-mechanism-known-answers.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let target = native_spans(case["target"].as_str().unwrap());
        let donor = native_spans(case["calibration_donor"].as_str().unwrap());
        let source = loader::observe(&donor).unwrap();
        let destination = resources::observe(&target).unwrap();
        let changed =
            bundle::composition::transplant(&target, &donor, test_space(), Some(0x600..0x700))
                .unwrap_or_else(|error| panic!("{}: {error:?}", case["id"]));
        let after = loader::observe(&changed).unwrap();
        assert_eq!(after.loader, source.loader);
        let mut expected = bundle::bind(&donor).unwrap();
        expected.table_select_0x28f = bundle::bind(&target).unwrap().table_select_0x28f;
        assert_eq!(bundle::bind(&changed).unwrap(), expected);
        for (role, table) in after.tables.unwrap().iter().enumerate() {
            let address = match table {
                loader::Table::Literal(address) => *address,
                loader::Table::Pointer(slot) => {
                    let at = (*slot - 0x410000) as usize;
                    assert!((0x6f8..0x700).contains(&at));
                    u32::from_be_bytes(changed[at..at + 4].try_into().unwrap())
                }
            };
            assert_eq!(
                address as usize - 0x410000,
                destination.selected.coefficients[role].start
            );
        }
        // Read-only initialization predicate bytes are retained verbatim.
        if let Some(initializer) = destination.initializer {
            assert_eq!(&changed[initializer.clone()], &target[initializer]);
        }
        if matches!(source.tables, Some([loader::Table::Pointer(_), _])) {
            for bad in [
                0x600..0x608,
                0x600..0x6ff,
                0x400..0x700,
                0x600..target.len() + 4,
            ] {
                assert!(
                    bundle::composition::transplant(&target, &donor, test_space(), Some(bad))
                        .is_err()
                );
            }
            assert_eq!(
                loader::logical_program(&changed).unwrap().len(),
                source.program.len()
            );
            let mut expected = donor[source.program.clone()].to_vec();
            let before = loader::observe(&target).unwrap();
            for (field, address) in [(18, 0x4106f8u32), (28, 0x4106fc), (132, before.writer)] {
                expected[field..field + 4].copy_from_slice(&address.to_be_bytes());
            }
            for (field, address) in [
                (67, before.coefficient_getter),
                (107, before.coefficient_getter),
                (179, before.readback),
            ] {
                expected[field..field + 3].copy_from_slice(&address.to_be_bytes()[1..]);
            }
            assert_eq!(&loader::logical_program(&changed).unwrap(), &expected);
        }
    }
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
        let mut bytes = Vec::new();
        let mut calls = Vec::new();
        let mut jumps = 0;
        loop {
            let decoded = decode_insn(&image[at..], Target::H8S2000, Mode::Advanced).unwrap();
            if decoded.insn.mnemonic == "JMP" {
                use h8_asm::isa::{Ea, Operand};
                let Operand::Address(Ea::Absolute { value, bits: 24 }) = decoded.insn.operands[0]
                else {
                    panic!("jump operand");
                };
                jumps += 1;
                assert_eq!(jumps, 1);
                at = (value - 0x410000) as usize;
                continue;
            }
            if decoded.insn.mnemonic == "JSR" {
                calls.push(bytes.len() + 1);
            }
            bytes.extend_from_slice(&image[at..at + decoded.len]);
            at += decoded.len;
            if decoded.insn.mnemonic == "RTS" {
                break;
            }
            assert!(bytes.len() < 128);
        }
        (bytes, calls)
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
            let changed = native::sources::transplant(target, donor, None).unwrap();
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
                let identity_call = donor_calls[0] - 1;
                for (from, to) in old_calls.into_iter().zip(donor_calls) {
                    expected[to..to + 3].copy_from_slice(&old[from..from + 3]);
                }
                let call = decode_insn(&expected[identity_call..], Target::H8S2000, Mode::Advanced)
                    .unwrap();
                let h8_asm::isa::Operand::Address(h8_asm::isa::Ea::Absolute { value, .. }) =
                    call.insn.operands[0]
                else {
                    panic!("absolute call");
                };
                assert_eq!(
                    decode_insn(
                        &target[(value - 0x410000) as usize..],
                        Target::H8S2000,
                        Mode::Advanced
                    )
                    .unwrap()
                    .insn
                    .mnemonic,
                    "RTS"
                );
                expected.drain(identity_call..identity_call + call.len);
                assert_eq!(body(&changed, after.functions[word]).0, expected);
            }
            assert_eq!(
                native::sources::transplant(&changed, donor, None).unwrap(),
                changed
            );
            let reversed = native::sources::transplant(&changed, target, None).unwrap();
            let Observation::Known(back) = native::discover_pair(&reversed) else {
                panic!("reverse pair");
            };
            assert_eq!(back.assignment, before.assignment);
            for word in 0..2 {
                let (mut expected, calls) = body(target, before.functions[word]);
                let at = calls[0] - 1;
                let d = decode_insn(&expected[at..], Target::H8S2000, Mode::Advanced).unwrap();
                expected.drain(at..at + d.len);
                assert_eq!(body(&reversed, back.functions[word]).0, expected);
            }
            assert!(changed[0x60a..0x620].iter().all(|b| *b == 0xff));
            for (at, (old, new)) in target.iter().zip(&changed).enumerate() {
                if old != new {
                    assert!(
                        before
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
        assert_eq!(&loader::logical_program(&changed).unwrap(), &expected);
        assert_eq!(
            loader::transplant_plain(&changed, donor, before.tables.unwrap(), None).unwrap(),
            changed,
        );
        let reverse_space = (after.spans.len() == 1).then_some(0x800..0x820);
        let restored =
            loader::transplant_plain(&changed, target, before.tables.unwrap(), reverse_space)
                .unwrap();
        assert_eq!(
            loader::logical_program(&restored).unwrap(),
            loader::logical_program(target).unwrap()
        );
        if after.spans.len() == 2 {
            for bytes in restored[after.spans[1].clone()].chunks_exact(2) {
                let d = h8_asm::isa::decode_insn(
                    bytes,
                    h8_asm::Target::H8S2000,
                    h8_asm::Mode::Advanced,
                )
                .unwrap();
                assert_eq!(d.insn.mnemonic, "NOP");
            }
        }

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
    for address in [before.writer, before.readback] {
        let mut broken = original.clone();
        broken[(address - 0x410000) as usize] ^= 2;
        assert_eq!(
            loader::transplant_computed(&broken, &original, table),
            Err(loader::Error::ResourceMismatch)
        );
        assert_eq!(
            loader::transplant_computed(&original, &broken, table),
            Err(loader::Error::ResourceMismatch)
        );
    }
    assert_eq!(
        loader::transplant_plain(
            &original,
            &original,
            [loader::Table::Literal(table); 2],
            None
        ),
        Err(loader::Error::ComputedUnsupported)
    );
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
fn historical_sparse_outputs_remain_recognized_and_donor_transplants_match_conventions() {
    // Native held code/data spans remain at their original addresses. All other
    // bytes are erased: these are incomplete test images, never flash inputs.
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-mechanism-known-answers.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let target = native_spans(case["target"].as_str().unwrap());
        let installed = native_spans(case["calibration_donor"].as_str().unwrap());
        let actual =
            bundle::composition::transplant(&target, &installed, test_space(), Some(0x600..0x700))
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
        let historical = bundle::bind(&expected).unwrap();
        let mut desired = bundle::bind(&installed).unwrap();
        desired.table_select_0x28f = bundle::bind(&target).unwrap().table_select_0x28f;
        let observed = bundle::bind(&actual).unwrap();
        assert_eq!(observed, desired, "{}: OEM convention", case["id"]);
        // Historical normalization and modern donor copying use different table
        // representations. Their native non-loader conventions must still agree.
        let historical_expected = bundle::Bundle {
            loader: if observed.loader == bundle::Loader::AscendingNegated17 {
                bundle::Loader::Ascending
            } else {
                observed.loader
            },
            ..observed
        };
        assert_eq!(
            historical, historical_expected,
            "{}: historical convention",
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
        let actual =
            bundle::composition::transplant(target, installed, test_space(), Some(0x600..0x700))
                .unwrap();
        let desired = bundle::bind(installed).unwrap();
        let observed = bundle::bind(&actual).unwrap();
        assert_eq!(observed, desired);
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
        bundle::composition::transplant(&target, &installed, occupied, Some(0x600..0x700)),
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
        assert!(
            matches!(native::discover_pair(&sourced), pioneer_optical::image::layout::Observation::Known(p) if p.assignment == required_assignment)
        );
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
        let loaded =
            bundle::waveforms::transplant(&original, &calibration_donor, Some(0x600..0x700))
                .unwrap();
        assert_eq!(
            bundle::waveforms::loader::observe(&loaded).unwrap().loader,
            bundle::waveforms::loader::observe(&calibration_donor)
                .unwrap()
                .loader
        );
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
        let composed = bundle::composition::transplant(
            &target,
            &installed,
            bundle::composition::Space {
                conversions: [Some(0x400..0x440), Some(0x440..0x484), Some(0x484..0x4b8)],
                calibration: Some(0x4b8..0x4fc),
                sources: Some(0x4fc..0x52c),
            },
            Some(0x600..0x700),
        )
        .unwrap_or_else(|e| panic!("{}: {e:?}", case["id"]));
        let mut expected = bundle::bind(&installed).unwrap();
        expected.table_select_0x28f = bundle::bind(&target).unwrap().table_select_0x28f;
        assert_eq!(bundle::bind(&composed).unwrap(), expected);
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
        let waveforms =
            bundle::waveforms::transplant(&target, &installed, Some(0x600..0x700)).unwrap();
        let loader = bundle::waveforms::loader::observe(&target).unwrap();
        let allowed: Vec<_> = std::iter::once(loader.program)
            .chain(std::iter::once(0x600..0x700))
            .chain(
                std::iter::once(&target_roles.selected)
                    .chain(&target_roles.erased_parameter)
                    .flat_map(|t| t.motion.clone()),
            )
            .chain(target_roles.selected.coefficients.clone())
            .collect();
        for (to, from) in target_roles
            .selected
            .coefficients
            .iter()
            .zip(&installed_roles.selected.coefficients)
        {
            assert_eq!(&waveforms[to.clone()], &installed[from.clone()]);
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

#[test]
#[ignore = "requires PIONEER_NORMAL_CORPUS; OEM full-image boundary proof"]
fn native_oem_full_images_match_guarded_sparse_patch_spans() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let pairs = native_oem_pairs();
    for (id, target_hash, donor_hash) in pairs {
        let read = |hash: &str| {
            let image = std::fs::read(root.join(format!("{hash}.bin"))).unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(&image)), hash);
            image
        };
        let target = read(&target_hash);
        let donor = read(&donor_hash);
        let sparse_target = native_spans(&target_hash);
        let sparse_donor = native_spans(&donor_hash);
        let sparse_output = bundle::composition::transplant(
            &sparse_target,
            &sparse_donor,
            test_space(),
            Some(0x600..0x700),
        )
        .unwrap();
        // The stage tests independently compare copied bodies against donor
        // instructions and tables. Here verify the same guarded differences in
        // full images, including untouched bytes omitted from sparse fixtures.
        let mut expected = target.clone();
        let mut count = 0;
        for (at, (old, new)) in sparse_target.iter().zip(&sparse_output).enumerate() {
            if old != new {
                assert_eq!(target[at], *old, "{id}: original guard at {at:#x}");
                expected[at] = *new;
                count += 1;
            }
        }
        let changed =
            bundle::composition::transplant(&target, &donor, test_space(), Some(0x600..0x700))
                .unwrap();
        assert_eq!(changed, expected, "{id}: full-image diff");
        assert_eq!(&changed[..24], &target[..24]);
        println!(
            "{id}: {count} changed bytes before checksum; SHA256 {:x}",
            Sha256::digest(&changed)
        );
    }
}

fn native_oem_pairs() -> Vec<(String, String, String)> {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-mechanism-known-answers.json")).unwrap();
    let mut pairs: Vec<(String, String, String)> = cases
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            (
                case["id"].as_str().unwrap().to_owned(),
                case["target"].as_str().unwrap().to_owned(),
                case["calibration_donor"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let sat9 = [
        "3711cd5cdde5b5e7f288ccd7bc7fe1100eb6de5e40f3d0ffdcc528fb93ebeb46",
        "c93736b1fc66c7ada2d586044bf5d8a50a622b65e2f1fe6e74ad212f254adc1b",
    ];
    pairs.push(("SAT9 forward".into(), sat9[0].into(), sat9[1].into()));
    pairs.push(("SAT9 reverse".into(), sat9[1].into(), sat9[0].into()));
    pairs
}

#[test]
#[ignore = "requires PIONEER_HOARD; eight OEM compositions through original codecs"]
fn native_oem_compositions_round_trip_original_envelopes() {
    use pioneer_optical::{compatibility::Firmware, envelope::Envelope, filters};
    let root = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").unwrap());
    let pairs = native_oem_pairs();
    let mut needed: std::collections::BTreeSet<_> = pairs
        .iter()
        .flat_map(|(_, target, donor)| [target.clone(), donor.clone()])
        .collect();
    let mut originals = std::collections::BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    let (packages, _) = page::hoard_packages(&root).unwrap();
    for package in packages {
        if !seen.insert(package.component.clone()) {
            continue;
        }
        let Ok(decoded) = page::decode(&root, &package) else {
            continue;
        };
        let hash = format!("{:x}", Sha256::digest(&decoded.normal.image));
        if needed.remove(&hash) {
            originals.insert(hash, (package.hardware, decoded));
        }
        if needed.is_empty() {
            break;
        }
    }
    assert!(needed.is_empty(), "missing original envelopes: {needed:?}");
    let sum = |image: &[u8]| {
        image.chunks_exact(4).fold(0u32, |s, w| {
            s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
        })
    };
    for (id, target_hash, donor_hash) in pairs {
        let (hardware, target) = &originals[&target_hash];
        let donor = &originals[&donor_hash].1;
        // Test reservations do not establish production code-space ownership.
        let changed = bundle::composition::transplant(
            &target.normal.image,
            &donor.normal.image,
            test_space(),
            Some(0x600..0x700),
        )
        .unwrap();
        let mut variants = vec![("explicit reservation", changed)];
        if donor_hash == "84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750"
            && matches!(
                target_hash.as_str(),
                "87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1"
                    | "e6bdfa9bd0220f618d3e4bf722a590c2e1cf4216431869ab399561b94c71f515"
            )
        {
            variants.push((
                "retired reader",
                bundle::composition::transplant_reusing_reader(
                    &target.normal.image,
                    &donor.normal.image,
                )
                .unwrap(),
            ));
        }
        for (placement, changed) in variants {
            let context = filters::Preparation {
                target: Firmware {
                    hardware,
                    normal: &target.normal.image,
                    kernel: target.kernel.as_ref().map(|k| k.image.as_slice()),
                },
                normal: Some(&target.normal),
                kernel: target.kernel.as_ref(),
            };
            let corrected = (filters::be32_normal_integrity().repair)(&context, &changed).unwrap();
            assert_eq!(sum(&target.normal.image), 0, "{id}: original checksum");
            assert_eq!(sum(&corrected), 0, "{id}: output checksum");
            assert_eq!(&corrected[..16], &changed[..16]);
            assert_eq!(&corrected[20..], &changed[20..]);
            let original_word = u32::from_be_bytes(changed[16..20].try_into().unwrap());
            assert_eq!(
                &corrected[16..20],
                &original_word.wrapping_sub(sum(&changed)).to_be_bytes()
            );
            let file = target
                .normal
                .repack(&corrected)
                .expect("original codec must preserve modified image");
            let decoded = match &target.kernel {
                Some(kernel) => Envelope::load_with_kernel(&file, kernel),
                None => Envelope::load(&file),
            }
            .unwrap();
            assert_eq!(decoded.image, corrected, "{id}: every decoded output byte");
            assert_eq!(
                decoded.repack(&decoded.image).unwrap(),
                file,
                "{id}: stable encoded output"
            );
            assert_eq!(decoded.info().layout, target.normal.info().layout);
            println!(
                "{id}: checksum and {:?} envelope round-trip passed",
                decoded.info().layout
            );
            println!("{id}: {placement} verified");
        }
    }
}

#[test]
fn native_oem_loader_rejects_changed_writer_abi() {
    use bundle::waveforms::loader::{self, writer};
    for (_, target_hash, donor_hash) in native_oem_pairs() {
        let target = native_spans(&target_hash);
        let donor = native_spans(&donor_hash);
        let before = loader::observe(&target).unwrap();
        let source = loader::observe(&donor).unwrap();
        let destination = writer::observe(&target, before.writer).unwrap();
        let original = writer::observe(&donor, source.writer).unwrap();
        assert_eq!(destination.program.len(), 112);
        assert_eq!(original.program.len(), 112);
        for i in 0..112 {
            if (100..104).contains(&i) {
                continue;
            }
            assert_eq!(
                target[destination.program.start + i],
                donor[original.program.start + i]
            );
        }
        // A changed register, port, loop branch or return is not ABI-equivalent.
        for offset in [4, 59, 72, 110] {
            let mut broken = donor.clone();
            broken[original.program.start + offset] ^= 2;
            assert!(writer::observe(&broken, source.writer).is_err());
            assert_eq!(
                loader::transplant_plain(
                    &target,
                    &broken,
                    source.tables.unwrap(),
                    Some(0x600..0x700)
                ),
                Err(loader::Error::ResourceMismatch)
            );
        }
        let mut broken = target.clone();
        broken[destination.program.end - 1] ^= 2;
        assert_eq!(
            loader::transplant_plain(&broken, &donor, source.tables.unwrap(), Some(0x600..0x700)),
            Err(loader::Error::ResourceMismatch)
        );
    }
}

#[test]
fn native_oem_loader_binds_readback_writer_shadow_and_clear_helper() {
    use bundle::waveforms::loader::{self, readback};
    for (_, target_hash, donor_hash) in native_oem_pairs() {
        let target = native_spans(&target_hash);
        let donor = native_spans(&donor_hash);
        for normal in [&target, &donor] {
            let loader = loader::observe(normal).unwrap();
            let reader = readback::observe(normal, loader.readback, loader.writer).unwrap();
            let (shadow, call) = if reader.clear.is_some() {
                (90, 111)
            } else {
                (46, 69)
            };
            for offset in [0, shadow + 3, call + 2, reader.program.len() - 1] {
                let mut broken = normal.clone();
                broken[reader.program.start + offset] ^= 2;
                assert!(readback::observe(&broken, loader.readback, loader.writer).is_err());
                assert_eq!(
                    loader::transplant_plain(
                        &broken,
                        normal,
                        loader.tables.unwrap(),
                        Some(0x600..0x700)
                    ),
                    Err(loader::Error::ResourceMismatch)
                );
                assert_eq!(
                    loader::transplant_plain(
                        normal,
                        &broken,
                        loader.tables.unwrap(),
                        Some(0x600..0x700)
                    ),
                    Err(loader::Error::ResourceMismatch)
                );
            }
            if let Some(clear) = reader.clear {
                let mut broken = normal.clone();
                broken[clear.end - 1] ^= 2;
                assert!(readback::observe(&broken, loader.readback, loader.writer).is_err());
                broken = normal.clone();
                // Two calls to different clear helpers do not establish this contract.
                broken[reader.program.start + 35] ^= 2;
                assert!(readback::observe(&broken, loader.readback, loader.writer).is_err());
            }
        }
    }
}

#[test]
#[ignore = "requires PIONEER_HOARD; computed-loader DSP helper coverage"]
fn computed_loader_dsp_contracts_cover_held_native_images() {
    use bundle::waveforms::loader::{self, Table};
    let root = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").unwrap());
    let (packages, _) = page::hoard_packages(&root).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    let mut checked = 0;
    for package in packages {
        if !seen.insert(package.component.clone()) {
            continue;
        }
        let Ok(decoded) = page::decode(&root, &package) else {
            continue;
        };
        let image = &decoded.normal.image;
        let Ok(binding) = loader::observe(image) else {
            continue;
        };
        if !binding.computed {
            continue;
        }
        let Some([Table::Literal(table), _]) = binding.tables else {
            panic!("computed table")
        };
        loader::readback::observe(image, binding.readback, binding.writer)
            .unwrap_or_else(|e| panic!("{} {}: {e:?}", package.hardware, package.component));
        assert_eq!(
            loader::transplant_computed(image, image, table).unwrap(),
            *image
        );
        checked += 1;
    }
    println!("{checked} computed-loader images retain native DSP helper contracts");
    assert!(
        checked >= 76,
        "computed-loader coverage unexpectedly shrank"
    );
}

#[test]
fn native_arithmetic_services_follow_mapped_call_targets() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-native-arithmetic.json")).unwrap();
    for f in fixtures.as_array().unwrap() {
        let base = f["base"].as_u64().unwrap() as u32;
        let multiply = f["multiply"].as_u64().unwrap() as u32;
        let divide = f["divide"].as_u64().unwrap() as u32;
        let mut image = vec![0xff; f["size"].as_u64().unwrap() as usize];
        for span in f["spans"].as_array().unwrap() {
            let at = span[0].as_u64().unwrap() as usize;
            let bytes = hex(span[1].as_str().unwrap());
            image[at..at + bytes.len()].copy_from_slice(&bytes);
        }
        let binding = native::arithmetic::observe(&image, base, multiply, divide).unwrap();
        assert_eq!(binding.multiply.len(), 24);
        assert_eq!(binding.signed_divide.len(), 38);
        assert_eq!(binding.unsigned_divide.len(), 60);
        for span in [
            &binding.multiply,
            &binding.signed_divide,
            &binding.unsigned_divide,
        ] {
            for at in span.clone() {
                let mut broken = image.clone();
                broken[at] ^= 2;
                assert!(
                    native::arithmetic::observe(&broken, base, multiply, divide).is_none(),
                    "mutation {at:#x}"
                );
            }
        }
        assert!(native::arithmetic::observe(&image, base + 2, multiply, divide).is_none());
        assert!(native::arithmetic::observe(&image, base, multiply + 1, divide).is_none());
        assert!(
            native::arithmetic::observe(&image[..image.len() - 1], base, multiply, divide)
                .is_none()
        );
        // Relocation is accepted by native linkage, never by an address registry.
        let offset = binding.signed_divide.start + 19;
        let relocated_core = base + binding.unsigned_divide.start as u32 + 0x200;
        image[offset..offset + 3].copy_from_slice(&relocated_core.to_be_bytes()[1..]);
        assert_eq!(
            native::arithmetic::observe(&image, base + 0x200, multiply + 0x200, divide + 0x200),
            Some(binding)
        );
    }
}

#[test]
#[ignore = "requires PIONEER_HOARD; independently guarded arithmetic dump spans"]
fn native_arithmetic_spans_match_original_drive_dumps() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").unwrap());
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-native-arithmetic.json")).unwrap();
    for f in fixtures.as_array().unwrap() {
        let hash = f["original_sha256"].as_str().unwrap();
        let original = std::fs::read(root.join("originals").join(hash).join("dump.bin")).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&original)), hash);
        let base = f["base"].as_u64().unwrap() as usize;
        for span in f["spans"].as_array().unwrap() {
            let at = base + span[0].as_u64().unwrap() as usize;
            let bytes = hex(span[1].as_str().unwrap());
            assert_eq!(&original[at..at + bytes.len()], bytes.as_slice());
        }
        native::arithmetic::observe(
            &original,
            0,
            f["multiply"].as_u64().unwrap() as u32,
            f["divide"].as_u64().unwrap() as u32,
        )
        .unwrap();
    }
}

#[test]
fn native_multiply_instructions_match_wrapping_u32_products() {
    use h8_asm::{
        isa::{decode_insn, Operand as O, Reg},
        Mode, Target,
    };
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-native-arithmetic.json")).unwrap();
    let f = &fixtures[0];
    let offset = f["multiply"].as_u64().unwrap() - f["base"].as_u64().unwrap();
    let span = f["spans"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s[0].as_u64() == Some(offset))
        .unwrap();
    let bytes = hex(span[1].as_str().unwrap());
    let mut program = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let decoded = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced).unwrap();
        program.push(decoded.insn);
        at += decoded.len;
    }
    fn word(registers: &[u32; 8], n: u8) -> u32 {
        (registers[(n % 8) as usize] >> if n < 8 { 0 } else { 16 }) & 0xffff
    }
    fn set_word(registers: &mut [u32; 8], n: u8, value: u32) {
        let shift = if n < 8 { 0 } else { 16 };
        let r = &mut registers[(n % 8) as usize];
        *r = (*r & !(0xffff << shift)) | ((value & 0xffff) << shift);
    }
    let run = |a: u32, b: u32| {
        let mut registers = [0x1357_9bdf; 8];
        registers[0] = a;
        registers[1] = b;
        let mut saved = Vec::new();
        for insn in &program {
            match (insn.mnemonic, insn.operands) {
                ("STM", [O::Registers { first, last }, _, _]) => {
                    saved.push(registers[first as usize..=last as usize].to_vec());
                }
                ("LDM", [_, O::Registers { first, last }, _]) => {
                    registers[first as usize..=last as usize]
                        .copy_from_slice(&saved.pop().unwrap());
                }
                ("MOV", [O::Register(Reg::Word(from)), O::Register(Reg::Word(to)), _]) => {
                    let value = word(&registers, from);
                    set_word(&mut registers, to, value);
                }
                ("MULXU", [O::Register(Reg::Word(from)), O::Register(Reg::Long(to)), _]) => {
                    registers[to as usize] = word(&registers, from) * word(&registers, to);
                }
                ("ADD", [O::Register(Reg::Word(from)), O::Register(Reg::Word(to)), _]) => {
                    let value = word(&registers, from) + word(&registers, to);
                    set_word(&mut registers, to, value);
                }
                ("RTS", _) => {
                    assert!(saved.is_empty());
                    assert_eq!(registers[1], b);
                    assert!(registers[2..].iter().all(|r| *r == 0x1357_9bdf));
                    return registers[0];
                }
                other => panic!("unexpected multiply instruction {other:?}"),
            }
        }
        panic!("missing return")
    };
    let edges = [
        0,
        1,
        2,
        0x7fff,
        0x8000,
        0xffff,
        0x10000,
        0x7fff_ffff,
        0x8000_0000,
        u32::MAX,
    ];
    for a in edges {
        for b in edges {
            assert_eq!(run(a, b), a.wrapping_mul(b));
        }
    }
    let mut random = 0x9e37_79b9u32;
    for word in 0..=u16::MAX {
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        let a = (u32::from(word) << 16) | u32::from(!word);
        assert_eq!(run(a, random), a.wrapping_mul(random));
    }
}

#[test]
fn calibration_caller_binds_four_modes_and_rejects_high_byte_consumption() {
    use h8_asm::{
        isa::{decode_insn, encode_insn, Operand, Reg},
        Mode, Target,
    };
    for (id, target_hash, donor_hash) in native_oem_pairs() {
        let target = native_spans(&target_hash);
        let donor = native_spans(&donor_hash);
        let before = native::calibration::callers::observe(&target)
            .unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let changed =
            bundle::composition::transplant(&target, &donor, test_space(), Some(0x600..0x700))
                .unwrap();
        assert_eq!(
            native::calibration::callers::observe(&changed).unwrap(),
            before,
            "{id}"
        );
        let mut extra = target.clone();
        let call =
            decode_insn(&target[before.calls[0]..], Target::H8S2000, Mode::Advanced).unwrap();
        let encoded = encode_insn(call.insn, Target::H8S2000, Mode::Advanced).unwrap();
        extra[0x800..0x800 + encoded.len()].copy_from_slice(&encoded);
        assert!(
            native::calibration::callers::observe(&extra).is_err(),
            "{id}: unproved extra caller"
        );
        let at = before.calls[0];
        let call = decode_insn(&target[at..], Target::H8S2000, Mode::Advanced).unwrap();
        let at = at + call.len;
        let mut mov = decode_insn(&target[at..], Target::H8S2000, Mode::Advanced)
            .unwrap()
            .insn;
        assert_eq!(mov.operands[0], Operand::Register(Reg::Byte(8)));
        mov.operands[0] = Operand::Register(Reg::Byte(0));
        let encoded = encode_insn(mov, Target::H8S2000, Mode::Advanced).unwrap();
        let mut broken = target.clone();
        broken[at..at + encoded.len()].copy_from_slice(&encoded);
        assert!(
            native::calibration::callers::observe(&broken).is_err(),
            "{id}: high byte consumer"
        );
        let at = before.calls[3];
        let mut call = decode_insn(&target[at..], Target::H8S2000, Mode::Advanced)
            .unwrap()
            .insn;
        match &mut call.operands[0] {
            Operand::Address(h8_asm::isa::Ea::Absolute { value, .. }) => *value += 2,
            Operand::Address(h8_asm::isa::Ea::PcRelative { value, .. }) => *value += 2,
            _ => panic!("unexpected call"),
        }
        let encoded = encode_insn(call, Target::H8S2000, Mode::Advanced).unwrap();
        let mut broken = target;
        broken[at..at + encoded.len()].copy_from_slice(&encoded);
        assert!(
            native::calibration::callers::observe(&broken).is_err(),
            "{id}: fourth call target"
        );
    }
}

#[test]
#[ignore = "exports OEM caller spans from PIONEER_NORMAL_CORPUS into sparse CI fixtures"]
fn export_calibration_callers_from_reference_normals() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/phase-native-spans.json");
    let mut fixtures: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let hashes: std::collections::BTreeSet<_> = native_oem_pairs()
        .into_iter()
        .flat_map(|(_, a, b)| [a, b])
        .collect();
    for hash in hashes {
        let image = std::fs::read(root.join(format!("{hash}.bin"))).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&image)), hash);
        let binding = native::calibration::callers::observe(&image).unwrap();
        let fixture = fixtures
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|f| f["original_sha256"].as_str() == Some(&hash))
            .unwrap();
        let spans = fixture["spans"].as_array_mut().unwrap();
        for span in spans.iter() {
            let at = span[0].as_u64().unwrap() as usize;
            let bytes = hex(span[1].as_str().unwrap());
            assert_eq!(&image[at..at + bytes.len()], bytes);
        }
        let covered = spans.iter().any(|span| {
            let at = span[0].as_u64().unwrap() as usize;
            at <= binding.program.start
                && at + span[1].as_str().unwrap().len() / 2 >= binding.program.end
        });
        if !covered {
            let bytes: String = image[binding.program.clone()]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            spans.push(serde_json::json!([binding.program.start, bytes]));
            spans.sort_by_key(|span| span[0].as_u64().unwrap());
        }
    }
    std::fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(&fixtures).unwrap()),
    )
    .unwrap();
}

#[test]
fn indirect_loader_fits_thirty_bytes_with_pointer_cells_at_either_end() {
    use bundle::waveforms::{
        self,
        loader::{self, Table},
    };
    for (id, target_hash, donor_hash) in native_oem_pairs() {
        let target = native_spans(&target_hash);
        let donor = native_spans(&donor_hash);
        if !matches!(
            loader::observe(&donor).unwrap().tables,
            Some([Table::Pointer(_), _])
        ) {
            continue;
        }
        for (space, expected_cells) in [(0x600..0x61e, 0x600), (0x602..0x620, 0x618)] {
            let changed = waveforms::transplant(&target, &donor, Some(space.clone()))
                .unwrap_or_else(|e| panic!("{id} {space:?}: {e:?}"));
            let binding = loader::observe(&changed).unwrap();
            assert_eq!(
                binding.tables,
                Some([
                    Table::Pointer(0x410000 + expected_cells),
                    Table::Pointer(0x410004 + expected_cells)
                ])
            );
            assert_eq!(binding.spans[1].len(), 22);
            assert!(binding.spans[1].start >= space.start && binding.spans[1].end <= space.end);
            assert_eq!(
                waveforms::transplant(&changed, &donor, None).unwrap(),
                changed
            );
        }
        assert!(
            waveforms::transplant(&target, &donor, Some(0x600..0x61c)).is_err(),
            "{id}: insufficient suffix space"
        );
        assert!(
            waveforms::transplant(&target, &donor, Some(0x601..0x61f)).is_err(),
            "{id}: misaligned code space"
        );
    }
}

#[test]
fn ud02_composition_reuses_only_the_retired_packed_reader_tail() {
    use h8_asm::{
        isa::{encode_insn, Ea, Insn, Operand},
        Mode, Target,
    };
    let donor = native_spans("84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750");
    for hash in [
        "87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1",
        "e6bdfa9bd0220f618d3e4bf722a590c2e1cf4216431869ab399561b94c71f515",
    ] {
        let target = native_spans(hash);
        let entry = native::calibration::callers::observe(&target)
            .unwrap()
            .reader;
        let tail = entry + 36..entry + 66;
        let changed = bundle::composition::transplant_reusing_reader(&target, &donor).unwrap();
        let loader = bundle::waveforms::loader::observe(&changed).unwrap();
        assert_eq!(loader.spans[1].len(), 22);
        assert!(loader.spans[1].start >= tail.start && loader.spans[1].end <= tail.end);
        for table in loader.tables.unwrap() {
            let bundle::waveforms::loader::Table::Pointer(address) = table else {
                panic!("OEM indirect load")
            };
            let at = (address - 0x410000) as usize;
            assert!(at >= tail.start && at + 4 <= tail.end);
        }
        assert_eq!(
            &changed[..0x1000],
            &target[..0x1000],
            "no header-gap allocation"
        );
        let explicit =
            bundle::composition::transplant(&target, &donor, test_space(), Some(0x600..0x700))
                .unwrap();
        for (at, (old, new)) in target.iter().zip(&changed).enumerate() {
            if old != new {
                assert!(
                    tail.contains(&at) || explicit[at] != *old,
                    "unexpected write {at:x}"
                );
            }
        }
        assert_eq!(
            bundle::composition::transplant_reusing_reader(&changed, &donor).unwrap(),
            changed
        );
        let mut pointer = target.clone();
        pointer[0x801..0x805].copy_from_slice(&((0x410000 + entry) as u32).to_be_bytes());
        assert!(
            bundle::composition::transplant_reusing_reader(&pointer, &donor).is_err(),
            "unaligned address-taken reader"
        );
        for (mnemonic, bits) in [("JSR", 24), ("MOV", 32)] {
            let instruction = if mnemonic == "JSR" {
                Insn::new(
                    mnemonic,
                    None,
                    [
                        Operand::Address(Ea::Absolute {
                            value: (0x410000 + tail.start) as u32,
                            bits,
                        }),
                        Operand::None,
                        Operand::None,
                    ],
                )
            } else {
                Insn::new(
                    mnemonic,
                    Some(h8_asm::isa::Size::Long),
                    [
                        Operand::Immediate {
                            value: (0x410000 + tail.start) as u32,
                            bits,
                        },
                        Operand::Register(h8_asm::isa::Reg::Long(0)),
                        Operand::None,
                    ],
                )
            };
            let bytes = encode_insn(instruction, Target::H8S2000, Mode::Advanced).unwrap();
            let mut broken = target.clone();
            broken[0x800..0x800 + bytes.len()].copy_from_slice(&bytes);
            assert!(
                bundle::composition::transplant_reusing_reader(&broken, &donor).is_err(),
                "reference into retired tail"
            );
        }
    }
}

#[test]
#[ignore = "requires PIONEER_NORMAL_CORPUS; retired reader space in full images"]
fn ud02_retired_reader_space_in_full_images() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let read = |hash: &str| {
        let image = std::fs::read(root.join(format!("{hash}.bin"))).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&image)), hash);
        image
    };
    let donor = read("84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750");
    for hash in [
        "87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1",
        "e6bdfa9bd0220f618d3e4bf722a590c2e1cf4216431869ab399561b94c71f515",
    ] {
        let target = read(hash);
        let changed = bundle::composition::transplant_reusing_reader(&target, &donor).unwrap();
        let sparse = native_spans(hash);
        let expected = bundle::composition::transplant_reusing_reader(
            &sparse,
            &native_spans("84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750"),
        )
        .unwrap();
        for (at, (old, new)) in target.iter().zip(&changed).enumerate() {
            if sparse[at] != expected[at] {
                assert_eq!(*new, expected[at]);
            } else {
                assert_eq!(old, new);
            }
        }
    }
}

#[test]
fn mechanism_filter_plans_equal_coil_control_changes_and_checks_all_effects() {
    use pioneer_optical::{
        compatibility::{Error, Firmware},
        filters::{self, Filter},
    };
    let mut checked = 0;
    for (_, target_hash, donor_hash) in native_oem_pairs() {
        let donor = native_spans(&donor_hash);
        let other = native_spans(&target_hash);
        // An isolated native mode/controller difference exercises the full
        // operation without assuming ownership of any extra code reservation.
        let mut target = bundle::conversions::rewrite_controls(&donor, &other).unwrap();
        target[16..20].fill(0);
        let sum = target.chunks_exact(4).fold(0u32, |sum, word| {
            sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
        });
        target[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
        if bundle::bind(&target).unwrap() == bundle::bind(&donor).unwrap() {
            continue;
        }
        checked += 1;
        let installed = filters::Context::new(Firmware {
            hardware: "SAT 8000",
            normal: &donor,
            kernel: None,
        });
        let target_context = filters::Context::new(Firmware {
            hardware: "SAT 8000",
            normal: &target,
            kernel: None,
        });
        let filter = &filters::phase::FILTER;
        let operation = filter
            .plan(
                &filters::Transition {
                    installed: &installed,
                    target: &target_context,
                },
                &filter.inspect(&installed),
                &filter.inspect(&target_context),
            )
            .unwrap()
            .expect("different bundle needs operation even with equal coils");
        let preparation = filters::Preparation {
            target: target_context.firmware,
            normal: None,
            kernel: None,
        };
        let changed = operation.prepare(&preparation).unwrap().unwrap();
        operation.verify(&preparation, &changed).unwrap();
        let registry: &[&dyn Filter] = &[filter];
        let plan = filters::runner::plan_with(
            &installed,
            &target_context,
            filters::runner::Policy::Strict,
            registry,
        )
        .unwrap();
        let composed = plan.prepare_with(&preparation, registry).unwrap().unwrap();
        plan.verify_with(&preparation, &composed, registry).unwrap();
        let words = plan.required_words().unwrap();
        assert_eq!(
            words.iter().map(|w| w.word).collect::<Vec<_>>(),
            operation.required_words()
        );
        assert!(words.iter().all(|w| w.filter == "phase"));
        filters::prerequisites::check(&words, |_| Ok::<_, ()>(1)).unwrap();
        if !words.is_empty() {
            assert!(matches!(
                filters::prerequisites::check(&words, |_| Ok::<_, ()>(0)),
                Err(filters::prerequisites::CheckError::Mismatch { .. })
            ));
        }

        assert_eq!(
            operation.verify(&preparation, &target),
            Err(Error::VerificationFailed)
        );
        assert_eq!(
            operation.required_words(),
            if bundle::bind(&donor).unwrap().table_select_0x28f {
                vec![filters::prerequisites::Word {
                    parameter: 0x28f,
                    value: 1,
                }]
            } else {
                vec![]
            }
        );
        let altered = target
            .iter()
            .zip(&changed)
            .position(|(a, b)| a != b)
            .unwrap();
        let mut damaged = changed.clone();
        damaged[altered] = target[altered];
        assert_eq!(
            operation.verify(&preparation, &damaged),
            Err(Error::VerificationFailed)
        );
        let mut substituted = target.clone();
        substituted[30] ^= 1;
        let wrong = filters::Preparation {
            target: Firmware {
                normal: &substituted,
                ..target_context.firmware
            },
            normal: None,
            kernel: None,
        };
        assert_eq!(operation.prepare(&wrong), Err(Error::ComponentMismatch));
    }
    assert_eq!(checked, 8);
}
