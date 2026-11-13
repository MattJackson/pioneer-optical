#![cfg(feature = "envelope")]
#![cfg(feature = "internals")]
use pioneer_optical::filters::phase::native::sat1;
#[test]
#[ignore = "requires PIONEER_SAT1_CORPUS; exact two native SAT1 graphs"]
fn held_sat1_graphs_bind() {
    let dir = std::path::PathBuf::from(std::env::var("PIONEER_SAT1_CORPUS").unwrap());
    let mut images = Vec::new();
    let mut fixtures = Vec::new();
    for hash in [
        "bf92cbe9587d30fa04a5adfd063292952a68e5d965d0e687ab3da1189144fc82",
        "fd498e08fbbda744745bdd1f2366ea453375af0eb5c88dcd565b2d679b0c6225",
    ] {
        let normal = std::fs::read(dir.join(format!("{hash}.bin"))).unwrap();
        let kernel = std::fs::read(dir.join(format!("{hash}.kernel.bin"))).unwrap();
        println!("{hash}: {:?}", sat1::observe(&normal, &kernel));
        assert!(sat1::observe(&normal, &kernel).is_ok());
        let binding = sat1::observe(&normal, &kernel).unwrap();
        let mut spans = vec![
            0..24,
            binding.command.clone(),
            binding.caller.clone(),
            binding.output.clone(),
            binding.zero.clone(),
            binding.jump_table.clone(),
            binding.mode_getter.clone(),
        ];
        spans.extend(binding.tables.iter().cloned());
        let mut data: Vec<_> = spans
            .iter()
            .map(|r| {
                serde_json::json!([
                    0x410000 + r.start,
                    normal[r.clone()]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                ])
            })
            .collect();
        let k = (binding.encoders[0] - 0x400000) as usize;
        data.push(serde_json::json!([
            binding.encoders[0],
            kernel[k..k + 6]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ]));
        fixtures.push(serde_json::json!({"normal":hash,"normal_len":normal.len(),"spans":data}));
        images.push((normal, kernel));
    }
    if let Ok(path) = std::env::var("PIONEER_SAT1_EXPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&fixtures).unwrap()).unwrap();
    }
    for (a, b) in [(&images[0], &images[1]), (&images[1], &images[0])] {
        let result = sat1::transplant(&a.0, &a.1, &b.0, &b.1);
        println!("transplant {:?}", result.as_ref().map(|_| ()));
        let changed = result.unwrap();
        sat1::verify(&a.0, &a.1, &b.0, &b.1, &changed).unwrap();
    }
}

fn fixtures() -> Vec<(Vec<u8>, Vec<u8>)> {
    let all: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-sat1-native.json")).unwrap();
    all.as_array()
        .unwrap()
        .iter()
        .map(|f| {
            let mut n = vec![255; f["normal_len"].as_u64().unwrap() as usize];
            let mut k = vec![255; 65536];
            for s in f["spans"].as_array().unwrap() {
                let addr = s[0].as_u64().unwrap() as usize;
                let h = s[1].as_str().unwrap();
                let (dst, at) = if addr >= 0x410000 {
                    (&mut n, addr - 0x410000)
                } else {
                    (&mut k, addr - 0x400000)
                };
                for i in 0..h.len() / 2 {
                    dst[at + i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
                }
            }
            (n, k)
        })
        .collect()
}
#[test]
fn complete_sat1_native_graphs_transfer_and_reject_partial_changes() {
    let all = fixtures();
    for (a, b) in [(&all[0], &all[1]), (&all[1], &all[0])] {
        let before = sat1::observe(&a.0, &a.1).unwrap();
        let donor = sat1::observe(&b.0, &b.1).unwrap();
        let changed = sat1::transplant(&a.0, &a.1, &b.0, &b.1).unwrap();
        let after = sat1::observe(&changed, &a.1).unwrap();
        assert_eq!(after.assignment, donor.assignment);
        sat1::verify(&a.0, &a.1, &b.0, &b.1, &changed).unwrap();
        assert_eq!(
            sat1::transplant(&changed, &a.1, &b.0, &b.1).unwrap(),
            changed
        );
        let restored = sat1::transplant(&changed, &a.1, &a.0, &a.1).unwrap();
        assert_eq!(sat1::observe(&restored, &a.1).unwrap(), before);
        for (i, (x, y)) in a.0.iter().zip(&changed).enumerate() {
            if x != y {
                assert!(
                    before.caller.contains(&i)
                        || before.output.contains(&i)
                        || before.jump_table.contains(&i)
                        || before.tables.iter().any(|r| r.contains(&i))
                );
            }
        }
        for at in [
            before.command.start + 4,
            before.caller.start + 8,
            before.output.start + 8,
            before.mode_getter.start + 7,
            before.jump_table.start,
            before.tables[0].start,
        ] {
            let mut broken = changed.clone();
            broken[at] ^= 1;
            assert!(
                sat1::verify(&a.0, &a.1, &b.0, &b.1, &broken).is_err(),
                "mutated {at:x}"
            );
        }
        let mut kernel = a.1.clone();
        let at = (before.encoders[0] - 0x400000) as usize;
        kernel[at] = 0;
        assert!(sat1::transplant(&a.0, &kernel, &b.0, &b.1).is_err());
        assert!(sat1::transplant(&a.0, &a.1[..65534], &b.0, &b.1).is_err());
        let mut hostile = a.0.clone();
        let address = (0x410000 + before.output.start + 4) as u32;
        hostile[0x800..0x804].copy_from_slice(&[
            0x5e,
            (address >> 16) as u8,
            (address >> 8) as u8,
            address as u8,
        ]);
        assert!(sat1::transplant(&hostile, &a.1, &b.0, &b.1).is_err());
        let mut kernel = a.1.clone();
        kernel[0x101..0x105].copy_from_slice(&address.to_be_bytes());
        assert!(sat1::transplant(&a.0, &kernel, &b.0, &b.1).is_err());
        // Every high-encoder reference must agree: changing only the indirect
        // literal cannot be hidden by the two still-valid absolute identity calls.
        let mut broken = a.0.clone();
        let slot = before.output.start
            + if before.assignment == pioneer_optical::filters::phase::native::Assignment::Direct {
                108
            } else {
                110
            };
        broken[slot + 3] ^= 2;
        assert!(sat1::observe(&broken, &a.1).is_err());
    }
}

fn checksum(bytes: &mut [u8]) {
    bytes[16..20].fill(0);
    let sum = bytes.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    bytes[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
}
/// The phase owner preserves every byte outside target output operands and
/// checksum, even when the installed mechanism has different native tables.
fn phase_only_change(
    source: pioneer_optical::compatibility::Firmware<'_>,
    target: pioneer_optical::compatibility::Firmware<'_>,
    envelope: Option<&pioneer_optical::envelope::Envelope>,
    kernel: Option<&pioneer_optical::envelope::Envelope>,
) -> Vec<u8> {
    use pioneer_optical::filters::{self, Filter};
    let required = sat1::phase_only::observe(source.normal).unwrap();
    let before = sat1::phase_only::observe(target.normal).unwrap();
    assert_eq!(required.interface, before.interface);
    assert_ne!(required.assignment, before.assignment);
    let installed = filters::Context::new(source);
    let destination = filters::Context::new(target);
    let registry: &[&dyn Filter] = &[&filters::phase::FILTER];
    let plan = filters::runner::plan_with(
        &installed,
        &destination,
        filters::runner::Policy::Strict,
        registry,
    )
    .unwrap();
    assert!(plan.required_words().unwrap().is_empty());
    let context = filters::Preparation {
        target,
        normal: envelope,
        kernel,
    };
    let changed = plan
        .prepare_with(&context, registry)
        .unwrap()
        .expect("target output correction");
    plan.verify_with(&context, &changed, registry).unwrap();
    let expected = sat1::phase_only::correct(target.normal, required.assignment).unwrap();
    let expected = (filters::be32_normal_integrity().repair)(&context, &expected).unwrap();
    assert_eq!(
        changed, expected,
        "only target output operands and checksum change"
    );
    assert_eq!(sat1::phase_only::observe(&changed).unwrap(), required);
    let at = changed
        .iter()
        .zip(target.normal)
        .enumerate()
        .find(|(at, (a, b))| !(16..20).contains(at) && a != b)
        .unwrap()
        .0;
    let mut broken = changed.clone();
    broken[at] = target.normal[at];
    assert!(plan.verify_with(&context, &broken, registry).is_err());
    changed
}

#[test]
fn sat1_phase_owner_preserves_target_tables_calibration_and_callers() {
    use pioneer_optical::compatibility::Firmware;
    let mut all = fixtures();
    for (n, _) in &mut all {
        checksum(n);
    }
    for (a, b) in [(&all[0], &all[1]), (&all[1], &all[0])] {
        let changed = phase_only_change(
            Firmware {
                hardware: "SAT 1000",
                normal: &b.0,
                kernel: Some(&b.1),
            },
            Firmware {
                hardware: "SAT 1000",
                normal: &a.0,
                kernel: Some(&a.1),
            },
            None,
            None,
        );
        let before = sat1::observe(&a.0, &a.1).unwrap();
        for range in before.tables.iter().chain([
            &before.command,
            &before.caller,
            &before.jump_table,
            &before.mode_getter,
        ]) {
            assert_eq!(&changed[range.clone()], &a.0[range.clone()]);
        }
    }
}

#[path = "../examples/hardware_matrix/page.rs"]
mod page;
#[test]
#[ignore = "requires PIONEER_HOARD; exact two SAT1 originals through their own codecs"]
fn native_sat1_directions_round_trip_original_envelopes() {
    use pioneer_optical::{
        compatibility::Firmware,
        envelope::Envelope,
        filters::{self, Filter},
    };
    let root = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").unwrap());
    let components = [
        "2fbd27764be34ebb9a95e898d4e53afa5f67435b7fd324adbfde7411a386466c",
        "ab9ff1487bb2551064c59a53a659676833e0096c183bafb8e7715f49806a51a3",
    ];
    let (packages, _) = page::hoard_packages(&root).unwrap();
    let originals: Vec<_> = components
        .iter()
        .map(|hash| {
            let p = packages.iter().find(|p| p.component == *hash).unwrap();
            (p.hardware.clone(), page::decode(&root, p).unwrap())
        })
        .collect();
    for (a, b) in [
        (&originals[0], &originals[1]),
        (&originals[1], &originals[0]),
    ] {
        let (hardware, original) = a;
        let (source_hardware, source) = b;
        let installed = filters::Context::new(Firmware {
            hardware: source_hardware,
            normal: &source.normal.image,
            kernel: source.kernel.as_ref().map(|k| k.image.as_slice()),
        });
        let destination = filters::Context::new(Firmware {
            hardware,
            normal: &original.normal.image,
            kernel: original.kernel.as_ref().map(|k| k.image.as_slice()),
        });
        let source_phase = sat1::phase_only::observe(&source.normal.image).unwrap();
        let target_phase = sat1::phase_only::observe(&original.normal.image).unwrap();
        let cross_interface = source_phase.interface != target_phase.interface;
        let registry: &[&dyn Filter] = &[&filters::phase::FILTER];
        let complete =
            filters::runner::evaluate(&installed, &destination, filters::runner::Policy::Strict)
                .unwrap();
        assert!(
            complete.admit().is_err(),
            "other filters retain independent restrictions"
        );
        assert_eq!(
            complete
                .decisions()
                .iter()
                .find(|d| d.id == "phase")
                .unwrap()
                .blocked()
                .is_some(),
            cross_interface
        );
        let synthetic_source;
        let phase_source = if cross_interface {
            assert!(matches!(
                filters::runner::plan_with(
                    &installed,
                    &destination,
                    filters::runner::Policy::Strict,
                    registry
                ),
                Err(pioneer_optical::compatibility::Error::Incompatible)
            ));
            // Synthetic installed assignment, actual OEM target and codec.
            // A different native interface cannot authorize transplantation.
            let assignment = match target_phase.assignment {
                pioneer_optical::filters::phase::native::Assignment::Direct => {
                    pioneer_optical::filters::phase::native::Assignment::Swapped
                }
                pioneer_optical::filters::phase::native::Assignment::Swapped => {
                    pioneer_optical::filters::phase::native::Assignment::Direct
                }
            };
            let mut changed =
                sat1::phase_only::correct(&original.normal.image, assignment).unwrap();
            checksum(&mut changed);
            synthetic_source = changed;
            Firmware {
                hardware,
                normal: &synthetic_source,
                kernel: destination.firmware.kernel,
            }
        } else {
            // Both current held originals are SplitWord: use their actual
            // opposite assignments, without synthetic donor conventions.
            installed.firmware
        };
        let changed = phase_only_change(
            phase_source,
            destination.firmware,
            Some(&original.normal),
            original.kernel.as_ref(),
        );
        let encoded = original.normal.repack(&changed).unwrap();
        let decoded =
            Envelope::load_with_kernel(&encoded, original.kernel.as_ref().unwrap()).unwrap();
        assert_eq!(decoded.image, changed);
        assert_eq!(decoded.repack(&decoded.image).unwrap(), encoded);
    }
}
