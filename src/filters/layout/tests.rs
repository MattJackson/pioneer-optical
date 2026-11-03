use super::*;
use crate::{
    compatibility::Firmware,
    image::layout::{LogicalDomain, RecordRegion},
};

fn fix(n: &mut [u8]) {
    n[16..20].fill(0);
    let sum = n.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    n[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
}
fn normal() -> Vec<u8> {
    let mut n = vec![0xff; 0x10000];
    n[..16].copy_from_slice(b"PIONEER TEST    ");
    n[20..24].copy_from_slice(&0x10000u32.to_be_bytes());
    n[24..32].fill(0);
    n[0xd00..0xf00].copy_from_slice(&phase::tests::fixture(false));
    layout::install_test_layout_variant(&mut n, 0x1000, 8);
    let code = [
        0x5d, 0x60, 0x7a, 2, 0, 0x5d, 0x51, 0x60, 0x7a, 0x20, 0, 0x5c, 0, 0, 0x46, 4, 0x79, 0x0a,
        0, 0x5c, 0x0f, 0xa0, 0x69, 0x21,
    ];
    n[0x7000..0x7000 + code.len()].copy_from_slice(&code);
    fix(&mut n);
    n
}
fn variant(n: &[u8]) -> Vec<u8> {
    let mut out = n.to_vec();
    for at in (34..n.len() - 3).step_by(2) {
        if n[at - 2] == 0x7a && n[at..at + 4] == 0x9984u32.to_be_bytes() {
            out[at..at + 4].copy_from_slice(&0x5984u32.to_be_bytes());
        }
    }
    fix(&mut out);
    out
}
fn kernel() -> Vec<u8> {
    let mut k = vec![0; 0x10000];
    k[0x1000..0x1008].copy_from_slice(b"SAT 8600");
    let sum = k.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    k[0x1020..0x1024].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
    k
}
fn fw<'a>(n: &'a [u8], k: &'a [u8]) -> Firmware<'a> {
    Firmware {
        hardware: "SAT 8600",
        normal: n,
        kernel: Some(k),
    }
}
fn preparation<'a>(target: Firmware<'a>) -> Preparation<'a> {
    Preparation {
        target,
        #[cfg(feature = "envelope")]
        normal: None,
        #[cfg(feature = "envelope")]
        kernel: None,
    }
}

#[test]
fn owner_prepares_layout_only_and_verifies_independent_phase_composition() {
    let n = normal();
    let k = kernel();
    let layout_target = variant(&n);
    let target = phase::correct_normal(&layout_target, phase::Assignment::Swapped).unwrap();
    let source = Context::new(fw(&n, &k));
    let destination = Context::new(fw(&target, &k));
    let operation = FILTER
        .plan(
            &Transition {
                installed: &source,
                target: &destination,
            },
            &FILTER.inspect(&source),
            &FILTER.inspect(&destination),
        )
        .unwrap()
        .unwrap();
    let context = preparation(fw(&target, &k));
    let changed = operation.prepare(&context).unwrap().unwrap();
    assert_eq!(operation.filter_id(), FILTER.id());
    assert_eq!(
        operation.description(),
        Some(
            crate::compatibility::Correction::PersistentParameterLayout {
                from: 0x5984,
                to: 0x9984
            }
        )
    );
    assert!(
        matches!(phase::discover(&changed),Observation::Known(p) if p.assignment==phase::Assignment::Swapped)
    );
    let Observation::Known(expected) = native(&source) else {
        panic!("native source layout")
    };
    assert!(
        matches!(layout::discover_h8(&changed,Some(&k)), Observation::Known(p) if p == expected)
    );
    operation.verify(&context, &changed).unwrap();
    operation.verify(&context, &n).unwrap();
    let mut unrelated = n.clone();
    unrelated[0x9000] ^= 1;
    fix(&mut unrelated);
    assert_eq!(
        operation.verify(&context, &unrelated),
        Err(Error::VerificationFailed)
    );
    let altered = preparation(fw(&unrelated, &k));
    assert_eq!(operation.prepare(&altered), Err(Error::ComponentMismatch));
}

#[test]
fn layout_planning_requires_equal_proved_geometry_and_complete_components() {
    let n = normal();
    let k = kernel();
    let target = variant(&n);
    let source = Context::new(fw(&n, &k));
    let mut bad = target.clone();
    bad[0x7000] ^= 1;
    fix(&mut bad);
    let missing = Context::new(fw(&bad, &k));
    assert!(matches!(
        FILTER.plan(
            &Transition {
                installed: &source,
                target: &missing
            },
            &FILTER.inspect(&source),
            &FILTER.inspect(&missing)
        ),
        Err(Error::UnresolvedIdentity)
    ));
    let mut other_kernel = k.clone();
    other_kernel[0x9000] ^= 1;
    let destination = Context::new(fw(&target, &other_kernel));
    assert!(matches!(
        FILTER.plan(
            &Transition {
                installed: &source,
                target: &destination
            },
            &FILTER.inspect(&source),
            &FILTER.inspect(&destination)
        ),
        Err(Error::PersistentLayout(
            layout::H8RelocationError::KernelMismatch
        ))
    ));
}

#[test]
fn every_record_header_allocation_encoding_and_domain_field_is_encoded() {
    let original = ParameterLayout::FlashRecords {
        regions: vec![RecordRegion {
            address: 0x9984,
            basis: AddressBasis::SelectedBank,
            allocation_bytes: Some(0x2000),
            record_bytes: 320,
            record_count: 20,
            header_bytes: 40,
            header_test: HeaderTest::ByteFf,
        }],
        encoding: WordEncoding::LittleEndian,
        domains: vec![LogicalDomain {
            first: 0,
            last: 159,
            region: 0,
        }],
    };
    let expected = value(&original).unwrap().canonical_bytes();
    for field in 0..11 {
        let mut changed = original.clone();
        if let ParameterLayout::FlashRecords {
            regions,
            encoding,
            domains,
        } = &mut changed
        {
            match field {
                0 => regions[0].address += 1,
                1 => regions[0].basis = AddressBasis::Absolute,
                2 => regions[0].allocation_bytes = None,
                3 => regions[0].record_bytes += 1,
                4 => regions[0].record_count += 1,
                5 => regions[0].header_bytes += 1,
                6 => regions[0].header_test = HeaderTest::WordFfff,
                7 => *encoding = WordEncoding::DirectOrBusPermutedLittleEndian,
                8 => domains[0].first += 1,
                9 => domains[0].last += 1,
                _ => domains[0].region += 1,
            }
        }
        assert_ne!(
            expected,
            value(&changed).unwrap().canonical_bytes(),
            "nativefield{field}"
        );
    }
    let a = ParameterLayout::SerialSelected {
        address_bits: 10,
        bases: [0x220, 0x260],
        slots: [8, 10, 11, 9, 12, 0, 1, 2],
        selection: SerialSelection::Header(0x256),
        encoding: WordEncoding::SerialHighByteFirst,
    };
    let mut b = a.clone();
    if let ParameterLayout::SerialSelected { selection, .. } = &mut b {
        *selection = SerialSelection::FallbackWords([0x240; 8]);
    }
    assert_ne!(value(&a), value(&b));
}
#[test]
fn native_misses_are_reported_and_do_not_create_equal_layouts() {
    for hardware in [
        "SAT 1000", "SAT 8000", "SAT 9000", "ATA 0000", "SCSI0001", "UNKNOWN",
    ] {
        let context = Context::new(Firmware {
            hardware,
            normal: &[],
            kernel: None,
        });
        let a = FILTER.inspect(&context);
        assert!(matches!(a.finding, Finding::Unresolved(_)));
        assert_eq!(FILTER.compare(&a, &a), Comparison::Unresolved);
    }
}

#[test]
fn address_only_owner_is_bidirectional_and_candidate_values_remain_distinct() {
    let source_normal = normal();
    let target_normal = variant(&source_normal);
    let kernel = kernel();
    let source = Context::new(fw(&source_normal, &kernel));
    let target = Context::new(fw(&target_normal, &kernel));
    let a = FILTER.inspect(&source);
    let b = FILTER.inspect(&target);
    assert_ne!(FILTER.candidate(&source, &a), FILTER.candidate(&target, &b));
    for (installed, requested, from, to, expected) in [
        (&source, &target, 0x5984, 0x9984, &source_normal),
        (&target, &source, 0x9984, 0x5984, &target_normal),
    ] {
        let operation = FILTER
            .plan(
                &Transition {
                    installed,
                    target: requested,
                },
                &FILTER.inspect(installed),
                &FILTER.inspect(requested),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            operation.description(),
            Some(crate::compatibility::Correction::PersistentParameterLayout { from, to })
        );
        let context = preparation(requested.firmware);
        assert_eq!(operation.prepare(&context).unwrap(), Some(expected.clone()));
        assert_eq!(operation.prepare(&context).unwrap(), Some(expected.clone()));
    }
}

#[test]
fn record_format_and_independent_known_geometry_remain_required() {
    let n = normal();
    let k = kernel();
    let source = Context::new(fw(&n, &k));
    let mut forty = n.clone();
    forty[0x1000..0x3000].fill(0xff);
    layout::install_test_layout_variant(&mut forty, 0x1000, 0);
    fix(&mut forty);
    let target = Context::new(fw(&forty, &k));
    assert!(matches!(
        FILTER.plan(
            &Transition {
                installed: &source,
                target: &target
            },
            &FILTER.inspect(&source),
            &FILTER.inspect(&target)
        ),
        Err(Error::Incompatible)
    ));
    let other_address = variant(&n);
    let mut geometry_difference = Context::new(fw(&other_address, &k));
    // Independent cached native geometry must remain a required comparison;
    // equal primary record dimensions cannot erase that observation.
    geometry_difference.sat.as_mut().unwrap().geometry =
        Observation::Known(crate::image::geometry::Geometry::MarkerBanks {
            marker: 0xfedc4322,
            stride: 0xc000,
        });
    assert!(matches!(
        FILTER.plan(
            &Transition {
                installed: &source,
                target: &geometry_difference
            },
            &FILTER.inspect(&source),
            &FILTER.inspect(&geometry_difference)
        ),
        Err(Error::Incompatible)
    ));
    let mut unrelated = other_address.clone();
    unrelated[0x9000] ^= 1;
    fix(&mut unrelated);
    let changed = Context::new(fw(&unrelated, &k));
    assert!(matches!(
        FILTER.plan(
            &Transition {
                installed: &source,
                target: &changed
            },
            &FILTER.inspect(&source),
            &FILTER.inspect(&changed)
        ),
        Err(Error::PersistentLayout(
            layout::H8RelocationError::OtherProgramDifference
        ))
    ));
    let missing_kernel = Context::new(Firmware {
        kernel: None,
        ..fw(&other_address, &k)
    });
    assert!(matches!(
        FILTER.plan(
            &Transition {
                installed: &source,
                target: &missing_kernel
            },
            &FILTER.inspect(&source),
            &FILTER.inspect(&missing_kernel)
        ),
        Err(Error::UnresolvedIdentity)
    ));
}

#[test]
fn sat1_occupied_retained_region_has_a_specific_normal_collision_diagnosis() {
    let mut old = normal();
    old[0x1000..0x3000].fill(0xff);
    layout::install_test_layout_variant(&mut old, 0x1000, 7);
    fix(&mut old);
    let mut new = old.clone();
    new.resize(0x200000, 0xff);
    for at in (34..new.len() - 3).step_by(2) {
        if new[at - 2] == 0x7a && new[at..at + 4] == 0x5e0000u32.to_be_bytes() {
            new[at..at + 4].copy_from_slice(&0x7f0000u32.to_be_bytes());
        }
    }
    new[20..24].copy_from_slice(&0x200000u32.to_be_bytes());
    new[0x5e0000 - 0x410000 + 80] = 0x12;
    fix(&mut new);
    let kernel = kernel();
    let source = Context::new(Firmware {
        hardware: "SAT 1005",
        ..fw(&old, &kernel)
    });
    let target = Context::new(Firmware {
        hardware: "SAT 1005",
        ..fw(&new, &kernel)
    });
    assert!(matches!(FILTER.inspect(&source).finding, Finding::Known(_)));
    assert!(matches!(FILTER.inspect(&target).finding, Finding::Known(_)));
    assert!(matches!(
        FILTER.plan(
            &Transition {
                installed: &source,
                target: &target
            },
            &FILTER.inspect(&source),
            &FILTER.inspect(&target)
        ),
        Err(Error::PersistentLayoutOverlap {
            start: 0x5e0000,
            end: 0x5e3250
        })
    ));
}
