use super::*;
use crate::compatibility::{plan, Correction, Error, Firmware};
use crate::image::{geometry::Geometry, layout::H8RelocationError, phase};

fn fix(n: &mut [u8]) {
    n[16..20].fill(0);
    let sum = n.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    n[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
}
fn normal() -> Vec<u8> {
    let mut n = alloc::vec![0xff; 0x10000];
    crate::image::matrix::install_test_contract(&mut n, 0);
    n[0x1000..].fill(0xff);
    crate::image::layout::install_test_layout_variant(&mut n, 0x1000, 8);
    n[..16].copy_from_slice(b"PIONEER TEST    ");
    n[20..24].copy_from_slice(&0x10000u32.to_be_bytes());
    n[24..32].fill(0);
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
    let mut k = alloc::vec![0;0x10000];
    k[0x1000..0x1008].copy_from_slice(b"SAT 8600");
    let sum = k.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    k[0x1020..0x1024].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
    k
}
fn firmware<'a>(normal: &'a [u8], kernel: &'a [u8]) -> Firmware<'a> {
    Firmware {
        hardware: "SAT 8600",
        normal,
        kernel: Some(kernel),
    }
}

#[test]
fn planner_corrects_address_variants_both_ways_without_merging_candidate_keys() {
    let n = normal();
    let target = variant(&n);
    let k = kernel();
    let source = crate::image::matrix::discover("SAT 8600", &n, Some(&k)).unwrap();
    let destination = crate::image::matrix::discover("SAT 8600", &target, Some(&k)).unwrap();
    assert_ne!(source.candidate, destination.candidate);
    let p = plan(firmware(&n, &k), firmware(&target, &k)).unwrap();
    assert_eq!(
        p.corrections(),
        &[Correction::PersistentParameterLayout {
            from: 0x5984,
            to: 0x9984
        }]
    );
    assert_eq!(p.prepare_normal().unwrap(), Some(n.clone()));
    assert_eq!(p.prepare_normal().unwrap(), Some(n.clone()));
    assert_eq!(
        plan(firmware(&target, &k), firmware(&n, &k))
            .unwrap()
            .prepare_normal()
            .unwrap(),
        Some(target)
    );
}

#[test]
fn phase_and_layout_share_one_verified_owned_preparation() {
    let n = normal();
    let k = kernel();
    let target = phase::correct_normal(&variant(&n), phase::Assignment::Swapped).unwrap();
    let p = plan(firmware(&n, &k), firmware(&target, &k)).unwrap();
    assert_eq!(
        p.corrections(),
        &[
            Correction::Phase {
                from: phase::Assignment::Swapped,
                to: phase::Assignment::Direct
            },
            Correction::PersistentParameterLayout {
                from: 0x5984,
                to: 0x9984
            }
        ]
    );
    assert_eq!(p.prepare_normal().unwrap(), Some(n.clone()));
    let back = plan(firmware(&target, &k), firmware(&n, &k)).unwrap();
    assert_eq!(back.prepare_normal().unwrap(), Some(target));
}

#[test]
fn planner_requires_full_program_equivalence_exact_kernel_and_other_filters() {
    let n = normal();
    let k = kernel();
    let target = variant(&n);
    let mut unrelated = target.clone();
    unrelated[0x8000] ^= 1;
    fix(&mut unrelated);
    assert!(matches!(
        plan(firmware(&n, &k), firmware(&unrelated, &k)),
        Err(Error::PersistentLayout(
            H8RelocationError::OtherProgramDifference
        ))
    ));
    let mut other_kernel = k.clone();
    other_kernel[0x9000] ^= 1;
    assert!(matches!(
        plan(firmware(&n, &k), firmware(&target, &other_kernel)),
        Err(Error::PersistentLayout(H8RelocationError::KernelMismatch))
    ));
    let mut wrong_irq = target.clone();
    wrong_irq[0x701] ^= 1;
    fix(&mut wrong_irq);
    assert!(matches!(
        plan(firmware(&n, &k), firmware(&wrong_irq, &k)),
        Err(Error::Incompatible)
    ));
    assert!(matches!(
        plan(
            firmware(&n, &k),
            Firmware {
                kernel: None,
                ..firmware(&target, &k)
            }
        ),
        Err(Error::UnresolvedIdentity)
    ));
}

#[test]
fn address_comparison_preserves_independent_bank_geometry_and_record_format() {
    let n = normal();
    let target = variant(&n);
    let a = crate::image::matrix::discover("SAT 8600", &n, None)
        .unwrap()
        .candidate;
    let b = crate::image::matrix::discover("SAT 8600", &target, None)
        .unwrap()
        .candidate;
    let (adjusted, from, to) = address_only_candidate(&a, &b).unwrap();
    assert_eq!((from, to), (0x5984, 0x9984));
    assert_eq!(adjusted, a);
    let source = Key::Sat(SatKey::Sat9 {
        geometry: Geometry::MarkerBanks {
            marker: 1,
            stride: 0x10000,
        },
        host: 0,
        phase: None,
        layout: sat_layout(&a).unwrap().clone(),
    });
    let destination = Key::Sat(SatKey::Sat9 {
        geometry: Geometry::MarkerBanks {
            marker: 1,
            stride: 0xc000,
        },
        host: 0,
        phase: None,
        layout: sat_layout(&b).unwrap().clone(),
    });
    let (adjusted, ..) = address_only_candidate(&source, &destination).unwrap();
    assert!(!crate::compatibility::compatible_candidates(
        &source, &adjusted
    ));
    let mut format = b.clone();
    if let Key::Sat(SatKey::Sat8 {
        layout: ParameterLayout::FlashRecords { regions, .. },
        ..
    }) = &mut format
    {
        regions[0].record_count = 40;
        regions[0].header_bytes = 80;
    }
    assert!(address_only_candidate(&a, &format).is_none());
}
