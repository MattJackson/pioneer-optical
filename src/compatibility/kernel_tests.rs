use super::*;
use crate::envelope::synthetic_roundtrip_tests::front_kernel;

fn kernel(gated: bool, marker: u8, entry: u32) -> Vec<u8> {
    let mut bytes = front_kernel();
    crate::image::handoff_fixture(&mut bytes);
    let receiver = crate::image::receiver_fixture(gated);
    bytes[0x300..0x380].copy_from_slice(&receiver[0x100..0x180]);
    if gated {
        bytes[0x3000..0x3100].copy_from_slice(&receiver[0x1000..0x1100]);
        bytes[0x363..0x366].copy_from_slice(&[0x40, 0x30, 0]);
    }
    if entry != 0x400020 {
        let at = (entry - 0x400000) as usize;
        bytes.copy_within(0x20..0x30, at);
        bytes[0x20..at].fill(0);
    }
    bytes[0x2105..0x2108].copy_from_slice(&entry.to_be_bytes()[1..]);
    bytes[crate::envelope::KERNEL_MARKER_OFFSET] = marker;
    fix_sum(&mut bytes);
    bytes
}

fn fix_sum(bytes: &mut [u8]) {
    let end = bytes.len() - 4;
    bytes[end..].fill(0);
    let sum = bytes.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    bytes[end..].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
}

#[test]
fn kernel_rules_cover_both_directions_without_mutating_the_inputs() {
    for source_entry in [0x400020, 0x40002a] {
        for target_entry in [0x400020, 0x40002a] {
            for source_gated in [false, true] {
                for target_gated in [false, true] {
                    for target_marker in [0, 1, 0xff] {
                        let source = kernel(source_gated, 1, source_entry);
                        let target = kernel(target_gated, target_marker, target_entry);
                        let original_source = source.clone();
                        let original_target = target.clone();
                        let result = plan_kernel(&source, &target);
                        if source_gated && target_gated && target_marker != 1 {
                            assert_eq!(
                                result.err(),
                                Some(KernelPlanningError::UnsupportedRestoration)
                            );
                        } else {
                            let plan = result.unwrap();
                            let mut expected = Vec::new();
                            if source_entry != target_entry {
                                expected.push(KernelStep::Handoff {
                                    from: source_entry,
                                    to: target_entry,
                                });
                            }
                            if source_gated && target_marker != 1 {
                                expected.push(KernelStep::ReceiverMarker {
                                    from: target_marker,
                                    to: 1,
                                });
                            }
                            expected.push(KernelStep::Target);
                            assert_eq!(plan.steps(), expected);
                            assert_eq!(plan.restores_marker(), source_gated && target_marker != 1);
                            assert!(plan.matches_components(&source, &target));
                        }
                        assert_eq!(source, original_source);
                        assert_eq!(target, original_target);
                    }
                }
            }
        }
    }
}

#[test]
fn kernel_plan_is_bound_to_both_complete_component_bodies() {
    let source = kernel(true, 1, 0x400020);
    let target = kernel(false, 0xff, 0x40002a);
    let plan = plan_kernel(&source, &target).unwrap();
    let mut other_source = source.clone();
    other_source[0x7000] ^= 1;
    fix_sum(&mut other_source);
    let mut other_target = target.clone();
    other_target[0x7000] ^= 1;
    fix_sum(&mut other_target);
    assert!(!plan.matches_components(&other_source, &target));
    assert!(!plan.matches_components(&source, &other_target));
    assert!(!plan.matches_components(&target, &source));
}

#[test]
fn unknown_or_conflicting_handoff_evidence_never_selects_a_bridge() {
    let source = kernel(false, 1, 0x400020);
    let target = kernel(false, 1, 0x40002a);
    assert_eq!(
        plan_kernel(&vec![0; 0x10000], &target).err(),
        Some(KernelPlanningError::UnknownInstalledPolicy)
    );
    let mut no_programmer = source.clone();
    no_programmer[0x2000] = 0;
    assert_eq!(
        plan_kernel(&no_programmer, &target).err(),
        Some(KernelPlanningError::Handoff(
            KernelHandoffError::UnknownInstalled
        ))
    );
    let mut ambiguous = target.clone();
    ambiguous.copy_within(0x2a..0x3a, 0x80);
    assert_eq!(
        plan_kernel(&source, &ambiguous).err(),
        Some(KernelPlanningError::Handoff(
            KernelHandoffError::UnknownTarget
        ))
    );
    let mut already_redirected = source.clone();
    already_redirected[0x2105..0x2108].copy_from_slice(&0x400060u32.to_be_bytes()[1..]);
    assert_eq!(
        plan_kernel(&already_redirected, &target).err(),
        Some(KernelPlanningError::Handoff(KernelHandoffError::Mismatch {
            installed: 0x400060,
            target: 0x400020,
        }))
    );
}

#[test]
fn source_bridge_marker_must_satisfy_the_installed_receiver() {
    let target = kernel(false, 1, 0x40002a);
    for marker in [0, 0xff] {
        let source = kernel(true, marker, 0x400020);
        assert_eq!(
            plan_kernel(&source, &target).err(),
            Some(KernelPlanningError::RejectedBridgeMarker)
        );
    }
}
