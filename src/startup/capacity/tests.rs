use super::*;
use crate::startup::bank;
use crate::startup::checks::{Checks, Error, Policy};

fn distinct_cases() -> Vec<u8> {
    // Versioned capacity fixture with distinct address cases but no recognized
    // discriminator copy, so the program digest never resolves: equal cases
    // alone must never relate.
    bank::versioned_fixture(0xfedc_4321, [0xfffa, 0x1_fffa])
}

#[test]
fn equal_address_cases_with_unproved_discriminators_refuse_both_policies() {
    let installed = distinct_cases();
    let mut target = installed.clone();
    target[0] ^= 1;
    let kernel = vec![0; 0x10000];
    assert_eq!(bank::analyze(&installed), bank::analyze(&target));
    for policy in [Policy::CompatibleBanks, Policy::ExplicitCrossflash] {
        assert_eq!(
            Checks::discover(&installed, Some(&kernel))
                .plan_to_with_policy(Checks::discover(&target, Some(&kernel)), policy),
            Err(Error::CapacityRelationUnproved)
        );
    }
}

#[test]
fn complete_pair_identity_is_positive_but_missing_or_changed_kernel_is_not() {
    let normal = distinct_cases();
    let kernel = vec![0; 0x10000];
    let checks = Checks::discover(&normal, Some(&kernel));
    assert!(checks.plan_to(checks).is_ok());
    let missing = Checks::discover(&normal, None);
    assert_eq!(
        missing.plan_to(missing),
        Err(Error::CapacityRelationUnproved)
    );
    assert_eq!(
        checks.plan_to(missing),
        Err(Error::CapacityRelationUnproved)
    );
    let mut changed = kernel.clone();
    changed[0x200] = 1;
    assert_eq!(
        checks.plan_to(Checks::discover(&normal, Some(&changed))),
        Err(Error::CapacityRelationUnproved)
    );
    let short = Checks::discover(&normal, Some(&kernel[..0x100]));
    assert_eq!(short.plan_to(short), Err(Error::CapacityRelationUnproved));
}

#[test]
fn actual_collapsed_native_address_expression_does_not_need_a_query_relation() {
    let mut normal = distinct_cases();
    for (at, value) in [
        (0x1406, 0x800000u32),
        (0x1418, 0x800000),
        (0x1420, 0x30001),
        (0x1428, 0x20001),
    ] {
        normal[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }
    normal[0x1410..0x1412].copy_from_slice(&[0, 0x7f]);
    let guard = bank::discover(&normal).unwrap();
    let layout = guard.layout(&normal).unwrap();
    assert_eq!(layout.when_one.markers, layout.otherwise.markers);
    // Both branches are actual recognized code, not a hand-built enum.
    let mut changed = normal.clone();
    changed[0] ^= 1;
    assert!(Checks::discover(&normal, None)
        .plan_to(Checks::discover(&changed, None))
        .is_ok());
}

#[test]
fn fixed_banks_keep_their_existing_pairing_behavior() {
    let mut normal = vec![0; 0x2000];
    bank::fixture(&mut normal);
    assert!(matches!(
        bank::analyze(&normal).unwrap().addresses,
        Addresses::Fixed(_)
    ));
    let mut changed = normal.clone();
    changed[0] ^= 1;
    for policy in [Policy::CompatibleBanks, Policy::ExplicitCrossflash] {
        assert!(Checks::discover(&normal, None)
            .plan_to_with_policy(Checks::discover(&changed, None), policy)
            .is_ok());
    }
}

#[test]
fn capacity_refusal_has_a_specific_public_code() {
    use crate::CodedError;
    let e = Error::CapacityRelationUnproved;
    assert_eq!(e.code(), "pioneer.startup.capacity_relation_unproved");
    assert!(e.to_string().contains("capacity discriminator relation"));
}
