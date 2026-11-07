use super::*;
use crate::startup::{
    bank,
    checks::{Checks, Error, Policy},
};

fn fixture(index: usize) -> (Vec<u8>, Vec<u8>) {
    let compressed: &[u8] = match index {
        0 => include_bytes!("entry_0_test.zlib"),
        1 => include_bytes!("entry_1_test.zlib"),
        _ => unreachable!(),
    };
    let bytes = miniz_oxide::inflate::decompress_to_vec_zlib(compressed).unwrap();
    assert_eq!(&bytes[..4], b"CAP1");
    let word = |at| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
    let mut normal = vec![0xff; word(4)];
    let mut kernel = vec![0xff; word(8)];
    let mut at = 12;
    while at < bytes.len() {
        let image = if bytes[at] == 0 {
            &mut normal
        } else {
            &mut kernel
        };
        let start = word(at + 1);
        let len = word(at + 5);
        at += 9;
        image[start..start + len].copy_from_slice(&bytes[at..at + len]);
        at += len;
    }
    (normal, kernel)
}

#[test]
fn complete_relocated_native_transactions_pair_under_both_policies() {
    let (a, ka) = fixture(0);
    let (b, kb) = fixture(1);
    for (normal, kernel) in [(&a, &ka), (&b, &kb)] {
        assert_eq!(discover(normal, kernel), Some(Transaction::Jedec4290));
        let guard = bank::discover(normal).unwrap();
        let layout = guard.layout(normal).unwrap();
        assert_eq!(layout.capacity_query, 0x5a2);
        assert_ne!(layout.when_one.markers, layout.otherwise.markers);
    }
    for (source, sk, target, tk) in [(&a, &ka, &b, &kb), (&b, &kb, &a, &ka)] {
        let source = Checks::discover(source, Some(sk));
        for policy in [Policy::CompatibleBanks, Policy::ExplicitCrossflash] {
            source
                .plan_to_with_policy(Checks::discover(target, Some(tk)), policy)
                .unwrap();
        }
    }
}

#[test]
fn every_complete_role_and_every_normalized_operand_is_bound() {
    for (index, form) in shapes::FORMS.iter().enumerate() {
        let (normal, kernel) = fixture(index);
        for span in form.spans {
            let mut changed_normal = normal.clone();
            let mut changed_kernel = kernel.clone();
            match span.component {
                Component::Normal => changed_normal[span.start] ^= 1,
                Component::Kernel => changed_kernel[span.start] ^= 1,
            }
            assert!(
                discover(&changed_normal, &changed_kernel).is_none(),
                "unbound role {:#x}",
                span.start
            );
            for relocation in span.relocations {
                let mut changed_normal = normal.clone();
                let mut changed_kernel = kernel.clone();
                let at = span.start + relocation.at;
                match span.component {
                    Component::Normal => changed_normal[at] ^= 1,
                    Component::Kernel => changed_kernel[at] ^= 1,
                }
                assert!(
                    span.matches(form.spans, &changed_normal, &changed_kernel)
                        .is_none(),
                    "unbound operand {at:#x}"
                );
            }
        }
    }
}

#[test]
fn query_constructor_controller_and_irq_mutations_refuse_the_actual_planner() {
    let (installed, ik) = fixture(0);
    let (target, tk) = fixture(1);
    let source = Checks::discover(&installed, Some(&ik));
    // Query command, result partition, builder, copied block bound, constructor
    // target, logger interrupt masking, runtime IRQ entry, controller setup.
    for (component, cpu) in [
        (Component::Normal, 0x57c4ee + 6),
        (Component::Normal, 0x57c52e + 16),
        (Component::Normal, 0x57c592 + 22),
        (Component::Normal, 0x4af4f8 + 5),
        (Component::Normal, 0x5b388c),
        (Component::Normal, 0x54a024 + 1),
        (Component::Kernel, 0x40b6f4),
        (Component::Kernel, 0x4062d4 + 18),
    ] {
        let mut n = target.clone();
        let mut k = tk.clone();
        match component {
            Component::Normal => n[cpu - 0x410000] ^= 1,
            Component::Kernel => k[cpu - 0x400000] ^= 1,
        }
        assert_eq!(bank::analyze(&n), bank::analyze(&target));
        for policy in [Policy::CompatibleBanks, Policy::ExplicitCrossflash] {
            assert_eq!(
                source.plan_to_with_policy(Checks::discover(&n, Some(&k)), policy),
                Err(Error::CapacityRelationUnproved)
            );
        }
    }
}

#[test]
fn scoped_certificate_allows_unrelated_bytes_and_dynamic_matching_headers() {
    for index in 0..2 {
        let (mut normal, mut kernel) = fixture(index);
        let before = Checks::discover(&normal, Some(&kernel));
        normal[0x18000] ^= 1; // outside every recognized native role
        let descriptor = shapes::FORMS[index].kernel_descriptor;
        normal[3] ^= 1;
        kernel[descriptor + 3] ^= 1;
        normal[0x1a] ^= 1;
        kernel[0x100a] ^= 1;
        assert_eq!(discover(&normal, &kernel), Some(Transaction::Jedec4290));
        assert!(before
            .plan_to(Checks::discover(&normal, Some(&kernel)))
            .is_ok());
        kernel[descriptor] ^= 1;
        assert!(discover(&normal, &kernel).is_none());
    }
}

#[test]
fn marker_bridge_keeps_only_the_generation_relation_actually_executed() {
    let (normal, original) = fixture(0);
    let mut temporary = original.clone();
    temporary[0xfe] = 1;
    // This form never reads the generation marker. Both actual stages are
    // recognized; receiver planning separately owns restoration and signing.
    assert_eq!(discover(&normal, &temporary), Some(Transaction::Jedec4290));
    let original_checks = Checks::discover(&normal, Some(&original));
    let bridge_checks = Checks::discover(&normal, Some(&temporary));
    assert!(original_checks.plan_to(bridge_checks).is_ok());
    assert!(bridge_checks.plan_to(original_checks).is_ok());
    let (normal, mut checked) = fixture(1);
    checked[0xfe] ^= 1;
    assert!(discover(&normal, &checked).is_none());
    checked[0xfe] = normal[0x28];
    assert!(discover(&normal, &checked).is_some());
}
