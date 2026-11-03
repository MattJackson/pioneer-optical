use super::*;

fn sum(bytes: &[u8]) -> u32 {
    bytes.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    })
}
fn fix_normal(bytes: &mut [u8]) {
    bytes[16..20].fill(0);
    let value = sum(bytes).wrapping_neg();
    bytes[16..20].copy_from_slice(&value.to_be_bytes());
}
fn kernel() -> Vec<u8> {
    let mut k = alloc::vec![0; 0x10000];
    k[0x1000..0x1008].copy_from_slice(b"SAT 9000");
    let value = sum(&k).wrapping_neg();
    k[0x1020..0x1024].copy_from_slice(&value.to_be_bytes());
    k
}
fn normal(variant: usize, size: usize) -> Vec<u8> {
    let mut n = alloc::vec![0xff; size];
    n[..16].copy_from_slice(b"PIONEER TEST    ");
    n[20..24].copy_from_slice(&(size as u32).to_be_bytes());
    n[24..32].fill(0);
    n[0xd00..0xf00].copy_from_slice(&crate::image::phase::tests::fixture(false));
    crate::image::layout::install_test_layout_variant(&mut n, 0x1000, variant);
    fix_normal(&mut n);
    n
}
fn extra_operations(n: &mut [u8], primary: u32) {
    // Consumers outside the getter graph: MOV, ADD, CMP and SUB. The complete
    // program proof must include their operands rather than patching only the
    // three read-side fields.
    for (i, opcode) in [0, 0x10, 0x20, 0x30].into_iter().enumerate() {
        let at = 0x9000 + i * 16;
        n[at..at + 2].copy_from_slice(&[0x7a, opcode]);
        n[at + 2..at + 6].copy_from_slice(&primary.to_be_bytes());
        n[at + 6..at + 8].copy_from_slice(&[0x54, 0x70]);
    }
    fix_normal(n);
}
fn variant(n: &[u8], from: u32, to: u32) -> Vec<u8> {
    let mut out = n.to_vec();
    for at in (34..n.len() - 3).step_by(2) {
        if n[at - 2] == 0x7a && n[at..at + 4] == from.to_be_bytes() {
            out[at..at + 4].copy_from_slice(&to.to_be_bytes());
        }
    }
    fix_normal(&mut out);
    out
}

#[test]
fn address_only_equivalence_covers_all_operations_both_ways() {
    let k = kernel();
    let mut installed = normal(8, 0x10000);
    extra_operations(&mut installed, 0x9984);
    let target = variant(&installed, 0x9984, 0x5984);
    let plan = plan_h8_relocation(&installed, &k, &target, &k).unwrap();
    assert_eq!((plan.from(), plan.to()), (0x5984, 0x9984));
    assert_eq!(plan.operands().len(), 7);
    let fixed = plan.prepare_normal().unwrap();
    assert_eq!(fixed, installed);
    let reverse = plan_h8_relocation(&target, &k, &installed, &k).unwrap();
    assert_eq!(reverse.prepare_normal().unwrap(), target);
    let no_change = plan_h8_relocation(&installed, &k, &installed, &k).unwrap();
    assert!(no_change.operands().is_empty());
    assert_eq!(no_change.prepare_normal().unwrap(), installed);
}

#[test]
fn phase_and_layout_are_composed_once_and_reverse_exactly() {
    let k = kernel();
    let mut installed = normal(8, 0x10000);
    extra_operations(&mut installed, 0x9984);
    let target = variant(&installed, 0x9984, 0x5984);
    let swapped = phase::correct_normal(&target, phase::Assignment::Swapped).unwrap();
    let plan = plan_h8_relocation(&installed, &k, &swapped, &k).unwrap();
    let fixed = plan
        .prepare_with_phase(Some(phase::Assignment::Direct))
        .unwrap();
    assert_eq!(fixed, installed);
    assert_eq!(sum(&fixed), 0);
    let reverse = plan_h8_relocation(&swapped, &k, &installed, &k).unwrap();
    assert_eq!(
        reverse
            .prepare_with_phase(Some(phase::Assignment::Swapped))
            .unwrap(),
        swapped
    );
}

#[test]
fn unsupported_target_changes_are_not_silently_replaced_by_installed_code() {
    let k = kernel();
    let installed = normal(8, 0x10000);
    let mut target = variant(&installed, 0x9984, 0x5984);
    target[0x8000] ^= 1;
    fix_normal(&mut target);
    assert!(matches!(
        plan_h8_relocation(&installed, &k, &target, &k),
        Err(H8RelocationError::OtherProgramDifference)
    ));
    assert_ne!(target, installed);
}

#[test]
fn unbound_address_encoding_is_not_treated_as_an_immediate_patch() {
    let k = kernel();
    let mut installed = normal(8, 0x10000);
    installed[0x9000..0x9008].copy_from_slice(&[1, 0, 0x6b, 0x20, 0, 0, 0x99, 0x84]);
    fix_normal(&mut installed);
    let mut target = variant(&installed, 0x9984, 0x5984);
    target[0x9004..0x9008].copy_from_slice(&0x5984u32.to_be_bytes());
    fix_normal(&mut target);
    assert!(matches!(
        plan_h8_relocation(&installed, &k, &target, &k),
        Err(H8RelocationError::OtherProgramDifference)
    ));
}

#[test]
fn original_integrity_kernel_binding_and_record_format_are_mandatory() {
    let k = kernel();
    let installed = normal(8, 0x10000);
    let target = variant(&installed, 0x9984, 0x5984);
    let mut bad = target.clone();
    bad[0x8000] ^= 1;
    assert!(matches!(
        plan_h8_relocation(&installed, &k, &bad, &k),
        Err(H8RelocationError::InvalidNormal)
    ));
    let mut other_kernel = k.clone();
    other_kernel[0x8000] ^= 1;
    assert!(matches!(
        plan_h8_relocation(&installed, &k, &target, &other_kernel),
        Err(H8RelocationError::KernelMismatch)
    ));
    let forty = normal(0, 0x10000);
    assert!(matches!(
        plan_h8_relocation(&forty, &k, &target, &k),
        Err(H8RelocationError::FormatChange)
    ));
    let mut partial = target.clone();
    // Restore only one resolver operand. Complete graph consistency must fail.
    let at = (34..partial.len() - 3)
        .step_by(2)
        .find(|&at| partial[at - 2] == 0x7a && partial[at..at + 4] == 0x5984u32.to_be_bytes())
        .unwrap();
    partial[at..at + 4].copy_from_slice(&0x9984u32.to_be_bytes());
    fix_normal(&mut partial);
    assert!(matches!(
        plan_h8_relocation(&installed, &k, &partial, &k),
        Err(H8RelocationError::UnresolvedReader)
    ));
}

#[test]
fn absolute_records_cannot_be_redirected_into_the_target_payload() {
    let k = kernel();
    let installed = normal(7, 0x200000);
    let target = variant(&installed, 0x5e0000, 0x7f0000);
    assert!(matches!(
        plan_h8_relocation(&installed, &k, &target, &k),
        Err(H8RelocationError::NormalOverlap)
    ));
}

#[test]
fn checksum_valid_header_changes_cannot_bypass_complete_program_equivalence() {
    let k = kernel();
    let installed = normal(8, 0x10000);
    let target = variant(&installed, 0x9984, 0x5984);
    // Any header byte may be read by code. Both the printable banner and the
    // identity fields must match even when integrity and native readers pass.
    for offset in [0, 15, 24, 31] {
        let mut changed = target.clone();
        changed[offset] = if offset < 16 { b'X' } else { 0x12 };
        fix_normal(&mut changed);
        assert!(edits::valid_normal(&changed));
        assert!(matches!(
            discover_h8_reader(&changed, Some(&k)),
            Observation::Known(_)
        ));
        assert!(
            matches!(
                plan_h8_relocation(&installed, &k, &changed, &k),
                Err(H8RelocationError::OtherProgramDifference)
            ),
            "header offset {offset}"
        );
    }
}
