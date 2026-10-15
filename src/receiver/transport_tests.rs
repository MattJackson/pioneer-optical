use super::*;

const STAGING_ADD: [u8; 6] = [0x7a, 0x10, 0x00, 0x01, 0x02, 0x00];

/// A synthetic kernel body carrying the 10xx handler fingerprint.
fn signature_body() -> Vec<u8> {
    let mut img = vec![0u8; BODY_LEN];
    img[0x100..0x106].copy_from_slice(&STAGING_ADD);
    img[0x200..0x204].copy_from_slice(&0x0001_1200u32.to_be_bytes());
    img[0x300..0x304].copy_from_slice(&0x0002_0400u32.to_be_bytes());
    img[0x400..0x404].copy_from_slice(&0x0041_0000u32.to_be_bytes());
    img
}

#[test]
fn detects_two_region_from_fingerprint() {
    assert_eq!(detect(&signature_body()), KernelReceive::FrontKeyTwoRegion);
}

#[test]
fn plain_body_is_linear() {
    assert_eq!(detect(&vec![0u8; BODY_LEN]), KernelReceive::Linear);
    // The staging add alone, without the flush constants, is not enough.
    let mut img = vec![0u8; BODY_LEN];
    img[0x10..0x16].copy_from_slice(&STAGING_ADD);
    assert_eq!(detect(&img), KernelReceive::Linear);
}

#[test]
fn two_region_plan_splits_body_and_front() {
    // Distinct front and body bytes so we can prove where each lands.
    let mut wire = vec![0xAAu8; FRONT_LEN];
    wire.extend(core::iter::repeat(0xBB).take(BODY_LEN));
    let normal = [0u8; 0x40];
    let mut storage = [Segment::PLACEHOLDER; 3];
    let plan = plan(
        Some(&wire),
        &normal,
        KernelReceive::FrontKeyTwoRegion,
        &mut storage,
    )
    .unwrap();

    assert_eq!(plan.segments.len(), 3);

    // Body: the trailing 0x10000 of the wire, to transfer offset 0.
    let body = plan.segments[0];
    assert_eq!(body.role, Role::Kernel);
    assert_eq!(body.buffer_id, cdb::KERNEL_ID);
    assert_eq!(body.dest_offset, 0);
    assert_eq!(body.bytes.len(), BODY_LEN);
    assert!(body.bytes.iter().all(|&b| b == 0xBB));

    // Front: the leading 0x1200, to transfer offset 0x10200.
    let front = plan.segments[1];
    assert_eq!(front.dest_offset, FRONT_DEST_OFFSET);
    assert_eq!(front.bytes.len(), FRONT_LEN);
    assert!(front.bytes.iter().all(|&b| b == 0xAA));

    // Normal unchanged: linear from zero on the Normal buffer.
    let n = plan.segments[2];
    assert_eq!(n.role, Role::Normal);
    assert_eq!(n.buffer_id, cdb::NORMAL_ID);
    assert_eq!(n.dest_offset, 0);
}

#[test]
fn linear_plan_is_one_kernel_segment() {
    let wire = vec![0u8; 0x4000];
    let normal = [0u8; 0x40];
    let mut storage = [Segment::PLACEHOLDER; 3];
    let plan = plan(Some(&wire), &normal, KernelReceive::Linear, &mut storage).unwrap();
    assert_eq!(plan.segments.len(), 2);
    assert_eq!(plan.segments[0].dest_offset, 0);
    assert_eq!(plan.segments[0].bytes.len(), 0x4000);
}

#[test]
fn two_region_rejects_unexpected_wire_length() {
    let wire = vec![0u8; WIRE_LEN - 1];
    let normal = [0u8; 0x40];
    let mut storage = [Segment::PLACEHOLDER; 3];
    assert!(matches!(
        plan(
            Some(&wire),
            &normal,
            KernelReceive::FrontKeyTwoRegion,
            &mut storage
        ),
        Err(PlanError::KernelLayout)
    ));
}
