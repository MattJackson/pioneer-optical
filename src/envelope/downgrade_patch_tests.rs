use super::*;

fn sum32_be(body: &[u8]) -> u32 {
    body.chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .fold(0u32, |acc, w| acc.wrapping_add(w))
}

/// Build a 64 KiB body with a given marker and a word at 0x1020 that
/// zero-balances the sum. The transform must preserve that zero sum.
fn body_with_marker(marker: u8) -> Vec<u8> {
    let mut b = vec![0u8; KERNEL_BODY_LEN];
    b[KERNEL_MARKER_OFFSET] = marker;
    // Compensate: pre-populate the checksum word so the full-body
    // additive sum is zero (the invariant on real Kernels).
    let marker_word_offset = KERNEL_MARKER_OFFSET & !3;
    let mw = u32::from_be_bytes([
        b[marker_word_offset],
        b[marker_word_offset + 1],
        b[marker_word_offset + 2],
        b[marker_word_offset + 3],
    ]);
    let correction = mw.wrapping_neg();
    b[KERNEL_CHECKSUM_WORD_OFFSET..KERNEL_CHECKSUM_WORD_OFFSET + 4]
        .copy_from_slice(&correction.to_be_bytes());
    debug_assert_eq!(sum32_be(&b), 0);
    b
}

#[test]
fn ff_marker_is_patched_and_sum_preserved() {
    let b = body_with_marker(0xFF);
    let (patched, outcome) = downgrade_patch(&b).unwrap();
    assert_eq!(patched.len(), KERNEL_BODY_LEN);
    assert_eq!(patched[KERNEL_MARKER_OFFSET], 0x01);
    assert_eq!(
        sum32_be(&patched),
        0,
        "zero-sum invariant must survive the patch"
    );
    match outcome {
        DowngradePatchOutcome::Patched {
            marker_before,
            checksum_word_before,
            checksum_word_after,
        } => {
            assert_eq!(marker_before, 0xFF);
            // FF->01 compensation is +0xFE00.
            assert_eq!(
                checksum_word_after,
                checksum_word_before.wrapping_add(0xFE00)
            );
        }
        _ => panic!("expected Patched"),
    }
    // Only the two expected regions differ.
    for (i, (&a, &c)) in b.iter().zip(patched.iter()).enumerate() {
        if a != c {
            assert!(
                i == KERNEL_MARKER_OFFSET
                    || (KERNEL_CHECKSUM_WORD_OFFSET..KERNEL_CHECKSUM_WORD_OFFSET + 4).contains(&i),
                "unexpected diff at {i:#x}"
            );
        }
    }
}

#[test]
fn checksum_word_is_read_and_written_byte_for_byte() {
    // Four distinct bytes: any wrong index arithmetic reads a different word.
    let mut b = body_with_marker(0xFF);
    let o = KERNEL_CHECKSUM_WORD_OFFSET;
    b[o..o + 4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    let (patched, outcome) = downgrade_patch(&b).unwrap();
    assert_eq!(
        outcome,
        DowngradePatchOutcome::Patched {
            marker_before: 0xFF,
            checksum_word_before: 0x1122_3344,
            // (0x01 - 0xFF) * 0x100 = -0xFE00; compensation adds 0xFE00.
            checksum_word_after: 0x1123_3144,
        }
    );
    assert_eq!(&patched[o..o + 4], &[0x11, 0x23, 0x31, 0x44]);
}

#[test]
fn zero_marker_is_patched_like_ff() {
    let b = body_with_marker(0x00);
    let (patched, outcome) = downgrade_patch(&b).unwrap();
    assert_eq!(patched[KERNEL_MARKER_OFFSET], 0x01);
    assert_eq!(sum32_be(&patched), 0);
    assert!(matches!(
        outcome,
        DowngradePatchOutcome::Patched {
            marker_before: 0x00,
            ..
        }
    ));
}

#[test]
fn already_newer_is_noop_not_error() {
    let b = body_with_marker(0x01);
    let (patched, outcome) = downgrade_patch(&b).unwrap();
    assert_eq!(patched, b, "AlreadyNewer must return a byte-identical body");
    assert_eq!(outcome, DowngradePatchOutcome::AlreadyNewer);
}

#[test]
fn unknown_marker_refused() {
    let mut b = body_with_marker(0xFF);
    b[KERNEL_MARKER_OFFSET] = 0x55; // not FF/00/01
    assert_eq!(
        downgrade_patch(&b),
        Err(Error::UnknownMarker { marker: 0x55 }),
    );
}

#[test]
fn wrong_size_refused() {
    let b = vec![0u8; KERNEL_BODY_LEN - 1];
    assert_eq!(
        downgrade_patch(&b),
        Err(Error::KernelBodySize {
            got: KERNEL_BODY_LEN - 1
        }),
    );
}
