use super::*;
use alloc::vec;

fn body(entries: &[u32], terminate: bool) -> Vec<u8> {
    let mut b = vec![0u8; COMP_OFFSET + 0x104];
    b[COMP_OFFSET..COMP_OFFSET + 4].copy_from_slice(b"COMP");
    let mut off = COMP_OFFSET + 4;
    for e in entries {
        b[off..off + 4].copy_from_slice(&e.to_be_bytes());
        off += 4;
    }
    if terminate {
        b[off..off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    }
    b
}

#[test]
fn be_u32_bounds() {
    assert_eq!(be_u32(&[1, 2, 3, 4], 0), Some(0x0102_0304));
    assert_eq!(be_u32(&[0, 1, 2, 3, 4], 1), Some(0x0102_0304));
    assert_eq!(be_u32(&[1, 2, 3], 0), None);
    assert_eq!(be_u32(&[1, 2, 3, 4], usize::MAX), None);
}

#[test]
fn pairs_from_directory() {
    assert_eq!(
        comp_pairs(&body(&[1, 2, 3, 4], true)),
        Some(vec![(1, 2), (3, 4)])
    );
}

#[test]
fn directory_must_be_even_nonempty_and_within_cap() {
    assert_eq!(comp_pairs(&body(&[], true)), None);
    assert_eq!(comp_pairs(&body(&[1, 2, 3], true)), None);
    let ok: Vec<u32> = (0..MAX_ENTRIES as u32).collect();
    assert_eq!(comp_pairs(&body(&ok, true)).map(|p| p.len()), Some(16));
    let over: Vec<u32> = (0..MAX_ENTRIES as u32 + 2).collect();
    assert_eq!(comp_pairs(&body(&over, true)), None);
}

#[test]
fn marker_and_bounds_are_checked() {
    let mut b = body(&[1, 2], true);
    b[COMP_OFFSET] = b'X';
    assert_eq!(comp_pairs(&b), None);
    assert_eq!(comp_pairs(&[]), None);
    // Marker present but the directory region is truncated, no terminator.
    let mut short = body(&[1, 2], false);
    short.truncate(COMP_OFFSET + 0x20);
    assert_eq!(comp_pairs(&short), None);
    // A marker that ends exactly at the end of the body.
    let mut tiny = vec![0u8; COMP_OFFSET + 4];
    tiny[COMP_OFFSET..].copy_from_slice(b"COMP");
    assert_eq!(comp_pairs(&tiny), None);
}
