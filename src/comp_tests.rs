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

#[cfg(feature = "image")]
#[test]
fn comp_streams_huge_end_offset_is_invalid_without_panic() {
    let mut image = vec![0u8; 0x3000];
    image[COMP_OFFSET..COMP_OFFSET + 4].copy_from_slice(b"COMP");
    image[COMP_OFFSET + 4..COMP_OFFSET + 8].copy_from_slice(&0x2000u32.to_be_bytes());
    image[COMP_OFFSET + 8..COMP_OFFSET + 12].copy_from_slice(&0xFFFF_FFFEu32.to_be_bytes());
    image[COMP_OFFSET + 12..COMP_OFFSET + 16].copy_from_slice(&u32::MAX.to_be_bytes());
    let result = crate::comp_streams::read(&image, usize::MAX, &mut || true);
    assert!(matches!(
        result,
        Err(crate::comp_streams::StreamError::Invalid)
    ));
}

#[cfg(feature = "image")]
#[test]
fn comp_streams_share_one_decode_budget_across_candidate_bases() {
    use std::io::Write;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&[0x5a; 1000]).unwrap();
    let compressed = encoder.finish().unwrap();
    let base = 0x40_0000u32;
    let mut image = vec![0u8; 0x8000];
    let entries = [
        base + 0x2000,
        base + 0x2000 + compressed.len() as u32,
        base + 0x5000,
        base + 0x5010,
    ];
    image[..COMP_OFFSET + 0x104].copy_from_slice(&body(&entries, true));
    // Pair 0 decodes under base and base - 0x1000; pair 1 is invalid under both.
    for offset in [0x2000, 0x3000] {
        image[offset..offset + 4].copy_from_slice(&1000u32.to_be_bytes());
        image[offset + 4..offset + 4 + compressed.len()].copy_from_slice(&compressed);
    }
    let read = |limit| crate::comp_streams::read(&image, limit, &mut || true).err();
    assert_eq!(read(2000), Some(crate::comp_streams::StreamError::Invalid));
    assert_eq!(read(1500), Some(crate::comp_streams::StreamError::Limit));
}

#[cfg(feature = "image")]
#[test]
fn comp_stream_inflation_stops_after_the_declared_size() {
    use std::io::Write;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&vec![0u8; 8 << 20]).unwrap();
    let compressed = encoder.finish().unwrap();
    let base = 0x40_0000u32;
    let mut image = vec![0u8; 0x2004 + compressed.len()];
    let entries = [base + 0x2000, base + 0x2000 + compressed.len() as u32];
    image[..COMP_OFFSET + 0x104].copy_from_slice(&body(&entries, true));
    // Declares 512 bytes but inflates to 8 MiB.
    image[0x2000..0x2004].copy_from_slice(&512u32.to_be_bytes());
    image[0x2004..].copy_from_slice(&compressed);
    crate::comp_streams::PEAK_INFLATED.with(|peak| peak.set(0));
    assert_eq!(
        crate::comp_streams::read(&image, usize::MAX, &mut || true).err(),
        Some(crate::comp_streams::StreamError::Invalid)
    );
    assert!(crate::comp_streams::PEAK_INFLATED.with(|peak| peak.get()) <= 513);
}
