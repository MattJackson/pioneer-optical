use super::*;

#[test]
fn empty_bodies_are_not_uhd() {
    assert!(!is_uhd(&[]));
}

#[test]
fn family_displays_lowercase_hex() {
    assert_eq!(format!("{}", Family(0xABCD_1234)), "abcd1234");
}

#[test]
fn is_uhd_rejects_bodies_without_the_signature() {
    assert!(!is_uhd(&alloc::vec![0u8; 4096]));
    let mut body = alloc::vec![0u8; 100];
    body.extend_from_slice(&SIG0[..SIG0.len() - 1]);
    assert!(!is_uhd(&body));
}

#[test]
fn is_uhd_finds_the_signature_anywhere() {
    let mut body = alloc::vec![0u8; 100];
    body.extend_from_slice(&SIG0);
    body.extend_from_slice(&[0u8; 50]);
    assert!(is_uhd(&body));
}

// ---- mutation-kill tests -------------------------------------------

use alloc::vec;
use alloc::vec::Vec;

fn zlib(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(data, 6)
}

/// `n` (BE) followed by the zlib stream of `data`.
fn stream_bytes(data: &[u8], n: usize) -> Vec<u8> {
    let mut v = (n as u32).to_be_bytes().to_vec();
    v.extend_from_slice(&zlib(data));
    v
}

fn comp_body(len: usize, dir: &[u32], placed: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let mut b = vec![0u8; len];
    for (o, d) in placed {
        b[*o..*o + d.len()].copy_from_slice(d);
    }
    b[0x1000..0x1004].copy_from_slice(b"COMP");
    let mut off = 0x1004;
    for w in dir {
        b[off..off + 4].copy_from_slice(&w.to_be_bytes());
        off += 4;
    }
    b[off..off + 4].copy_from_slice(&[0xFF; 4]);
    b
}

fn payload(seed: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(7) ^ seed).collect()
}

const BASE: u32 = 0x40_0000;

#[test]
fn comp_streams_two_streams_nonzero_base() {
    let d1 = payload(1, 50);
    let d2 = payload(2, 70);
    let s1 = stream_bytes(&d1, d1.len());
    let s2 = stream_bytes(&d2, d2.len());
    let (o1, o2) = (0x1200usize, 0x1400usize);
    let dir = [
        BASE + o1 as u32,
        BASE + (o1 + s1.len() - 4) as u32,
        BASE + o2 as u32,
        BASE + (o2 + s2.len() - 4) as u32,
    ];
    let body = comp_body(0x2000, &dir, &[(o1, s1), (o2, s2)]);
    assert_eq!(comp_streams(&body), Some(vec![(o1, d1), (o2, d2)]));
}

#[test]
fn comp_streams_base_equal_to_stop_and_tail_window() {
    // Stream at offset 0x200 in a 0x1201-byte body: the base one step below
    // the true one puts the length word 1 byte past the end.
    let d = payload(3, 40);
    let s = stream_bytes(&d, d.len());
    let dir = [BASE + 0x200, BASE + 0x200 + (s.len() - 4) as u32];
    let body = comp_body(0x1201, &dir, &[(0x200, s)]);
    assert_eq!(comp_streams(&body), Some(vec![(0x200, d)]));
}

#[test]
fn comp_streams_stream_at_body_offset_zero() {
    let d = payload(4, 40);
    let s = stream_bytes(&d, d.len());
    let dir = [BASE, BASE + (s.len() - 4) as u32];
    let body = comp_body(0x1100, &dir, &[(0, s)]);
    assert_eq!(comp_streams(&body), Some(vec![(0, d)]));
}

#[test]
fn comp_streams_rejects_stream_below_base() {
    let d = payload(5, 40);
    let s = stream_bytes(&d, d.len());
    let e = BASE + 0x200 + (s.len() - 4) as u32;
    let dir = [BASE + 0x200, e, BASE - 0xE00, e];
    let body = comp_body(0x1400, &dir, &[(0x200, s)]);
    assert_eq!(comp_streams(&body), None);
}

#[test]
fn comp_streams_rejects_end_before_start() {
    let d = payload(6, 40);
    let s = stream_bytes(&d, d.len());
    let dir = [BASE + 0x200, 0];
    let body = comp_body(0x1400, &dir, &[(0x200, s.clone())]);
    assert_eq!(comp_streams(&body), None);
    // e == s
    let dir = [BASE + 0x200, BASE + 0x200];
    let body = comp_body(0x1400, &dir, &[(0x200, s)]);
    assert_eq!(comp_streams(&body), None);
}

#[test]
fn comp_streams_end_address_bounds_the_compressed_data() {
    let d = payload(7, 200);
    let s = stream_bytes(&d, d.len());
    let zl = (s.len() - 4) as u32;
    // exact end works, truncated by two bytes does not.
    let body = comp_body(
        0x1400,
        &[BASE + 0x200, BASE + 0x200 + zl],
        &[(0x200, s.clone())],
    );
    assert!(comp_streams(&body).is_some());
    let body = comp_body(
        0x1400,
        &[BASE + 0x200, BASE + 0x200 + zl - 2],
        &[(0x200, s)],
    );
    assert_eq!(comp_streams(&body), None);
}

#[test]
fn comp_streams_rejects_wrong_expanded_length() {
    let d = payload(8, 60);
    for n in [d.len() + 5, d.len() - 5] {
        let s = stream_bytes(&d, n);
        let dir = [BASE + 0x200, BASE + 0x200 + (s.len() - 4) as u32];
        let body = comp_body(0x1400, &dir, &[(0x200, s)]);
        assert_eq!(comp_streams(&body), None, "n={n}");
    }
}

#[test]
fn comp_streams_none_for_uncompressed() {
    assert_eq!(comp_streams(&[0u8; 0x2000]), None);
}

#[test]
fn is_uhd_exact_length_signature() {
    assert!(is_uhd(&SIG0));
    assert!(!is_uhd(&SIG0[..23]));
}

#[test]
fn family_debug_format() {
    assert_eq!(alloc::format!("{:?}", Family(0xabc)), "Family(abc)");
}

#[test]
fn regions_never_synthesize_patterns_across_boundaries() {
    let a = &SIG0[..10];
    let b = &SIG0[10..];
    assert!(!uhd_regions(&[a, b]));
}

#[test]
fn stored_code_regions_preserve_image_alignment() {
    let body = [0xff, 0xff, 0xf6, 0x12, 0x6a, 0x86, 0xe4, 0x36];
    assert_eq!(aligned_code_region(&body[1..], &body), &body[2..]);
}
