use super::*;

#[test]
fn empty_and_junk_bodies_have_no_family() {
    assert_eq!(family(&[]), None);
    assert_eq!(family(&[0u8; 64]), None);
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

#[test]
fn asic_write_yields_a_stable_family() {
    // MOV.B #0x12,R6 ; MOV.B R6,@0xE436:16
    let body = [0xF6u8, 0x12, 0x6A, 0x86, 0xE4, 0x36, 0x00, 0x00];
    let a = family(&body).unwrap();
    assert_eq!(family(&body), Some(a));
    let other = [0xF6u8, 0x13, 0x6A, 0x86, 0xE4, 0x36, 0x00, 0x00];
    assert_ne!(family(&other), Some(a));
}

// ---- mutation-kill tests -------------------------------------------

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::ToString;
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

fn set16(v: &[u16]) -> BTreeSet<u16> {
    v.iter().copied().collect()
}

#[test]
fn reg_writes_form1_exact() {
    // F6 12 | 36 C5   : MOV.B #12,R6 ; MOV.B R6,@FFC5
    let code = [0xF6u8, 0x12, 0x36, 0xC5];
    let w = reg_writes(&code, &set16(&[0xFFC5]));
    let mut exp = BTreeMap::new();
    exp.insert(0xFFC5u16, BTreeSet::from([0x12u8]));
    assert_eq!(w, exp);
    // r = 0 form
    let code = [0xF0u8, 0x21, 0x30, 0xC5];
    let w = reg_writes(&code, &set16(&[0xFFC5]));
    assert_eq!(w[&0xFFC5], BTreeSet::from([0x21u8]));
    // wrong register not wanted
    assert!(reg_writes(&code, &set16(&[0xFFC6])).is_empty());
}

#[test]
fn reg_writes_form2_exact_and_late_offsets() {
    // 8 filler bytes then F6 12 | 6A 86 E4 36
    let mut code = vec![0u8; 8];
    code.extend_from_slice(&[0xF6, 0x12, 0x6A, 0x86, 0xE4, 0x36]);
    let w = reg_writes(&code, &set16(&[0xE436]));
    assert_eq!(w[&0xE436], BTreeSet::from([0x12u8]));
    assert_eq!(w.len(), 1);
    // form1 late
    let mut code = vec![0u8; 8];
    code.extend_from_slice(&[0xF2, 0x44, 0x32, 0xC5]);
    let w = reg_writes(&code, &set16(&[0xFFC5]));
    assert_eq!(w[&0xFFC5], BTreeSet::from([0x44u8]));
}

#[test]
fn reg_writes_short_inputs_do_not_panic() {
    let want = set16(&[0xFFC5, 0xE436]);
    assert!(reg_writes(&[0xF6], &want).is_empty());
    assert!(reg_writes(&[0xF6, 0x12], &want).is_empty());
    // form1 missing its address byte, form2 missing bytes
    assert!(reg_writes(&[0xF6, 0x12, 0x36], &want).is_empty());
    assert!(reg_writes(&[0xF6, 0x12, 0x6A, 0x86, 0xE4], &want).is_empty());
}

#[test]
fn reg_writes_form2_requires_both_marker_bytes() {
    let want = set16(&[0xE436]);
    // 6A present but second byte not 80|r
    assert!(reg_writes(&[0xF6, 0x12, 0x6A, 0x87, 0xE4, 0x36], &want).is_empty());
    // second byte is 80|r but first is not 6A (nor 30|r)
    assert!(reg_writes(&[0xF6, 0x12, 0x6B, 0x86, 0xE4, 0x36], &want).is_empty());
}

#[test]
fn bit_ops_form1_names_and_bits() {
    let want = set16(&[0xFFC5]);
    for (op, nm) in [(0x70u8, "BSET"), (0x71, "BNOT"), (0x72, "BCLR")] {
        let code = [0x7Fu8, 0xC5, op, 0x50];
        let b = bit_ops(&code, &want);
        let mut exp = BTreeMap::new();
        exp.insert(0xFFC5u16, BTreeSet::from([alloc::format!("{nm}5")]));
        assert_eq!(b, exp);
    }
    // rejected: unknown op, low bits set, bit 7 set, other register
    assert!(bit_ops(&[0x7F, 0xC5, 0x73, 0x50], &want).is_empty());
    assert!(bit_ops(&[0x7F, 0xC5, 0x70, 0x51], &want).is_empty());
    assert!(bit_ops(&[0x7F, 0xC5, 0x70, 0xD0], &want).is_empty());
    assert!(bit_ops(&[0x7F, 0xC6, 0x70, 0x50], &want).is_empty());
    assert!(bit_ops(&[0x7E, 0xC5, 0x70, 0x50], &want).is_empty());
}

#[test]
fn bit_ops_form1_late_and_short() {
    let want = set16(&[0xFFC5]);
    let mut code = vec![0u8; 8];
    code.extend_from_slice(&[0x7F, 0xC5, 0x72, 0x30]);
    let b = bit_ops(&code, &want);
    assert_eq!(b[&0xFFC5], BTreeSet::from(["BCLR3".to_string()]));
    for n in 1..=3 {
        let c = [0x7Fu8, 0xC5, 0x70];
        assert!(bit_ops(&c[..n], &want).is_empty());
    }
}

#[test]
fn bit_ops_form2_names_and_bits() {
    let want = set16(&[0xEDCC]);
    for (op, nm) in [(0x70u8, "BSET"), (0x71, "BNOT"), (0x72, "BCLR")] {
        let code = [0x6Au8, 0x18, 0xED, 0xCC, op, 0x20];
        let b = bit_ops(&code, &want);
        let mut exp = BTreeMap::new();
        exp.insert(0xEDCCu16, BTreeSet::from([alloc::format!("{nm}2")]));
        assert_eq!(b, exp);
    }
    assert!(bit_ops(&[0x6A, 0x18, 0xED, 0xCC, 0x73, 0x20], &want).is_empty());
    assert!(bit_ops(&[0x6A, 0x18, 0xED, 0xCC, 0x70, 0x21], &want).is_empty());
    assert!(bit_ops(&[0x6A, 0x18, 0xED, 0xCC, 0x70, 0xA0], &want).is_empty());
    assert!(bit_ops(&[0x6A, 0x18, 0xED, 0xCD, 0x70, 0x20], &want).is_empty());
    assert!(bit_ops(&[0x6A, 0x18, 0xEC, 0xCC, 0x70, 0x20], &want).is_empty());
    // both marker bytes required
    assert!(bit_ops(&[0x6A, 0x19, 0xED, 0xCC, 0x70, 0x20], &want).is_empty());
    assert!(bit_ops(&[0x6B, 0x18, 0xED, 0xCC, 0x70, 0x20], &want).is_empty());
}

#[test]
fn bit_ops_form2_late_and_short() {
    let want = set16(&[0xEDCC]);
    let mut code = vec![0u8; 8];
    code.extend_from_slice(&[0x6A, 0x18, 0xED, 0xCC, 0x71, 0x70]);
    let b = bit_ops(&code, &want);
    assert_eq!(b[&0xEDCC], BTreeSet::from(["BNOT7".to_string()]));
    let c = [0x6Au8, 0x18, 0xED, 0xCC, 0x70];
    for n in 1..=5 {
        assert!(bit_ops(&c[..n], &want).is_empty());
    }
}

fn servo_row(fill: u8) -> Vec<u8> {
    let mut r = SERVO_ROW.to_vec();
    r.resize(SERVO_ROW_LEN, fill);
    r
}

fn servo_hash(rows: &[&[u8]]) -> String {
    let c: Vec<u8> = rows.iter().flat_map(|r| r.iter().copied()).collect();
    alloc::format!("{:016x}", fnv1a(&c))
}

#[test]
fn servo_none_cases() {
    assert_eq!(servo(&[]), "none");
    assert_eq!(servo(&[0u8; 100]), "none");
    assert_eq!(servo(&SERVO_ROW[..9]), "none");
}

#[test]
fn servo_hashes_distinct_rows_at_odd_offsets() {
    let (a, b) = (servo_row(0x11), servo_row(0x22));
    let mut code = vec![0u8; 3];
    code.extend_from_slice(&a);
    code.extend_from_slice(&a); // duplicate ignored
    code.extend_from_slice(&[9u8; 7]);
    code.extend_from_slice(&b);
    assert_eq!(servo(&code), servo_hash(&[&a, &b]));
    assert_ne!(servo(&code), servo_hash(&[&a, &a, &b]));
}

#[test]
fn servo_late_row_and_short_tail_row() {
    // Anchor far from start, then a final row cut short by the end.
    let a = servo_row(0x33);
    let mut code = vec![0u8; 50];
    code.extend_from_slice(&a);
    code.extend_from_slice(&SERVO_ROW); // exactly 10 bytes at the end
    let tail = SERVO_ROW.to_vec();
    assert_eq!(servo(&code), servo_hash(&[&a, &tail]));
    // a row truncated to 25 bytes by the end of the code
    let mut code = vec![0u8; 5];
    code.extend_from_slice(&SERVO_ROW);
    code.extend_from_slice(&[0x44u8; 15]);
    assert_eq!(servo(&code), servo_hash(&[&code[5..]]));
}

#[test]
fn servo_uses_only_first_seven_rows() {
    let rows: Vec<Vec<u8>> = (0..9).map(|i| servo_row(0x50 + i)).collect();
    let code: Vec<u8> = rows.iter().flatten().copied().collect();
    let refs: Vec<&[u8]> = rows.iter().take(7).map(|r| r.as_slice()).collect();
    assert_eq!(servo(&code), servo_hash(&refs));
}

#[test]
fn fmt_ints_formats() {
    assert_eq!(fmt_ints(None), "-");
    assert_eq!(fmt_ints(Some(&BTreeSet::new())), "-");
    assert_eq!(fmt_ints(Some(&BTreeSet::from([0x1fu8, 0x0a]))), "a.1f");
}

#[test]
fn fmt_board_formats() {
    assert_eq!(fmt_board(None, None), "-");
    let i = BTreeSet::from([0x20u8, 0x5]);
    let s = BTreeSet::from(["BSET5".to_string(), "BCLR1".to_string()]);
    assert_eq!(fmt_board(Some(&i), Some(&s)), "5.20.BCLR1.BSET5");
    assert_eq!(fmt_board(Some(&i), None), "5.20");
    assert_eq!(fmt_board(None, Some(&s)), "BCLR1.BSET5");
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
