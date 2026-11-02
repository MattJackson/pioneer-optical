use super::*;

#[test]
fn shared_fe94_constant_is_observed_without_rekeying_identity() {
    let mut code = vec![0xf8, 0x0d, 0x6a, 0x88, 0xe4, 0x36];
    let legacy = family_fingerprint(&code).unwrap();
    code.extend_from_slice(&[
        0xf9, 0x40, 0x6a, 0x89, 0xfe, 0x9d, 0xf8, 0x01, 0x6a, 0x88, 0xfe, 0x9f, 0x6a, 0x89, 0xfe,
        0x94,
    ]);
    let actual = family_fingerprint(&code).unwrap();
    assert_eq!(actual.raw_pins, "fe94=40 fec0=-");
    assert_eq!(actual.family, legacy.family);
    assert_eq!(actual.pins, legacy.pins);
}

fn observed_values(evidence: &FamilyEvidence, address: u16) -> BTreeSet<u8> {
    evidence
        .registers()
        .iter()
        .find(|r| r.address == address)
        .unwrap()
        .values()
}

#[test]
fn collimator_shared_zero_has_both_observations_without_identity_constraints() {
    let code = [
        0xf8, 0x0d, 0x6a, 0x88, 0xe4, 0x36, 0x18, 0x99, 0x6a, 0x89, 0xed, 0xcc, 0x6a, 0x89, 0xed,
        0xcd,
    ];
    let evidence = family_evidence(&code).unwrap();
    assert_eq!(observed_values(&evidence, 0xedcc), BTreeSet::from([0]));
    assert_eq!(observed_values(&evidence, 0xedcd), BTreeSet::from([0]));
    assert_eq!(evidence.fingerprint().board, "ffc5=-");
    let observation = &evidence
        .registers()
        .iter()
        .find(|r| r.address == 0xedcd)
        .unwrap()
        .observations[0];
    assert_eq!((observation.region, observation.offset), (0, 12));
    assert_eq!(
        observation.operation,
        RegisterOperation::Write {
            value: 0,
            loaded_at: 6
        }
    );
}

#[test]
fn movement_commands_remain_comparable_without_defining_hardware_identity() {
    let make = |high, low| {
        family_evidence(&[
            0xf8, 0x0d, 0x6a, 0x88, 0xe4, 0x36, 0xf8, high, 0x6a, 0x88, 0xed, 0xcc, 0xf8, low,
            0x6a, 0x88, 0xed, 0xcd,
        ])
        .unwrap()
    };
    let (a, b) = (make(0, 1), make(0xff, 2));
    assert_eq!(a.fingerprint().family, b.fingerprint().family);
    assert!(a.compare(&b).matches);
    assert!(FAMILY_CRITERIA
        .iter()
        .all(|c| !matches!(c, FamilyCriterion::Edcc | FamilyCriterion::Edcd)));
    let commands = a.compare_with(&b, &[FamilyCriterion::Edcc, FamilyCriterion::Edcd]);
    assert!(!commands.matches);
    assert!(commands
        .criteria
        .iter()
        .all(|c| c.evidence_known && !c.matches));
    assert_eq!(
        (
            commands.criteria[0].left.as_str(),
            commands.criteria[0].right.as_str()
        ),
        ("0", "ff")
    );
    assert_eq!(
        (
            commands.criteria[1].left.as_str(),
            commands.criteria[1].right.as_str()
        ),
        ("1", "2")
    );
    // Command observations alone do not establish an otherwise missing family.
    assert!(family_evidence(&[0xf8, 1, 0x6a, 0x88, 0xed, 0xcd]).is_none());
}

#[test]
fn removing_movement_commands_preserves_other_hardware_distinctions() {
    let seed = [0xf8, 0x0d, 0x6a, 0x88, 0xe4, 0x36];
    for (criterion, address) in [
        (FamilyCriterion::E436, 0xe436u16),
        (FamilyCriterion::Ffc5, 0xffc5),
        (FamilyCriterion::Fe94, 0xfe94),
        (FamilyCriterion::Fec0, 0xfec0),
    ] {
        let make = |value| {
            let mut code = seed.to_vec();
            code.extend_from_slice(&[0xf8, value, 0x6a, 0x88]);
            code.extend_from_slice(&address.to_be_bytes());
            family_evidence(&code).unwrap()
        };
        let (a, b) = (make(1), make(2));
        assert_ne!(
            a.fingerprint().family,
            b.fingerprint().family,
            "{criterion:?}"
        );
        assert!(!a.compare_with(&b, &[criterion]).matches);
    }
    let mut a = seed.to_vec();
    a.extend_from_slice(&servo_row(0x11));
    let mut b = seed.to_vec();
    b.extend_from_slice(&servo_row(0x12));
    let (a, b) = (family_evidence(&a).unwrap(), family_evidence(&b).unwrap());
    assert_ne!(a.fingerprint().family, b.fingerprint().family);
    assert!(!a.compare_with(&b, &[FamilyCriterion::Servo]).matches);
}

#[test]
fn observed_constants_do_not_cross_control_flow_or_operand_boundaries() {
    let seed = [0xf8, 0x0d, 0x6a, 0x88, 0xe4, 0x36];
    for interruption in [
        &[0x40, 0x00][..],             // branch
        &[0x5e, 0x40, 0x12, 0x00][..], // call
        &[0x5e, 0xf9, 0x40, 0x00][..], // call operand resembles MOV.B #40,R1L
        &[0x79, 0x01, 0xf9, 0x40][..], // word write clobbers the byte register
        &[0x6a, 0x09, 0xfe, 0xfc][..], // unknown hardware read
    ] {
        let mut code = seed.to_vec();
        code.extend_from_slice(&[0xf9, 0x40]);
        code.extend_from_slice(interruption);
        code.extend_from_slice(&[0x6a, 0x89, 0xfe, 0x94]);
        assert!(
            observed_values(&family_evidence(&code).unwrap(), 0xfe94).is_empty(),
            "{interruption:02x?}"
        );
    }
}

#[test]
fn corrected_observations_do_not_join_separate_regions() {
    let seed = [0xf8, 0x0d, 0x6a, 0x88, 0xe4, 0x36, 0xf9, 0x40];
    let store = [0x6a, 0x89, 0xfe, 0x94];
    let evidence = evidence_regions(&[&seed, &store], &[]).unwrap();
    assert!(observed_values(&evidence, 0xfe94).is_empty());
}

#[test]
fn each_family_criterion_can_be_compared_without_changing_ids() {
    let make = |value| {
        family_evidence(&[
            0xf8, 0x0d, 0x6a, 0x88, 0xe4, 0x36, 0xf8, value, 0x6a, 0x88, 0xfe, 0x94,
        ])
        .unwrap()
    };
    let (a, b) = (make(0x40), make(0xc0));
    let ids = (a.fingerprint().family, b.fingerprint().family);
    let comparison = a.compare(&b);
    assert!(!comparison.matches);
    assert_eq!(comparison.criteria.iter().filter(|c| !c.matches).count(), 1);
    let different = comparison.criteria.iter().find(|c| !c.matches).unwrap();
    assert_eq!(different.criterion, FamilyCriterion::Fe94);
    assert!(different.evidence_known);
    let selected: Vec<_> = FAMILY_CRITERIA
        .iter()
        .copied()
        .filter(|c| *c != FamilyCriterion::Fe94)
        .collect();
    assert!(a.compare_with(&b, &selected).matches);
    assert_eq!((a.fingerprint().family, b.fingerprint().family), ids);
    let missing_servo = comparison
        .criteria
        .iter()
        .find(|c| c.criterion == FamilyCriterion::Servo)
        .unwrap();
    assert!(missing_servo.matches);
    assert!(!missing_servo.evidence_known);
}

#[test]
fn criterion_comparison_retains_only_the_existing_fec0_mask() {
    let make = |value| {
        family_evidence(&[
            0xf8, 0x0d, 0x6a, 0x88, 0xe4, 0x36, 0xf8, value, 0x6a, 0x88, 0xfe, 0xc0,
        ])
        .unwrap()
    };
    let (a, b, c) = (make(0x87), make(0xc7), make(0xc6));
    assert!(a.compare(&b).matches);
    assert_eq!(a.fingerprint().family, b.fingerprint().family);
    assert!(!a.compare(&c).matches);
    assert_eq!(observed_values(&b, 0xfec0), BTreeSet::from([0xc7]));
    assert_eq!(FamilyCriterion::Fec0.value_mask(), 0xbf);
    assert!(FAMILY_CRITERIA
        .iter()
        .filter(|c| **c != FamilyCriterion::Fec0)
        .all(|c| c.value_mask() == 0xff));
}

#[test]
fn empty_and_junk_bodies_have_no_family() {
    assert_eq!(family(&[]), None);
    assert_eq!(family(&[0u8; 64]), None);
    assert!(!is_uhd(&[]));
}

#[test]
fn family_displays_lowercase_hex() {
    assert_eq!(format!("{}", Family(0xABCD_1234)), "00000000abcd1234");
    assert_eq!(format!("{}", Family(0)), "0000000000000000");
    assert_eq!(format!("{}", Family(u64::MAX)), "ffffffffffffffff");
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
    assert_eq!(servo(&code), servo_hash(&[&a]));
    // a row truncated to 25 bytes by the end of the code
    let mut code = vec![0u8; 5];
    code.extend_from_slice(&SERVO_ROW);
    code.extend_from_slice(&[0x44u8; 15]);
    assert_eq!(servo(&code), "none");
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

#[test]
fn ffc5_high_boards_still_compare_servo_tables() {
    // Identical hardware-register setup; only servo evidence differs.
    let mut body = vec![
        0xF6, 0x12, 0x6A, 0x86, 0xE4, 0x36, 0xF6, 0x20, 0x6A, 0x86, 0xFF, 0xC5,
    ];
    let missing = family_fingerprint(&body).unwrap();
    assert_eq!(missing.board, "ffc5=20");
    assert_eq!(missing.servo, "none");
    let first = servo_row(0x11);
    body.extend_from_slice(&first);
    let found = family_fingerprint(&body).unwrap();
    assert_ne!(found.family, missing.family);
    assert_eq!(found.servo, servo_hash(&[&first]));
    assert_eq!(Some(found.family), family(&body));
    let mut changed = body.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert_ne!(family(&changed), family(&body));
    assert_eq!(family_fingerprint(&[]), None);
}

#[test]
fn ffc5_high_servo_base_is_stable_across_duplicates_and_later_rows() {
    let mut body = vec![
        0xF6, 0x12, 0x6A, 0x86, 0xE4, 0x36, 0xF6, 0x20, 0x6A, 0x86, 0xFF, 0xC5,
    ];
    for i in 0..7 {
        body.extend_from_slice(&servo_row(i));
    }
    let before = family(&body);
    body.extend_from_slice(&servo_row(0));
    body.extend_from_slice(&servo_row(8));
    assert_eq!(family(&body), before);
}

#[test]
fn decoded_regions_make_compression_and_base_row_order_irrelevant() {
    let mut data = vec![0xf6, 0x12, 0x6a, 0x86, 0xe4, 0x36];
    data.extend_from_slice(&SIG0);
    let rows: Vec<_> = (0..7).map(|i| servo_row(0x20 + i)).collect();
    let mut plain = data.clone();
    for row in &rows {
        plain.extend_from_slice(row);
    }
    let stream0 = stream_bytes(&data, data.len());
    let backwards: Vec<u8> = rows.iter().rev().flatten().copied().collect();
    let stream1 = stream_bytes(&backwards, backwards.len());
    let o0 = 0x1200;
    let o1 = 0x1800;
    let directory = [
        BASE + o0,
        BASE + o0 + stream0.len() as u32 - 4,
        BASE + o1,
        BASE + o1 + stream1.len() as u32 - 4,
    ];
    let packed = comp_body(
        0x2200,
        &directory,
        &[(o0 as usize, stream0), (o1 as usize, stream1)],
    );
    assert_eq!(family_fingerprint(&plain), family_fingerprint(&packed));
    assert!(is_uhd(&packed));
    let mut reversed = packed.clone();
    reversed[0x1004..0x100c].copy_from_slice(&packed[0x100c..0x1014]);
    reversed[0x100c..0x1014].copy_from_slice(&packed[0x1004..0x100c]);
    assert_eq!(family_fingerprint(&plain), family_fingerprint(&reversed));
    let mut corrupt = packed;
    corrupt[0x1204] = 0;
    // Invalid compression must not become apparent hardware evidence from the head.
    corrupt[..data.len()].copy_from_slice(&data);
    assert!(family_fingerprint(&corrupt).is_none());
    assert!(!is_uhd(&corrupt));
}

#[test]
fn regions_never_synthesize_patterns_across_boundaries() {
    let a = &SIG0[..10];
    let b = &SIG0[10..];
    assert!(!uhd_regions(&[a, b]));
    assert!(fingerprint_regions(&[&[0xf6, 0x12], &[0x6a, 0x86, 0xe4, 0x36]], &[]).is_none());
}

#[test]
fn stored_code_regions_preserve_image_alignment() {
    let body = [0xff, 0xff, 0xf6, 0x12, 0x6a, 0x86, 0xe4, 0x36];
    assert_eq!(aligned_code_region(&body[1..], &body), &body[2..]);
    assert_eq!(
        fingerprint_regions(&[&body[1..]], &body),
        family_fingerprint(&body)
    );
}

#[test]
fn excluded_interface_registers_do_not_change_hardware_family() {
    let setup = [0xf8, 0x0d, 0x6a, 0x88, 0xe4, 0x36];
    let expected = family(&setup);
    assert!(expected.is_some());
    for register in [0xfe8fu16, 0xfe9d, 0xfe9f] {
        for value in [0, 0x18, 0x70, 0x93, 0xa0, 0xff] {
            let mut body = setup.to_vec();
            body.extend([
                0xf8,
                value,
                0x6a,
                0x88,
                (register >> 8) as u8,
                register as u8,
            ]);
            assert_eq!(family(&body), expected);
        }
    }
}

#[test]
fn fec0_bit6_is_not_family_identity_but_raw_values_survive() {
    let body = |value| {
        vec![
            0xf8, 0x0d, 0x6a, 0x88, 0xe4, 0x36, 0xf8, value, 0x6a, 0x88, 0xfe, 0xc0,
        ]
    };
    for value in 0u8..=255 {
        let a = family_fingerprint(&body(value)).unwrap();
        let b = family_fingerprint(&body(value ^ 0x40)).unwrap();
        assert_eq!(a.family, b.family);
        assert_eq!(a.pins, b.pins);
        assert_ne!(a.raw_pins, b.raw_pins);
        for bit in [0, 1, 2, 3, 4, 5, 7] {
            assert_ne!(a.family, family(&body(value ^ (1 << bit))).unwrap());
        }
    }
    let a = family_fingerprint(&body(0xc7)).unwrap();
    assert_eq!(a.pins, "fe94=- fec0=87");
    assert_eq!(a.raw_pins, "fe94=- fec0=c7");
    let mut both = body(0xc7);
    both.extend_from_slice(&body(0x87)[6..]);
    assert_eq!(family(&both), Some(a.family));
    assert_eq!(
        family_fingerprint(&both).unwrap().raw_pins,
        "fe94=- fec0=87.c7"
    );
    let mut fe94 = body(0xc7);
    fe94.extend_from_slice(&[0xf8, 0x40, 0x6a, 0x88, 0xfe, 0x94]);
    assert_ne!(family(&fe94), Some(a.family));
}
