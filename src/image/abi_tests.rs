use super::*;
use alloc::vec;

/// `0A 01` (INC.B R1H): a valid, non-terminating 2-byte filler instruction.
fn fill(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| if i & 1 == 0 { 0x0A } else { 0x01 })
        .collect()
}

/// Kernel with one RTS at 0x100: entries are 0x400000 and 0x400102.
fn kernel() -> Vec<u8> {
    let mut k = fill(KERNEL_LEN);
    k[0x100..0x102].copy_from_slice(&[0x54, 0x70]);
    k
}

fn normal_calling(target: u32, preceded_by_junk: bool) -> Vec<u8> {
    let mut n = fill(0x2_0000);
    let at = 0x3000;
    if preceded_by_junk {
        n[at - 2..at].copy_from_slice(&[0x01, 0x90]); // undefined encoding
    }
    let t = target.to_be_bytes();
    n[at..at + 4].copy_from_slice(&[0x5E, t[1], t[2], t[3]]);
    n
}

#[test]
fn provided_entries_of_a_kernel() {
    let p = provided_abi(&kernel()).unwrap();
    assert_eq!(p.entries(), &[0x40_0000, 0x40_0102]);
}

#[test]
fn required_entries_of_a_normal() {
    let r = required_abi(&normal_calling(0x40_0102, false)).unwrap();
    assert_eq!(r.entries(), &[0x40_0102]);
    assert_eq!(r.id(), Abi::new(vec![0x40_0102]).id());
}

#[test]
fn subset_semantics() {
    let p = provided_abi(&kernel()).unwrap();
    assert!(required_abi(&normal_calling(0x40_0102, false))
        .unwrap()
        .is_satisfied_by(&p));
    let bad = required_abi(&normal_calling(0x40_0104, false)).unwrap();
    assert!(!bad.is_satisfied_by(&p));
    assert_eq!(bad.missing_from(&p), vec![0x40_0104]);
}

#[test]
fn rejected_inputs() {
    assert!(required_abi(&normal_calling(0x40_0104, true)).is_none());
    assert!(required_abi(&normal_calling(0x40_0103, false)).is_none());
    assert!(required_abi(&normal_calling(0x41_0000, false)).is_none());
    assert!(provided_abi(&[0u8; 100]).is_none());
    assert!(required_abi(&kernel()).is_none());
    assert!(required_abi(&[]).is_none());
}

#[test]
fn shared_decoder_requires_complete_instructions_and_resynchronizes_unknown_data() {
    for bytes in [
        &[0x54, 0x70][..],
        &[0x5e, 0x40, 0x01, 0x02][..],
        &[0x7a, 0x00, 0x00, 0x41, 0x00, 0x00][..],
        &[0x01, 0x00, 0x6b, 0x20, 0x00, 0xa0, 0x10, 0x00][..],
    ] {
        assert!(valid(bytes, 0));
        assert_eq!(ilen(bytes, 0), bytes.len());
        for length in 0..bytes.len() {
            assert!(!valid(&bytes[..length], 0));
        }
    }
    for bytes in [&[0x01, 0x90][..], &[0x54, 0x71][..], &[][..]] {
        assert!(!valid(bytes, 0));
        assert_eq!(ilen(bytes, 0), 2);
    }
    assert!(!valid(&[0x54, 0x70], 3));
}

#[test]
fn abi_id_and_display() {
    let a = Abi::new(vec![0x40_0102, 0x40_0000]);
    let want = fnv1a(&[0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x01, 0x02]);
    assert_eq!(a.id(), want);
    assert_ne!(a.id(), 0);
    assert_ne!(a.id(), 1);
    assert_ne!(a.id(), Abi::new(vec![0x40_0000]).id());
    assert_eq!(alloc::format!("{a}"), alloc::format!("{want:016x}"));
    assert_eq!(alloc::format!("{a}").len(), 16);
}

fn call_at(at: usize, bytes: &[u8]) -> Vec<u8> {
    let mut n = fill(0x2_0000);
    n[at..at + bytes.len()].copy_from_slice(bytes);
    n
}

#[test]
fn required_entries_positions() {
    // call far into the body (guards the `i + 4 <= len` loop bound)
    let n = call_at(0x9000, &[0x5E, 0x40, 0x01, 0x00]);
    assert_eq!(required_entries(&n), vec![0x40_0100]);
    // call as the very last instruction
    let n = call_at(0x2_0000 - 4, &[0x5A, 0x40, 0x01, 0x00]);
    assert_eq!(required_entries(&n), vec![0x40_0100]);
    // JMP and JSR, multiple, kernel range bounds
    let mut n = call_at(0x3000, &[0x5A, 0x40, 0x02, 0x00]);
    n[0x3010..0x3014].copy_from_slice(&[0x5E, 0x40, 0xFF, 0xFE]);
    n[0x3020..0x3024].copy_from_slice(&[0x5E, 0x40, 0x00, 0x00]);
    n[0x3030..0x3034].copy_from_slice(&[0x5E, 0x3F, 0xFF, 0xFE]);
    n[0x3040..0x3044].copy_from_slice(&[0x5E, 0x41, 0x00, 0x00]);
    assert_eq!(required_entries(&n), vec![0x40_0200, 0x40_FFFE, 0x40_0000]);
    // non-call instruction whose following bytes look like a kernel address
    let n = call_at(0x3000, &[0x0A, 0x40, 0x08, 0x00]);
    assert!(required_entries(&n).is_empty());
    let n = call_at(0x3000, &[0x5C, 0x40, 0x08, 0x00]);
    assert!(required_entries(&n).is_empty());
}

fn prov(patches: &[(usize, &[u8])]) -> Vec<u32> {
    let mut k = fill(KERNEL_LEN);
    for (o, b) in patches {
        k[*o..*o + b.len()].copy_from_slice(b);
    }
    let mut v: Vec<u32> = provided_abi(&k).unwrap().entries().to_vec();
    for e in &mut v {
        *e -= KERNEL_BASE;
    }
    v
}

#[test]
fn provided_terminators() {
    assert_eq!(prov(&[]), vec![0]);
    for t in [[0x54u8, 0x70], [0x56, 0x70], [0x00, 0x00], [0xFF, 0xFF]] {
        assert_eq!(prov(&[(0x100, &t)]), vec![0, 0x102], "{t:?}");
    }
    for t in [[0x54u8, 0x71], [0x56, 0x00], [0x00, 0x01], [0xFF, 0x00]] {
        assert_eq!(prov(&[(0x100, &t)]), vec![0], "{t:?}");
    }
    for b0 in [0x59u8, 0x5B, 0x40] {
        assert_eq!(prov(&[(0x100, &[b0, 0x00])]), vec![0, 0x102], "{b0:#x}");
    }
    assert_eq!(prov(&[(0x100, &[0x58, 0x00, 0x0A, 0x00])]), vec![0, 0x104]);
    assert_eq!(prov(&[(0x100, &[0x58, 0x01, 0x0A, 0x01])]), vec![0]);
    assert_eq!(prov(&[(0x100, &[0x5A, 0x00, 0x00, 0x00])]), vec![0, 0x104]);
    assert_eq!(prov(&[(0x100, &[0x5E, 0x00, 0x00, 0x00])]), vec![0]);
}

#[test]
fn provided_call_and_branch_targets() {
    // JMP / JSR abs24 into the kernel
    assert_eq!(prov(&[(0x100, &[0x5E, 0x40, 0x08, 0x00])]), vec![0, 0x800]);
    assert_eq!(
        prov(&[(0x100, &[0x5A, 0x40, 0x08, 0x00])]),
        vec![0, 0x104, 0x800]
    );
    // target range edges
    assert_eq!(prov(&[(0x100, &[0x5E, 0x40, 0xFF, 0xFE])]), vec![0, 0xFFFE]);
    assert_eq!(prov(&[(0x100, &[0x5E, 0x41, 0x00, 0x00])]), vec![0]);
    assert_eq!(prov(&[(0x100, &[0x5E, 0x3F, 0xFF, 0xFE])]), vec![0]);
    // BSR 16-bit: target = a + 4 + d
    assert_eq!(prov(&[(0x100, &[0x5C, 0x00, 0x00, 0x10])]), vec![0, 0x114]);
    assert_eq!(prov(&[(0x100, &[0x5C, 0x00, 0xFF, 0xF0])]), vec![0, 0xF4]);
    // BSR as the final instruction: guard must stop the read past the end
    assert_eq!(
        prov(&[(KERNEL_LEN - 4, &[0x5C, 0x00, 0xFF, 0xF0])]),
        vec![0, (KERNEL_LEN - 16) as u32]
    );
    assert_eq!(prov(&[(KERNEL_LEN - 2, &[0x5C, 0x00])]), vec![0]);
    assert_eq!(prov(&[(KERNEL_LEN - 2, &[0x5A, 0x40])]), vec![0]);
    // BRA 8-bit: target = a + 2 + d
    assert_eq!(prov(&[(0x100, &[0x55, 0x10])]), vec![0, 0x112]);
    assert_eq!(prov(&[(0x100, &[0x55, 0xF0])]), vec![0, 0xF2]);
    assert_eq!(prov(&[(0x10, &[0x55, 0x80])]), vec![0]);
    // target at/after the kernel end is dropped, last byte kept
    assert_eq!(prov(&[(0x100, &[0x5E, 0x41, 0x00, 0x00])]), vec![0]);
    assert_eq!(prov(&[(KERNEL_LEN - 2, &[0x55, 0x00])]), vec![0]);
    assert_eq!(
        prov(&[(KERNEL_LEN - 4, &[0x55, 0x01])]),
        vec![0, (KERNEL_LEN - 4 + 3) as u32]
    );
}
