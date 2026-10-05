//! Analysis of decoded firmware bodies: hardware family, UHD capability and
//! Kernel ABI.
//!
//! Every function takes a decoded body (the plaintext image inside a firmware
//! envelope).
//!
//! Requires the `image` feature.

mod abi;
pub use abi::{provided_abi, required_abi, Abi};

use alloc::borrow::ToOwned;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Load address of the Kernel component.
pub const KERNEL_BASE: u32 = 0x40_0000;
/// Size of a Kernel body, in bytes.
pub const KERNEL_LEN: usize = 0x1_0000;

/// Front-end servo/RF ASIC register block (low 16 bits of `0xFFExxx`).
const ASIC_REGS: [u16; 7] = [0xE436, 0xE43A, 0xE43B, 0xE45B, 0xE463, 0xE46A, 0xE46B];
/// Board pin-function / port configuration registers.
const PIN_REGS: [u16; 4] = [0xFE8F, 0xFE94, 0xFE9D, 0xFEC0];
/// PCB-revision marker registers.
const BOARD_REGS: [u16; 3] = [0xFFC5, 0xEDCC, 0xEDCD];

/// Servo loop-filter coefficient-row anchor (`7f 97 7f 51 7f 51 7f 51 7f 51`).
const SERVO_ROW: [u8; 10] = [0x7f, 0x97, 0x7f, 0x51, 0x7f, 0x51, 0x7f, 0x51, 0x7f, 0x51];
/// Number of distinct servo rows that form the version-stable base.
const SERVO_BASE: usize = 7;
/// Full servo coefficient row width.
const SERVO_ROW_LEN: usize = 40;

/// Code fragment present in every UHD-capable body and no other.
const SIG0: [u8; 24] = [
    0x5E, 0x40, 0x83, 0xB8, 0x7A, 0x00, 0x41, 0x00, 0x03, 0x89, 0x01, 0x00, 0x6F, 0xE0, 0x00, 0xC4,
    0x01, 0x00, 0x69, 0xE3, 0x5E, 0x40, 0x87, 0xD0,
];

/// A hardware family. Bodies with equal families target the same hardware and
/// can be cross-flashed.
///
/// The value is an opaque hash; only equality and the hex [`Display`] form are
/// meaningful.
///
/// [`Display`]: core::fmt::Display
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Family(u64);

impl core::fmt::Display for Family {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl core::fmt::Debug for Family {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Family({:x})", self.0)
    }
}

/// FNV-1a 64-bit hash of a byte slice.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A decompressed COMP stream: `(offset_in_body, decompressed_bytes)`.
type Stream = (usize, Vec<u8>);

/// Decompress the streams of a COMP container. `None` for an uncompressed body
/// or an unparseable container.
fn comp_streams(img: &[u8]) -> Option<Vec<Stream>> {
    let pairs = crate::comp::comp_pairs(img)?;
    let npairs = pairs.len();
    let first = pairs[0].0 as u64;
    let len = img.len() as u64;
    // The load base is unknown: try each 4 KiB-aligned base that fits.
    let start = (first.saturating_sub(len)) & !0xFFF;
    let stop = first & !0xFFF; // inclusive
    let mut base = start;
    while base <= stop {
        let mut out: Vec<Stream> = Vec::with_capacity(npairs);
        let mut ok = true;
        for &(s, e) in &pairs {
            let (s, e) = (s as u64, e as u64);
            if s < base || e <= s {
                ok = false;
                break;
            }
            let o = (s - base) as usize;
            if o + 4 > img.len() {
                ok = false;
                break;
            }
            let n = crate::comp::be_u32(img, o)? as usize;
            if n > crate::comp::MAX_EXPANDED {
                ok = false;
                break;
            }
            // Compressed data runs to the stream end, clamped to the body.
            let end = core::cmp::min((e - base + 4) as usize, img.len());
            let cstart = o + 4;
            if cstart > end {
                ok = false;
                break;
            }
            let c = &img[cstart..end];
            if c.first() != Some(&0x78) {
                ok = false;
                break;
            }
            match miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(c, n) {
                Ok(x) if x.len() == n => out.push((o, x)),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && out.len() == npairs {
            return Some(out);
        }
        base += 0x1000;
    }
    None
}

/// `{reg16 -> set(imm)}` for `MOV.B #imm,Rn` immediately followed by
/// `MOV.B Rn,@aa:8` (`30|n`) or `MOV.B Rn,@aa:16` (`6a 80|n`). Even offsets only.
fn reg_writes(code: &[u8], want: &BTreeSet<u16>) -> BTreeMap<u16, BTreeSet<u8>> {
    let mut out: BTreeMap<u16, BTreeSet<u8>> = BTreeMap::new();
    let mut i = 0;
    while i + 2 < code.len() {
        let b0 = code[i];
        if !(0xF0..=0xFF).contains(&b0) {
            i += 2;
            continue;
        }
        let r = b0 & 0x0F;
        let imm = code[i + 1];
        let b2 = code[i + 2];
        let a: Option<u16> = if b2 == (0x30 | r) {
            code.get(i + 3).map(|&lo| 0xFF00u16 | lo as u16)
        } else if b2 == 0x6A && code.get(i + 3) == Some(&(0x80 | r)) {
            match (code.get(i + 4), code.get(i + 5)) {
                (Some(&hi), Some(&lo)) => Some(((hi as u16) << 8) | lo as u16),
                _ => None,
            }
        } else {
            None
        };
        if let Some(a) = a {
            if want.contains(&a) {
                out.entry(a).or_default().insert(imm);
            }
        }
        i += 2;
    }
    out
}

/// `{reg16 -> set("BSET5"...)}` for BSET/BNOT/BCLR `#n,@aa:8` / `@aa:16`.
/// Even offsets only.
fn bit_ops(code: &[u8], want: &BTreeSet<u16>) -> BTreeMap<u16, BTreeSet<String>> {
    fn name(op: u8) -> Option<&'static str> {
        match op {
            0x70 => Some("BSET"),
            0x71 => Some("BNOT"),
            0x72 => Some("BCLR"),
            _ => None,
        }
    }
    let mut out: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
    // form1: 7f <aa> <7X> <nn>
    let mut i = 0;
    while i + 3 < code.len() {
        if code[i] == 0x7F {
            let op = code[i + 2];
            let nn = code[i + 3];
            if let Some(nm) = name(op) {
                if nn & 0x8F == 0 {
                    let a = 0xFF00u16 | code[i + 1] as u16;
                    if want.contains(&a) {
                        out.entry(a)
                            .or_default()
                            .insert(format!("{}{}", nm, nn >> 4));
                    }
                }
            }
        }
        i += 2;
    }
    // form2: 6a 18 <aah><aal> <7X> <nn>
    let mut i = 0;
    while i + 5 < code.len() {
        if code[i] == 0x6A && code[i + 1] == 0x18 {
            let op = code[i + 4];
            let nn = code[i + 5];
            if let Some(nm) = name(op) {
                if nn & 0x8F == 0 {
                    let a = ((code[i + 2] as u16) << 8) | code[i + 3] as u16;
                    if want.contains(&a) {
                        out.entry(a)
                            .or_default()
                            .insert(format!("{}{}", nm, nn >> 4));
                    }
                }
            }
        }
        i += 2;
    }
    out
}

/// Servo coefficient fingerprint: hash of the first [`SERVO_BASE`] distinct
/// 40-byte rows (in table order), or `"none"`.
fn servo(code: &[u8]) -> String {
    let mut rows: Vec<&[u8]> = Vec::new();
    if code.len() >= SERVO_ROW.len() {
        let mut i = 0;
        while i + SERVO_ROW.len() <= code.len() {
            if code[i..i + SERVO_ROW.len()] == SERVO_ROW {
                let end = core::cmp::min(i + SERVO_ROW_LEN, code.len());
                let row = &code[i..end];
                if !rows.contains(&row) {
                    rows.push(row);
                    // Only the first SERVO_BASE distinct rows are used.
                    if rows.len() == SERVO_BASE {
                        break;
                    }
                }
            }
            i += 1;
        }
    }
    if rows.is_empty() {
        return "none".to_owned();
    }
    let mut concat: Vec<u8> = Vec::new();
    for r in rows.iter().take(SERVO_BASE) {
        concat.extend_from_slice(r);
    }
    format!("{:016x}", fnv1a(&concat))
}

/// Format a register's value set: sorted lowercase hex joined by `.`; `-` if
/// empty.
fn fmt_ints(s: Option<&BTreeSet<u8>>) -> String {
    match s {
        Some(set) if !set.is_empty() => {
            let parts: Vec<String> = set.iter().map(|v| format!("{:x}", v)).collect();
            parts.join(".")
        }
        _ => "-".to_owned(),
    }
}

/// Format a board register: value writes (hex) then bit-op labels, joined by
/// `.`; `-` if both are empty.
fn fmt_board(ints: Option<&BTreeSet<u8>>, strs: Option<&BTreeSet<String>>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(set) = ints {
        for v in set {
            parts.push(format!("{:x}", v));
        }
    }
    if let Some(set) = strs {
        for v in set {
            parts.push(v.clone());
        }
    }
    if parts.is_empty() {
        "-".to_owned()
    } else {
        parts.join(".")
    }
}

/// The hardware family of a body, or `None` when the body carries no front-end
/// configuration (a Kernel, an undecodable body, or unrelated data).
pub fn family(body: &[u8]) -> Option<Family> {
    let wanted: BTreeSet<u16> = ASIC_REGS
        .iter()
        .chain(PIN_REGS.iter())
        .chain(BOARD_REGS.iter())
        .copied()
        .collect();
    let board_wanted: BTreeSet<u16> = BOARD_REGS.iter().copied().collect();

    // Code = the uncompressed head plus stream 5; servo rows live in the head.
    let (code, main): (Vec<u8>, &[u8]) = match comp_streams(body) {
        Some(st) => {
            let first = st.iter().map(|(o, _)| *o).min().unwrap_or(0);
            let main = &body[..first.min(body.len())];
            let mut code = main.to_vec();
            if let Some((_, s5)) = st.get(5) {
                code.extend_from_slice(s5);
            }
            (code, main)
        }
        None => (body.to_vec(), body),
    };

    let w = reg_writes(&code, &wanted);
    if !ASIC_REGS
        .iter()
        .any(|a| w.get(a).is_some_and(|s| !s.is_empty()))
    {
        return None;
    }
    let b = bit_ops(&code, &board_wanted);
    let regs = |set: &[u16], f: &dyn Fn(&u16) -> String| {
        set.iter()
            .map(|a| format!("{:04x}={}", a, f(a)))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let asic = regs(&ASIC_REGS, &|a| fmt_ints(w.get(a)));
    let pins = regs(&PIN_REGS, &|a| fmt_ints(w.get(a)));
    let board = regs(&BOARD_REGS, &|a| fmt_board(w.get(a), b.get(a)));

    // Boards with FFC5 driven high carry no distinguishing servo table.
    let key = if board.contains("ffc5=20") {
        format!("asic={asic}\u{1f}board={board}\u{1f}pins={pins}")
    } else {
        format!(
            "asic={asic}\u{1f}board={board}\u{1f}pins={pins}\u{1f}servo={}",
            servo(main)
        )
    };
    Some(Family(fnv1a(key.as_bytes())))
}

/// Whether the body is UHD-capable.
pub fn is_uhd(body: &[u8]) -> bool {
    if body.len() < SIG0.len() {
        return false;
    }
    body.windows(SIG0.len()).any(|w| w == SIG0)
}

#[cfg(test)]
mod tests {
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
}
