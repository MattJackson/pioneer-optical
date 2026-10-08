//! Analysis of decoded firmware bodies: hardware family, UHD capability and
//! Kernel ABI.
//!
//! Every function takes a decoded body (the plaintext image inside a firmware
//! envelope).
//!
//! Requires the `image` feature.

mod abi;
mod control;
mod receiver;
pub use abi::{provided_abi, required_abi, Abi};
pub use control::receiver_control_key;
pub use receiver::{kernel_marker_policy, KernelMarkerPolicy};

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

/// A hardware-family fingerprint derived from the image's hardware setup.
/// Matching families identify hardware intended to accept complete firmware
/// packages in either direction. The receiver implementation must handle any
/// protocol or generation differences. Invalid packages and unimplemented
/// transfer paths must be reported separately from hardware incompatibility.
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
#[path = "image_tests.rs"]
mod tests;
