//! Firmware-body analysis: deterministic crossflash-compatibility family ids and
//! the UHD capability test, computed purely from an envelope-**decoded** Pioneer
//! firmware body (the `COMP` container, i.e.
//! `pioneer_codec::decode_envelope(enc).image`).
//!
//! This is a faithful Rust port of the reverse-engineered `hw_id.py` reference
//! algorithm, validated to reproduce its partition over the full firmware corpus
//! (441 images, 18 families). Two bodies share a [`FamilyId`] exactly when they
//! target the same silicon / optical platform and are therefore crossflash
//! compatible.
//!
//! The family is derived from the version-stable hardware configuration the
//! firmware must encode to drive the hardware:
//! - **asic** — servo/RF front-end register block `0xFFE436..0xFFE46B` boot writes,
//! - **pins** — board pin-function/port config (`0xFFFE8F/94/9D/C0`),
//! - **board** — PCB revision marker (`0xFFFFC5.5`, `0xFFEDCC/CD`),
//! - **servo** — servo loop-filter coefficient table (half-height mechanism).
//!
//! The laser (write-strategy) table is *reported* (see [`Profile`]) but not keyed:
//! early-BD releases retune it between versions, so it fails version-stability.
//!
//! The [`abi_required`] / [`abi_provided`] / [`abi_compatible`] / [`get_abi_match`] family
//! (module `abi`) answers a separate question: can a Normal body be paired with a Kernel
//! body, i.e. does the Normal call only Kernel entry points the Kernel provides.
//!
//! This module is gated behind the non-default `fw` cargo feature, which pulls in
//! `alloc` and a zlib inflater ([`miniz_oxide`]); the default build of the crate
//! stays `no_std`, no-alloc and dependency-free.

mod abi;
pub use abi::{
    abi_compatible, abi_provided, abi_required, get_abi_match, AbiProvided, AbiRequired,
    KERNEL_BASE, KERNEL_END,
};

use alloc::borrow::ToOwned;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

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

/// UHD capability signature `SIG0` (24 bytes) — a relocation-stable fragment of
/// the shared UHD capability library present in every UHD body and no standard
/// body. See `UHD-INVENTORY.md`.
const SIG0: [u8; 24] = [
    0x5E, 0x40, 0x83, 0xB8, 0x7A, 0x00, 0x41, 0x00, 0x03, 0x89, 0x01, 0x00, 0x6F, 0xE0, 0x00, 0xC4,
    0x01, 0x00, 0x69, 0xE3, 0x5E, 0x40, 0x87, 0xD0,
];

/// A deterministic crossflash-compatibility family id.
///
/// Equal ids mean the two firmware bodies target the same silicon / optical
/// platform and are crossflash compatible. The numeric value is an opaque hash
/// of the keyed hardware profile; only equality (and its [`Display`] hex form)
/// is meaningful.
///
/// [`Display`]: core::fmt::Display
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct FamilyId(u64);

impl core::fmt::Display for FamilyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl core::fmt::Debug for FamilyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FamilyId({:x})", self.0)
    }
}

/// The full reported hardware profile of a firmware body (for a future `fw info`).
///
/// The [`asic`](Self::asic), [`pins`](Self::pins), [`board`](Self::board) and
/// [`servo`](Self::servo) fields are the keyed components behind [`FamilyId`];
/// [`laser`](Self::laser) and [`flash`](Self::flash) are reported only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Pickup laser-power envelope from the BD write-strategy table (reported,
    /// not keyed). `"none"` when the table is absent.
    pub laser: String,
    /// Front-end ASIC register boot writes, e.g. `e436=d e43a=34 ...`.
    pub asic: String,
    /// Board pin-function / port configuration, e.g. `fe8f=70 ...`.
    pub pins: String,
    /// PCB-revision marker, e.g. `ffc5=BCLR5 edcc=- edcd=-`.
    pub board: String,
    /// Servo coefficient-table fingerprint, or `"none"`.
    pub servo: String,
    /// Flash window description implied by the COMP directory.
    pub flash: String,
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

/// Big-endian u32 read; `None` if the slice does not hold 4 bytes at `off`.
fn be_u32(img: &[u8], off: usize) -> Option<u32> {
    img.get(off..off + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// A decompressed COMP stream: `(offset_in_body, decompressed_bytes)`.
type Stream = (usize, Vec<u8>);

/// Parse the COMP container: returns `(base, streams)`. `None` for a pre-COMP
/// (uncompressed) body or an unparseable container. Faithful port of
/// `comp_streams`.
fn comp_streams(img: &[u8]) -> Option<(u32, Vec<Stream>)> {
    if img.get(0x1000..0x1004) != Some(b"COMP") {
        return None;
    }
    let mut addrs: Vec<u32> = Vec::new();
    let mut i = 0x1004;
    while i < 0x1100 {
        let v = be_u32(img, i)?;
        if v == 0xFFFF_FFFF {
            break;
        }
        addrs.push(v);
        i += 4;
    }
    if addrs.is_empty() || addrs.len() % 2 != 0 {
        return None;
    }
    let npairs = addrs.len() / 2;
    let first = addrs[0] as u64;
    let len = img.len() as u64;
    // base sweep: from (max(0, first-len) & !0xFFF) .. (first & !0xFFF) step 0x1000.
    let start = (first.saturating_sub(len)) & !0xFFF;
    let stop = first & !0xFFF; // inclusive
    let mut base = start;
    while base <= stop {
        let mut out: Vec<Stream> = Vec::with_capacity(npairs);
        let mut ok = true;
        for p in 0..npairs {
            let s = addrs[2 * p] as u64;
            let e = addrs[2 * p + 1] as u64;
            if s < base || e <= s {
                ok = false;
                break;
            }
            let o = (s - base) as usize;
            if o + 4 > img.len() {
                ok = false;
                break;
            }
            let n = u32::from_be_bytes([img[o], img[o + 1], img[o + 2], img[o + 3]]) as usize;
            // c = img[o+4 .. e-base+4], clamped to the body length (Python slice semantics).
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
            match miniz_oxide::inflate::decompress_to_vec_zlib(c) {
                Ok(x) if x.len() == n => out.push((o, x)),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && out.len() == npairs {
            return Some((base as u32, out));
        }
        base += 0x1000;
    }
    None
}

/// `{reg16 -> set(imm)}` for `MOV.B #imm,Rn` immediately followed by
/// `MOV.B Rn,@aa:8` (`30|n`) or `MOV.B Rn,@aa:16` (`6a 80|n`). Even offsets only.
/// Faithful port of `reg_writes`.
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
/// Even offsets only. Faithful port of `bit_ops`.
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

/// Servo coefficient fingerprint over `main_only`: hash of the first
/// [`SERVO_BASE`] distinct 40-byte rows (in table order), or `"none"`.
/// Faithful port of `servo` (the hash value differs from Python's sha1 but the
/// equivalence — equal input rows => equal output — is preserved).
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

/// Laser write-strategy envelope (reported, not keyed). Faithful port of `laser`.
fn laser(strat: &[u8]) -> Option<String> {
    let needle = [0x00u8, 0x3c, 0x01, 0x02];
    let mut recs: Vec<[u8; 7]> = Vec::new();
    if strat.len() >= needle.len() {
        let mut i = 0;
        while i + needle.len() <= strat.len() {
            if strat[i..i + needle.len()] == needle {
                let s = i + 4;
                if s + 7 <= strat.len() {
                    let mut r = [0u8; 7];
                    r.copy_from_slice(&strat[s..s + 7]);
                    recs.push(r);
                }
            }
            i += 1;
        }
    }
    if recs.is_empty() {
        return None;
    }
    // Each record: >hhhB (3 signed BE i16 + 1 u8). mx[i] = max over recs of
    // field i (ignoring 0x7FFF sentinel), default 0.
    let mut mx: [i32; 4] = [0; 4];
    let mut any: [bool; 4] = [false; 4];
    for r in &recs {
        let fields: [i32; 4] = [
            i16::from_be_bytes([r[0], r[1]]) as i32,
            i16::from_be_bytes([r[2], r[3]]) as i32,
            i16::from_be_bytes([r[4], r[5]]) as i32,
            r[6] as i32,
        ];
        for k in 0..4 {
            if fields[k] != 0x7FFF && (!any[k] || fields[k] > mx[k]) {
                mx[k] = fields[k];
                any[k] = true;
            }
        }
    }
    for k in 0..4 {
        if !any[k] {
            mx[k] = 0;
        }
    }
    let rec0_hex: String = recs[0].iter().map(|b| format!("{:02x}", b)).collect();
    Some(format!(
        "rec0={} max={}/{}/{}/{}",
        rec0_hex, mx[0], mx[1], mx[2], mx[3]
    ))
}

/// Format a reg's integer value set like Python's `fmt`: values sorted
/// numerically, each lowercase hex, joined by `.`; `-` if empty.
fn fmt_ints(s: Option<&BTreeSet<u8>>) -> String {
    match s {
        Some(set) if !set.is_empty() => {
            let parts: Vec<String> = set.iter().map(|v| format!("{:x}", v)).collect();
            parts.join(".")
        }
        _ => "-".to_owned(),
    }
}

/// Format a BOARD reg: integer writes (numeric, hex) then bit-op labels
/// (lexical), joined by `.`; `-` if both empty. Mirrors `fmt(w[a] | b[a])`.
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

/// The computed intermediate used by both [`get_family`] and [`profile`].
struct Computed {
    asic: String,
    pins: String,
    board: String,
    servo: String,
    laser: String,
    flash: String,
    has_asic: bool,
}

/// Compute all profile components from a decoded body. Faithful port of `profile`
/// (minus the family hashing).
fn compute(body: &[u8]) -> Computed {
    let wanted: BTreeSet<u16> = ASIC_REGS
        .iter()
        .chain(PIN_REGS.iter())
        .chain(BOARD_REGS.iter())
        .copied()
        .collect();
    let board_wanted: BTreeSet<u16> = BOARD_REGS.iter().copied().collect();

    let (code, strat, main_only, flash): (Vec<u8>, Vec<u8>, Vec<u8>, String) =
        match comp_streams(body) {
            Some((base, st)) => {
                let first = st.iter().map(|(o, _)| *o).min().unwrap_or(0);
                let main = &body[..first.min(body.len())];
                let mut code = main.to_vec();
                if st.len() > 5 {
                    code.extend_from_slice(&st[5].1);
                }
                let strat = st[0].1.clone();
                let main_only = main.to_vec();
                let flash = format!("base={:#x} window=0x400000-0x5fffff", base);
                (code, strat, main_only, flash)
            }
            None => (
                body.to_vec(),
                body.to_vec(),
                body.to_vec(),
                "uncompressed window=0x400000-0x5fffff".to_owned(),
            ),
        };

    let w = reg_writes(&code, &wanted);
    let b = bit_ops(&code, &board_wanted);

    let has_asic = ASIC_REGS
        .iter()
        .any(|a| w.get(a).is_some_and(|s| !s.is_empty()));

    let asic = ASIC_REGS
        .iter()
        .map(|a| format!("{:04x}={}", a, fmt_ints(w.get(a))))
        .collect::<Vec<_>>()
        .join(" ");
    let pins = PIN_REGS
        .iter()
        .map(|a| format!("{:04x}={}", a, fmt_ints(w.get(a))))
        .collect::<Vec<_>>()
        .join(" ");
    let board = BOARD_REGS
        .iter()
        .map(|a| format!("{:04x}={}", a, fmt_board(w.get(a), b.get(a))))
        .collect::<Vec<_>>()
        .join(" ");
    let servo = servo(&main_only);
    let laser = laser(&strat).unwrap_or_else(|| "none".to_owned());

    Computed {
        asic,
        pins,
        board,
        servo,
        laser,
        flash,
        has_asic,
    }
}

/// Deterministic crossflash-compat id from an envelope-**decoded** firmware body
/// (the `COMP` container, i.e. `pioneer_codec::decode_envelope(enc).image`).
///
/// Equal ids == same silicon/optical platform == crossflash compatible. Returns
/// `None` when the body cannot be profiled (no front-end ASIC configuration: a
/// Kernel component, an undecodable DVR body, or a non-Pioneer blob).
pub fn get_family(body: &[u8]) -> Option<FamilyId> {
    let c = compute(body);
    if !c.has_asic {
        return None;
    }
    // Family key = canonical (asic, board, pins, servo). Drop servo for v1 boards
    // (FFC5 driven high: the 'ffc5=20' case), where it is absent or redundant.
    let drop_servo = c.board.contains("ffc5=20");
    let key = if drop_servo {
        format!(
            "asic={}\u{1f}board={}\u{1f}pins={}",
            c.asic, c.board, c.pins
        )
    } else {
        format!(
            "asic={}\u{1f}board={}\u{1f}pins={}\u{1f}servo={}",
            c.asic, c.board, c.pins, c.servo
        )
    };
    Some(FamilyId(fnv1a(key.as_bytes())))
}

/// The full reported hardware [`Profile`], or `None` when the body carries no
/// front-end ASIC configuration (same condition as [`get_family`]).
pub fn profile(body: &[u8]) -> Option<Profile> {
    let c = compute(body);
    if !c.has_asic {
        return None;
    }
    Some(Profile {
        laser: c.laser,
        asic: c.asic,
        pins: c.pins,
        board: c.board,
        servo: c.servo,
        flash: c.flash,
    })
}

/// Whether the decoded body carries the UHD capability signature (`SIG0`).
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
        assert_eq!(get_family(&[]), None);
        assert_eq!(get_family(&[0u8; 64]), None);
        assert!(!is_uhd(&[]));
        assert!(profile(&[0u8; 64]).is_none());
    }

    #[test]
    fn family_id_displays_lowercase_hex() {
        let id = FamilyId(0xABCD_1234);
        assert_eq!(format!("{}", id), "abcd1234");
    }

    #[test]
    fn is_uhd_finds_sig0_anywhere() {
        let mut body = alloc::vec![0u8; 100];
        body.extend_from_slice(&SIG0);
        body.extend_from_slice(&[0u8; 50]);
        assert!(is_uhd(&body));
    }

    /// A minimal synthetic pre-COMP body: a single ASIC MOV.B write at an even
    /// offset gives a stable family and a Profile.
    #[test]
    fn synthetic_asic_write_yields_family() {
        // MOV.B #0x12,R6 ; MOV.B R6,@0x36:8  => F6 12 36 36  (addr 0xFF36 - not an
        // ASIC reg). Use E436: aa=0x36 gives 0xFF36; we need 0xE436 (16-bit form).
        // 16-bit: F6 12 6A 86 E4 36  -> MOV.B #12,R6 ; MOV.B R6,@E436:16
        let body = [0xF6u8, 0x12, 0x6A, 0x86, 0xE4, 0x36, 0x00, 0x00];
        let fam = get_family(&body);
        assert!(fam.is_some());
        let p = profile(&body).unwrap();
        assert!(p.asic.contains("e436=12"));
    }
}
