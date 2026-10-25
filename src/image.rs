//! Analysis of decoded firmware bodies: hardware family, UHD capability and
//! Kernel ABI.
//!
//! Every function takes a decoded body (the plaintext image inside a firmware
//! envelope).
//!
//! Requires the `image` feature.

mod abi;
mod control;
pub(crate) mod h8;
mod handoff;
mod receiver;
pub use abi::{provided_abi, required_abi, Abi};
pub use control::{receiver_control, ReceiverControl};
#[cfg(all(test, feature = "envelope"))]
pub(crate) use handoff::tests::fixture as handoff_fixture;
pub use handoff::{
    check_kernel_handoff, kernel_handoff_entry, kernel_startup_entry, KernelHandoffError,
};
#[cfg(all(test, feature = "envelope"))]
pub(crate) use receiver::tests::fixture as receiver_fixture;
pub use receiver::{kernel_marker_policy, KernelMarkerPolicy};

use alloc::borrow::ToOwned;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Load address of the Kernel component.
pub const KERNEL_BASE: u32 = 0x40_0000;
/// Size of a Kernel body, in bytes.
pub const KERNEL_LEN: usize = 0x1_0000;

/// Front-end servo/RF ASIC register block (low 16 bits of `0xFFExxx`).
const ASIC_REGS: [u16; 7] = [0xE436, 0xE43A, 0xE43B, 0xE45B, 0xE463, 0xE46A, 0xE46B];
/// Remaining hardware/interface initialization evidence.
/// Excluded host configuration is retained separately for settings admission.
const PIN_REGS: [u16; 2] = [0xFE94, 0xFEC0];
/// PCB-revision marker registers.
const BOARD_REGS: [u16; 3] = [0xFFC5, 0xEDCC, 0xEDCD];

/// Servo loop-filter coefficient-row anchor (`7f 97 7f 51 7f 51 7f 51 7f 51`).
const SERVO_ROW: [u8; 10] = [0x7f, 0x97, 0x7f, 0x51, 0x7f, 0x51, 0x7f, 0x51, 0x7f, 0x51];
/// Number of distinct servo rows that form the version-stable base.
const SERVO_BASE: usize = 7;
/// Version 4 separates host configuration from hardware evidence.
pub const FAMILY_SCHEME: &str = "pioneer.hardware.v4";

/// Full servo coefficient row width.
const SERVO_ROW_LEN: usize = 40;

/// Code fragment present in every UHD-capable body and no other.
const SIG0: [u8; 24] = [
    0x5E, 0x40, 0x83, 0xB8, 0x7A, 0x00, 0x41, 0x00, 0x03, 0x89, 0x01, 0x00, 0x6F, 0xE0, 0x00, 0xC4,
    0x01, 0x00, 0x69, 0xE3, 0x5E, 0x40, 0x87, 0xD0,
];

/// A hardware-family fingerprint derived from the image's hardware setup.
/// Matching families establish platform evidence; required settings migrations
/// must be independently supported before a package can be prepared. The receiver implementation must handle any
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

/// A logical region, kept separate so unrelated spans never form instructions.
pub(crate) struct Regions<'a> {
    pub stored: Vec<&'a [u8]>,
    pub expanded: Vec<Vec<u8>>,
}
impl Regions<'_> {
    pub fn slices(&self) -> Vec<&[u8]> {
        self.stored
            .iter()
            .copied()
            .chain(self.expanded.iter().map(Vec::as_slice))
            .collect()
    }
}

/// Shared checked decoding: malformed COMP never falls back to scanning compressed bytes.
pub(crate) fn regions(body: &[u8]) -> Option<Regions<'_>> {
    let streams =
        crate::comp_streams::read(body, crate::comp::MAX_TOTAL_EXPANDED, &mut || true).ok()?;
    let Some((_, mut streams)) = streams else {
        return Some(Regions {
            stored: vec![body],
            expanded: Vec::new(),
        });
    };
    streams.sort_by_key(|s| s.image_offset);
    let spans: Vec<_> = streams
        .iter()
        .map(|s| (s.image_offset, s.compressed_size))
        .collect();
    let stored = stored_regions(body, &spans)?;
    Some(Regions {
        stored,
        expanded: streams.into_iter().map(|s| s.expanded).collect(),
    })
}

/// Remove compressed spans without joining unrelated stored bytes.
/// Callers supply spans in physical order after validated COMP decoding.
pub(crate) fn stored_regions<'a>(
    body: &'a [u8],
    spans: &[(usize, usize)],
) -> Option<Vec<&'a [u8]>> {
    let mut regions = Vec::new();
    let mut cursor = 0;
    for &(offset, size) in spans {
        if offset < cursor {
            return None;
        }
        regions.push(body.get(cursor..offset)?);
        cursor = offset.checked_add(4)?.checked_add(size)?;
    }
    regions.push(body.get(cursor..)?);
    Some(regions)
}

#[cfg(test)]
fn comp_streams(body: &[u8]) -> Option<Vec<(usize, Vec<u8>)>> {
    crate::comp_streams::read(body, crate::comp::MAX_TOTAL_EXPANDED, &mut || true)
        .ok()?
        .map(|(_, streams)| {
            streams
                .into_iter()
                .map(|s| (s.image_offset, s.expanded))
                .collect()
        })
}

/// Stored gaps retain the image's instruction alignment; expanded streams start
/// at their own logical origin. Byte signatures still use the complete regions.
pub(crate) fn aligned_code_region<'a>(region: &'a [u8], body: &[u8]) -> &'a [u8] {
    let start = region.as_ptr() as usize;
    let origin = body.as_ptr() as usize;
    let skip = if start >= origin && start - origin < body.len() {
        (start - origin) & 1
    } else {
        0
    };
    region.get(skip..).unwrap_or_default()
}

/// `{reg16 -> set(value)}` for `MOV.B #imm,Rn` or self SUB/XOR byte zeroing, followed by
/// `MOV.B Rn,@aa:8` (`30|n`) or `MOV.B Rn,@aa:16` (`6a 80|n`). Even offsets only.
fn reg_writes(code: &[u8], want: &BTreeSet<u16>) -> BTreeMap<u16, BTreeSet<u8>> {
    let mut out: BTreeMap<u16, BTreeSet<u8>> = BTreeMap::new();
    let mut i = 0;
    while i + 2 < code.len() {
        let b0 = code[i];
        let (r, imm) = if (0xF0..=0xFF).contains(&b0) {
            (b0 & 0x0F, code[i + 1])
        } else if matches!(b0, 0x18 | 0x15) && code[i + 1] >> 4 == code[i + 1] & 0x0F {
            // SUB.B Rn,Rn / XOR.B Rn,Rn writes a known zero, not missing evidence.
            (code[i + 1] & 0x0F, 0)
        } else {
            i += 2;
            continue;
        };
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
/// 40-byte base rows, sorted before hashing, or `"none"`.
#[cfg(test)]
fn servo(code: &[u8]) -> String {
    servo_regions(&[code])
}

fn servo_regions(regions: &[&[u8]]) -> String {
    let mut rows: Vec<&[u8]> = Vec::new();
    for region in regions {
        for row in region.windows(SERVO_ROW_LEN) {
            if row.starts_with(&SERVO_ROW) && !rows.contains(&row) {
                rows.push(row);
                if rows.len() == SERVO_BASE {
                    break;
                }
            }
        }
        if rows.len() == SERVO_BASE {
            break;
        }
    }
    if rows.is_empty() {
        return "none".to_owned();
    }
    // The version-stable base may be laid out in different physical orders.
    rows.sort_unstable();
    let concat: Vec<u8> = rows.into_iter().flatten().copied().collect();
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
    family_fingerprint(body).map(|f| f.family)
}

/// Exact configuration inputs used to calculate a hardware family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyFingerprint {
    /// Calculated hardware-family identifier.
    pub family: Family,
    /// Canonical servo/RF register values.
    pub asic: String,
    /// Canonical board marker writes and bit operations.
    pub board: String,
    /// Canonical remaining hardware/interface setup values.
    /// The legacy field name does not imply verified physical pin assignments.
    pub pins: String,
    /// Servo coefficient hash, or `"none"` when no anchor rows were found.
    pub servo: String,
}

/// Extract the configuration evidence used by [`family`].
pub fn family_fingerprint(body: &[u8]) -> Option<FamilyFingerprint> {
    let regions = regions(body)?;
    fingerprint_regions(&regions.slices(), body)
}

/// Already-decoded regions supplied by the analysis pipeline.
#[cfg(feature = "analysis")]
pub(crate) fn family_regions(regions: &[&[u8]], body: &[u8]) -> Option<Family> {
    fingerprint_regions(regions, body).map(|f| f.family)
}

fn fingerprint_regions(regions: &[&[u8]], body: &[u8]) -> Option<FamilyFingerprint> {
    let wanted: BTreeSet<u16> = ASIC_REGS
        .iter()
        .chain(PIN_REGS.iter())
        .chain(BOARD_REGS.iter())
        .copied()
        .collect();
    let board_wanted: BTreeSet<u16> = BOARD_REGS.iter().copied().collect();

    let mut w: BTreeMap<u16, BTreeSet<u8>> = BTreeMap::new();
    let mut b: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
    for region in regions {
        let region = aligned_code_region(region, body);
        for (key, values) in reg_writes(region, &wanted) {
            w.entry(key).or_default().extend(values);
        }
        for (key, values) in bit_ops(region, &board_wanted) {
            b.entry(key).or_default().extend(values);
        }
    }
    if !ASIC_REGS
        .iter()
        .any(|a| w.get(a).is_some_and(|s| !s.is_empty()))
    {
        return None;
    }
    let regs = |set: &[u16], f: &dyn Fn(&u16) -> String| {
        set.iter()
            .map(|a| format!("{:04x}={}", a, f(a)))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let asic = regs(&ASIC_REGS, &|a| fmt_ints(w.get(a)));
    let pins = regs(&PIN_REGS, &|a| fmt_ints(w.get(a)));
    let board = regs(&BOARD_REGS, &|a| fmt_board(w.get(a), b.get(a)));

    // Servo is independent evidence even on boards whose FFC5 writes include
    // 0x20. Omitting it conflates SAT 8000/8680 and SAT 8301/8600/8800.
    let servo = servo_regions(regions);
    let key = format!("asic={asic}\u{1f}board={board}\u{1f}pins={pins}\u{1f}servo={servo}");
    Some(FamilyFingerprint {
        family: Family(fnv1a(key.as_bytes())),
        asic,
        board,
        pins,
        servo,
    })
}

/// Whether the body is UHD-capable.
pub fn is_uhd(body: &[u8]) -> bool {
    regions(body).is_some_and(|r| uhd_regions(&r.slices()))
}

pub(crate) fn uhd_regions(regions: &[&[u8]]) -> bool {
    regions
        .iter()
        .any(|s| s.windows(SIG0.len()).any(|w| w == SIG0))
}

#[cfg(test)]
#[path = "image_tests.rs"]
mod tests;
