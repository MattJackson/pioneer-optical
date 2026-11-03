//! Native pending-write queue contracts. The producer stores the supplied
//! parameter and desired value; initialization and producer reachability remain
//! separate observations. Missing recognition never means the queue is empty.
use super::{cache, cache_flow::Reference, cache_writers, CallKind};
use crate::image::layout::Observation;
use alloc::vec::Vec;

/// Complete zero-range call semantics, conditional on its indirect call target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialZero {
    /// Decoded Normal offset of the indirect call.
    pub call: usize,
    /// Indirect-call ER3 or ER4 that the boot graph must bind to `clearer`.
    pub target_register: u8,
    /// Actual CPU address of the fully bound native range-clear leaf.
    pub clearer: u32,
    /// Actual CPU address of its fully bound memset leaf.
    pub memset: u32,
    /// Inclusive RAM start and exclusive RAM end.
    pub range: (u32, u32),
    /// One-byte queue count address (one reserved byte follows).
    pub count: u32,
    /// Start of fifty four-byte records.
    pub storage: u32,
}
/// Bind MOV.L #lo,ER0; MOV.L #hi,ER1; SUB.W R2,R2; JSR @ER3/4,
/// the complete range-clear leaf and its actual complete memset callee.
/// The caller must prove the indirect target and execution before dispatch.
pub fn bind_initial_zero(
    normal: &[u8],
    cache_base: u32,
    call: usize,
    clearer: u32,
) -> Option<InitialZero> {
    let start = call.checked_sub(14)?;
    let bytes =
        cache_writers::stored_at(normal, 0x410000u32.checked_add(start.try_into().ok()?)?, 16)?;
    if bytes[..2] != [0x7a, 0] || bytes[6..8] != [0x7a, 1] || bytes[12..15] != [0x19, 0x22, 0x5d] {
        return None;
    }
    let target_register = match bytes[15] {
        0x30 => 3,
        0x40 => 4,
        _ => return None,
    };
    let lo = u32::from_be_bytes(bytes[2..6].try_into().ok()?);
    let hi = u32::from_be_bytes(bytes[8..12].try_into().ok()?);
    let count = cache_base.checked_add(128)?;
    if lo > count || count.checked_add(202)? > hi {
        return None;
    }
    let leaf = cache_writers::stored_at(normal, clearer, 18)?;
    const CLEAR: &[u8] = &[
        0x6d, 0xf4, 0x0d, 0x24, 0x0f, 0x92, 0x1a, 0x82, 0x0d, 0x41, 0x5e, 0, 0, 0, 0x6d, 0x74,
        0x54, 0x70,
    ];
    if leaf
        .iter()
        .zip(CLEAR)
        .enumerate()
        .any(|(i, (a, b))| !(11..14).contains(&i) && a != b)
    {
        return None;
    }
    let memset = u32::from_be_bytes([0, leaf[11], leaf[12], leaf[13]]);
    if !cache_writers::is_memset(normal, memset) {
        return None;
    }
    Some(InitialZero {
        call,
        target_register,
        clearer,
        memset,
        range: (lo, hi),
        count,
        storage: count + 2,
    })
}
/// Find clear argument setups covering the entire queue. These offsets require
/// `bind_initial_zero` plus boot-path target and execution proofs.
pub fn initial_zero_candidates(normal: &[u8], cache_base: u32) -> Vec<usize> {
    let Some(regions) = crate::image::regions(normal) else {
        return Vec::new();
    };
    let Some(count) = cache_base.checked_add(128) else {
        return Vec::new();
    };
    let Some(end) = count.checked_add(202) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for region in regions.stored {
        let start = region.as_ptr() as usize - normal.as_ptr() as usize;
        for local in (start & 1..region.len()).step_by(2) {
            let Some(b) = region.get(local..local + 16) else {
                continue;
            };
            if b[..2] == [0x7a, 0]
                && b[6..8] == [0x7a, 1]
                && b[12..15] == [0x19, 0x22, 0x5d]
                && [0x30, 0x40].contains(&b[15])
            {
                let lo = u32::from_be_bytes(b[2..6].try_into().unwrap());
                let hi = u32::from_be_bytes(b[8..12].try_into().unwrap());
                if lo <= count && end <= hi {
                    found.push(start + local + 14);
                }
            }
        }
    }
    found
}
/// Syntactic input evidence. Incoming branches and external callee register
/// preservation must be joined with function-level control-flow evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// Immediately preceding parameter load; an incoming edge may bypass it.
    ContiguousImmediate(u16),
    /// Unsigned record selector*16+0x1c0 plus offsets 0..7 excludes 0x009f.
    RecordSlots,
    /// Parameter and desired value both originate in a live RAM request word.
    RamRequest,
    /// No native input contract bound this reference.
    Unresolved,
}
/// A literal reference or aligned relative call to the bound producer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceEvidence {
    /// Actual stored/expanded address occurrence; for relative calls, opcode offset.
    pub reference: Reference,
    /// Native aligned call encoding, if any.
    pub call: Option<CallKind>,
    /// Local input contract, with its scope retained.
    pub input: Input,
}
/// Fully bound queue producer; all count operands and storage base agree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Producer {
    /// Decoded Normal entry offset.
    pub offset: usize,
    /// Exclusive end, including overflow diagnostics and return.
    pub end: usize,
    /// Native parameter argument word register; its high word supplies the value.
    pub argument_register: u8,
    /// One-byte queue count, bounded to fifty records by the native guard.
    pub count: u32,
    /// Fifty four-byte records: parameter word then desired-value word.
    pub storage: u32,
    /// External calls in the overflow path; no behavior is inferred from names.
    pub overflow_callees: Vec<u32>,
    /// Diagnostics source pointers that may relocate without changing scalars.
    pub diagnostic_sources: Vec<u32>,
    /// Every producer literal reference and aligned native relative call.
    pub references: Vec<ReferenceEvidence>,
    /// Complete non-immediate local input contracts and their dependencies.
    pub input_contracts: Vec<InputContract>,
}
struct Shape {
    bytes: &'static [u8],
    relocations: &'static [(usize, usize, usize)],
    count: usize,
    storage: usize,
    register: u8,
    calls: &'static [usize],
    sources: &'static [usize],
}
impl Shape {
    fn bind(&self, bytes: &[u8], cache_base: u32) -> Option<(Vec<u32>, Vec<u32>)> {
        if bytes.len() != self.bytes.len() {
            return None;
        }
        let mut groups: Vec<Option<u32>> =
            alloc::vec![None;self.relocations.iter().map(|r|r.2+1).max()?];
        for &(p, n, g) in self.relocations {
            let value = bytes[p..p + n]
                .iter()
                .fold(0, |a, &b| a * 256 + u32::from(b));
            if groups[g].is_some_and(|v| v != value) {
                return None;
            }
            groups[g] = Some(value);
        }
        if groups[self.count] != cache_base.checked_add(128)
            || groups[self.storage] != cache_base.checked_add(130)
        {
            return None;
        }
        if bytes.iter().zip(self.bytes).enumerate().any(|(i, (a, b))| {
            !self
                .relocations
                .iter()
                .any(|&(p, n, _)| (p..p + n).contains(&i))
                && a != b
        }) {
            return None;
        }
        Some((
            self.calls.iter().map(|&g| groups[g].unwrap()).collect(),
            self.sources.iter().map(|&g| groups[g].unwrap()).collect(),
        ))
    }
}
const PRODUCERS: &[Shape] = &[
    Shape {
        bytes: &[
            0x6d, 0xf3, 0x02, 0x0b, 0x04, 0x80, 0x0d, 0x82, 0x0d, 0x0a, 0x6a, 0x29, 0x00, 0x00,
            0x00, 0x00, 0xa9, 0x32, 0x44, 0x2c, 0x6a, 0x29, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x80,
            0x0c, 0x98, 0x10, 0x70, 0x7a, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x69, 0x82,
            0x6a, 0x20, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x28, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x08,
            0x6a, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x40, 0x0a, 0x79, 0x00, 0x45, 0x00, 0x5e, 0x00,
            0x00, 0x00, 0xf0, 0xff, 0xa0, 0xff, 0x46, 0x0a, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x5e, 0x00, 0x00, 0x00, 0x03, 0x0b, 0x6d, 0x73, 0x54, 0x70,
        ],
        relocations: &[
            (12, 4, 0),
            (22, 4, 0),
            (34, 4, 1),
            (44, 4, 0),
            (50, 4, 0),
            (58, 4, 0),
            (69, 3, 2),
            (80, 4, 3),
            (85, 3, 4),
        ],
        count: 0,
        storage: 1,
        register: 0,
        calls: &[2, 4],
        sources: &[3],
    },
    Shape {
        bytes: &[
            0x6d, 0xf3, 0x1b, 0x97, 0x02, 0x0b, 0x04, 0x80, 0x0d, 0x92, 0x0d, 0x1a, 0x6a, 0x28,
            0x00, 0x00, 0x00, 0x00, 0xa8, 0x32, 0x44, 0x2c, 0x6a, 0x29, 0x00, 0x00, 0x00, 0x00,
            0x1a, 0x80, 0x0c, 0x98, 0x10, 0x70, 0x7a, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x69, 0x82, 0x6a, 0x20, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x28, 0x00, 0x00, 0x00, 0x00,
            0x0a, 0x08, 0x6a, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x40, 0x0a, 0x79, 0x00, 0x45, 0x00,
            0x5e, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xa0, 0xff, 0x46, 0x12, 0x7a, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x69, 0xf0, 0x1a, 0x80, 0xf0, 0x20, 0x5e, 0x00, 0x00, 0x00,
            0x03, 0x0b, 0x0b, 0x97, 0x6d, 0x73, 0x54, 0x70,
        ],
        relocations: &[
            (14, 4, 0),
            (24, 4, 0),
            (36, 4, 1),
            (46, 4, 0),
            (52, 4, 0),
            (60, 4, 0),
            (71, 3, 2),
            (82, 4, 3),
            (95, 3, 4),
        ],
        count: 0,
        storage: 1,
        register: 1,
        calls: &[2, 4],
        sources: &[3],
    },
];

/// Bound producer-input block. External calls retain explicit preservation and
/// behavior obligations; no boot reachability follows from this local match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputContract {
    /// Start and exclusive end in decoded Normal.
    pub range: (usize, usize),
    /// Input relation established by native scalar instructions.
    pub input: Input,
    /// Other actual callees whose register preservation must be established.
    pub external_calls: Vec<u32>,
    /// Branch destinations outside this local block.
    pub continuation_targets: Vec<u32>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum SemanticKind {
    RecordSlots,
    RequestEntry,
    RequestWrite,
}
struct SemanticShape {
    kind: SemanticKind,
    bytes: &'static [u8],
    relocations: &'static [(usize, usize, usize)],
    branches: &'static [(usize, usize)],
}
impl SemanticShape {
    fn bind(&self, bytes: &[u8]) -> Option<Vec<u32>> {
        if bytes.len() != self.bytes.len() {
            return None;
        }
        let mut groups: Vec<Option<u32>> =
            alloc::vec![None;self.relocations.iter().map(|r|r.2+1).max()?];
        for &(p, n, g) in self.relocations {
            let value = bytes[p..p + n]
                .iter()
                .fold(0, |a, &b| a * 256 + u32::from(b));
            if groups[g].is_some_and(|v| v != value) {
                return None;
            }
            groups[g] = Some(value);
        }
        if bytes.iter().zip(self.bytes).enumerate().any(|(i, (a, b))| {
            !self
                .relocations
                .iter()
                .any(|&(p, n, _)| (p..p + n).contains(&i))
                && !self.branches.iter().any(|&(p, n)| (p..p + n).contains(&i))
                && a != b
        }) {
            return None;
        }
        Some(groups.into_iter().map(Option::unwrap).collect())
    }
}
const SEMANTICS: &[SemanticShape] = &[
    SemanticShape {
        kind: SemanticKind::RecordSlots,
        bytes: &[
            0x01, 0x00, 0x6d, 0xf3, 0x01, 0x20, 0x6d, 0xf4, 0x0f, 0x84, 0x6f, 0x03, 0x00, 0x02,
            0x6a, 0x10, 0x00, 0x00, 0x73, 0x00, 0x46, 0x04, 0x18, 0x33, 0x40, 0x08, 0x6a, 0x18,
            0x00, 0x00, 0x72, 0x00, 0xf3, 0xbb, 0x7a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x5d, 0x60,
            0x68, 0x49, 0x17, 0x51, 0x10, 0x51, 0x10, 0x51, 0x79, 0x11, 0x01, 0xc0, 0x0d, 0x39,
            0x7a, 0x05, 0x00, 0x00, 0x00, 0x00, 0x5d, 0x50, 0x68, 0x49, 0x0a, 0x09, 0xa9, 0x04,
            0x45, 0x02, 0x18, 0x99, 0x68, 0xc9, 0xf3, 0xff, 0x6a, 0x08, 0x00, 0x00, 0xa8, 0x02,
            0x46, 0x06, 0x6a, 0x0b, 0x00, 0x00, 0x40, 0x02, 0xfb, 0x0f, 0x6f, 0xc3, 0x00, 0x02,
            0x68, 0x48, 0x17, 0x50, 0x0d, 0x0b, 0x10, 0x5b, 0x10, 0x5b, 0x79, 0x1b, 0x01, 0xc0,
            0x5d, 0x60, 0x0d, 0x39, 0x0d, 0xb1, 0x5d, 0x50, 0x6a, 0x23, 0x00, 0x00, 0x00, 0x00,
            0x6a, 0x0b, 0x00, 0x00, 0x5d, 0x60, 0x0d, 0xb1, 0x0b, 0x51, 0x0d, 0x39, 0x5d, 0x50,
            0x6a, 0x03, 0x00, 0x00, 0x6a, 0x0b, 0x00, 0x00, 0x5d, 0x60, 0x0d, 0xb1, 0x0b, 0xd1,
            0x0d, 0x39, 0x5d, 0x50, 0x6a, 0x03, 0x00, 0x00, 0x6a, 0x0b, 0x00, 0x00, 0x5d, 0x60,
            0x0d, 0xb1, 0x79, 0x11, 0x00, 0x03, 0x0d, 0x39, 0x5d, 0x50, 0x6a, 0x03, 0x00, 0x00,
            0x6a, 0x0b, 0x00, 0x00, 0x5d, 0x60, 0x0d, 0xb1, 0x79, 0x11, 0x00, 0x04, 0x0d, 0x39,
            0x5d, 0x50, 0x6a, 0x03, 0x00, 0x00, 0x6a, 0x0b, 0x00, 0x00, 0x5d, 0x60, 0x0d, 0xb1,
            0x79, 0x11, 0x00, 0x05, 0x0d, 0x39, 0x5d, 0x50, 0x6a, 0x03, 0x00, 0x00, 0x6a, 0x0b,
            0x00, 0x00, 0x5d, 0x60, 0x0d, 0xb1, 0x79, 0x11, 0x00, 0x06, 0x0d, 0x39, 0x5d, 0x50,
            0x6b, 0x23, 0x00, 0x00, 0x00, 0x00, 0x5d, 0x60, 0x79, 0x1b, 0x00, 0x07, 0x0d, 0xb1,
            0x0d, 0x39, 0x5d, 0x50, 0x01, 0x20, 0x6d, 0x76, 0x01, 0x00, 0x6d, 0x73, 0x54, 0x70,
        ],
        relocations: &[
            (16, 2, 0),
            (28, 2, 0),
            (36, 4, 1),
            (58, 4, 2),
            (80, 2, 3),
            (88, 2, 4),
            (122, 4, 5),
            (128, 2, 6),
            (142, 2, 7),
            (146, 2, 8),
            (160, 2, 9),
            (164, 2, 10),
            (180, 2, 11),
            (184, 2, 12),
            (200, 2, 13),
            (204, 2, 14),
            (220, 2, 15),
            (224, 2, 16),
            (240, 4, 17),
        ],
        branches: &[],
    },
    SemanticShape {
        kind: SemanticKind::RequestEntry,
        bytes: &[
            0x01, 0x00, 0x6d, 0xf3, 0x01, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0x00, 0x08, 0xfe, 0x04,
            0x01, 0x00, 0x6b, 0x01, 0x00, 0x00, 0x0d, 0x13, 0x0d, 0x90, 0x0d, 0x04, 0x6a, 0x00,
            0x00, 0x00, 0x0c, 0x01, 0x72, 0x70, 0xa0, 0x01, 0x58, 0x70, 0x00, 0x00, 0xa0, 0x03,
            0x58, 0x70, 0x00, 0x00, 0xa0, 0x02, 0x58, 0x70, 0x00, 0x00, 0xa0, 0x0d, 0x58, 0x70,
            0x00, 0x00, 0xa0, 0x0e, 0x58, 0x70, 0x00, 0x00, 0xa0, 0x0f, 0x58, 0x60, 0x00, 0x00,
        ],
        relocations: &[(18, 2, 0), (28, 2, 1)],
        branches: &[(38, 2), (44, 2), (50, 2), (56, 2), (62, 2), (68, 2)],
    },
    SemanticShape {
        kind: SemanticKind::RequestWrite,
        bytes: &[
            0x7a, 0x05, 0x00, 0x00, 0x00, 0x00, 0x73, 0x71, 0x47, 0x26, 0x5d, 0x50, 0x5e, 0x00,
            0x00, 0x00, 0x0c, 0x88, 0x46, 0x3e, 0x5d, 0x50, 0x0d, 0x31, 0x5e, 0x00, 0x00, 0x00,
            0x0c, 0x88, 0x47, 0x0a, 0x5d, 0x50, 0x0d, 0x31, 0x5e, 0x00, 0x00, 0x00, 0x40, 0x46,
            0x79, 0x00, 0xaa, 0xaa, 0x40, 0x40, 0x5d, 0x50, 0x5e, 0x00, 0x00, 0x00, 0x0c, 0x88,
            0x46, 0x18, 0x5d, 0x50, 0x0d, 0x31, 0x5e, 0x00, 0x00, 0x00, 0x0c, 0x88, 0x47, 0x66,
            0x5d, 0x50, 0x0d, 0x31, 0x0d, 0x49, 0x5e, 0x00, 0x00, 0x00, 0x40, 0x5a,
        ],
        relocations: &[
            (2, 4, 0),
            (13, 3, 1),
            (25, 3, 2),
            (37, 3, 3),
            (51, 3, 1),
            (63, 3, 2),
            (77, 3, 4),
        ],
        branches: &[],
    },
];
fn read(bytes: &[u8], p: usize, n: usize) -> u32 {
    bytes[p..p + n]
        .iter()
        .fold(0, |a, &b| a * 256 + u32::from(b))
}
fn branch_target(bytes: &[u8], at: usize, p: usize) -> u32 {
    (0x410000i64
        + at as i64
        + p as i64
        + 2
        + i64::from(i16::from_be_bytes(bytes[p..p + 2].try_into().unwrap()))) as u32
}
fn input_contracts(normal: &[u8], producer: u32) -> Vec<InputContract> {
    let Some(regions) = crate::image::regions(normal) else {
        return Vec::new();
    };
    let mut matched = Vec::new();
    for region in regions.stored {
        let start = region.as_ptr() as usize - normal.as_ptr() as usize;
        for local in (start & 1..region.len()).step_by(2) {
            for shape in SEMANTICS {
                let Some(bytes) = region.get(local..local + shape.bytes.len()) else {
                    continue;
                };
                if bytes[..2] == shape.bytes[..2] && shape.bind(bytes).is_some() {
                    matched.push((shape, start + local, bytes.to_vec()));
                }
            }
        }
    }
    let mut result = Vec::new();
    for (shape, at, bytes) in &matched {
        if shape.kind == SemanticKind::RecordSlots && read(bytes, 0x3a, 4) == producer {
            result.push(InputContract {
                range: (*at, *at + bytes.len()),
                input: Input::RecordSlots,
                external_calls: alloc::vec![read(bytes, 0x24, 4)],
                continuation_targets: Vec::new(),
            });
        }
        if shape.kind != SemanticKind::RequestWrite || read(bytes, 0x4d, 3) != producer {
            continue;
        }
        for (entry, entry_at, entry_bytes) in &matched {
            if entry.kind != SemanticKind::RequestEntry {
                continue;
            }
            // Mode 2 selects exactly this read/write block; request words and
            // mode byte have the native two-byte relative placement.
            if branch_target(entry_bytes, *entry_at, 0x32) != 0x410000 + *at as u32
                || read(entry_bytes, 0x1c, 2).checked_add(2) != Some(read(entry_bytes, 0x12, 2))
            {
                continue;
            }
            let mut external_calls = alloc::vec![
                read(bytes, 2, 4),
                read(bytes, 0x0d, 3),
                read(bytes, 0x19, 3),
                read(bytes, 0x25, 3)
            ];
            external_calls.sort_unstable();
            external_calls.dedup();
            let mut continuation_targets: Vec<u32> = entry
                .branches
                .iter()
                .map(|&(p, _)| branch_target(entry_bytes, *entry_at, p))
                .collect();
            // Explicit outer branches from the request block are not assumed
            // equivalent merely because their relative displacement is fixed.
            for p in [0x13usize, 0x29, 0x2f, 0x39, 0x45, 0x51] {
                if p < bytes.len() {
                    let target =
                        (0x410000i64 + *at as i64 + p as i64 + 1 + i64::from(bytes[p] as i8))
                            as u32;
                    if target < 0x410000 + *at as u32
                        || target >= 0x410000 + (*at + bytes.len()) as u32
                    {
                        continuation_targets.push(target);
                    }
                }
            }
            result.push(InputContract {
                range: (*at, *at + bytes.len()),
                input: Input::RamRequest,
                external_calls,
                continuation_targets,
            });
        }
    }
    result
}
/// Bind complete producers and retain every reference whose input or address
/// interpretation is incomplete. The queue's initial state is a separate join.
pub fn discover(normal: &[u8]) -> Observation<Vec<Producer>> {
    let blocks = match cache::discover(normal) {
        Observation::Known(v) => v,
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    let regions = crate::image::regions(normal).expect("cache checked regions");
    let mut result = Vec::new();
    for block in blocks {
        for region in &regions.stored {
            let start = region.as_ptr() as usize - normal.as_ptr() as usize;
            for local in (start & 1..region.len()).step_by(2) {
                for shape in PRODUCERS {
                    let Some(bytes) = region.get(local..local + shape.bytes.len()) else {
                        continue;
                    };
                    if bytes[..2] != shape.bytes[..2] {
                        continue;
                    }
                    let Some((overflow_callees, diagnostic_sources)) =
                        shape.bind(bytes, block.ram_base)
                    else {
                        continue;
                    };
                    let offset = start + local;
                    let target = 0x410000 + offset as u32;
                    let contracts = if shape.register == 1 {
                        input_contracts(normal, target)
                    } else {
                        Vec::new()
                    };
                    let mut references = Vec::new();
                    for r in &regions.stored {
                        let base = r.as_ptr() as usize - normal.as_ptr() as usize;
                        for (q, window) in r.windows(3).enumerate() {
                            if window != &target.to_be_bytes()[1..] {
                                continue;
                            }
                            let call = if q > 0 && (base + q - 1) % 2 == 0 && r[q - 1] == 0x5e {
                                Some(CallKind::Absolute)
                            } else {
                                None
                            };
                            let mut input = Input::Unresolved;
                            if call.is_some() {
                                if q >= 7
                                    && r[q - 7..q - 5] == [0x79, shape.register]
                                    && r[q - 3..q - 1]
                                        == [0x0d, if shape.register == 0 { 0x18 } else { 0x29 }]
                                {
                                    input = Input::ContiguousImmediate(u16::from_be_bytes([
                                        r[q - 5],
                                        r[q - 4],
                                    ]));
                                } else if q >= 5 && r[q - 5..q - 3] == [0x79, shape.register] {
                                    input = Input::ContiguousImmediate(u16::from_be_bytes([
                                        r[q - 3],
                                        r[q - 2],
                                    ]));
                                }
                            }
                            if let Some(c) = contracts
                                .iter()
                                .find(|c| base + q >= c.range.0 && base + q + 3 <= c.range.1)
                            {
                                input = c.input.clone();
                            }
                            references.push(ReferenceEvidence {
                                reference: Reference::Stored(base + q),
                                call,
                                input,
                            });
                        }
                        for q in (base & 1..r.len()).step_by(2) {
                            let b = &r[q..];
                            let encoding = if b.len() >= 2 && b[0] == 0x55 {
                                Some((CallKind::Relative8, 2, i64::from(b[1] as i8)))
                            } else if b.len() >= 4 && b[..2] == [0x5c, 0] {
                                Some((
                                    CallKind::Relative16,
                                    4,
                                    i64::from(i16::from_be_bytes([b[2], b[3]])),
                                ))
                            } else {
                                None
                            };
                            if let Some((kind, n, disp)) = encoding {
                                if 0x410000i64 + (base + q + n) as i64 + disp == i64::from(target) {
                                    references.push(ReferenceEvidence {
                                        reference: Reference::Stored(base + q),
                                        call: Some(kind),
                                        input: Input::Unresolved,
                                    });
                                }
                            }
                        }
                    }
                    for (stream, r) in regions.expanded.iter().enumerate() {
                        for (offset, b) in r.windows(3).enumerate() {
                            if b == &target.to_be_bytes()[1..] {
                                references.push(ReferenceEvidence {
                                    reference: Reference::Expanded { stream, offset },
                                    call: None,
                                    input: Input::Unresolved,
                                });
                            }
                        }
                    }
                    result.push(Producer {
                        offset,
                        end: offset + bytes.len(),
                        argument_register: shape.register,
                        count: block.ram_base + 128,
                        storage: block.ram_base + 130,
                        overflow_callees,
                        diagnostic_sources,
                        references,
                        input_contracts: contracts,
                    });
                }
            }
        }
    }
    Observation::Known(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn producer(shape: &Shape, base: u32) -> Vec<u8> {
        let mut bytes = shape.bytes.to_vec();
        for &(p, n, g) in shape.relocations {
            let value = if g == shape.count {
                base + 128
            } else if g == shape.storage {
                base + 130
            } else {
                0x500000 + g as u32 * 0x100
            };
            bytes[p..p + n].copy_from_slice(&value.to_be_bytes()[4 - n..]);
        }
        bytes
    }
    #[test]
    fn entire_producer_and_repeated_count_storage_relationship_are_required() {
        for shape in PRODUCERS {
            let mut bytes = producer(shape, 0xa01000);
            assert!(shape.bind(&bytes, 0xa01000).is_some());
            for i in 0..bytes.len() {
                if shape
                    .relocations
                    .iter()
                    .any(|&(p, n, _)| (p..p + n).contains(&i))
                {
                    continue;
                }
                bytes[i] ^= 1;
                assert!(shape.bind(&bytes, 0xa01000).is_none(), "scalar {i}");
                bytes[i] ^= 1;
            }
            for &(p, n, g) in shape.relocations {
                if g != shape.count && g != shape.storage {
                    continue;
                }
                bytes[p + n - 1] ^= 1;
                assert!(
                    shape.bind(&bytes, 0xa01000).is_none(),
                    "RAM relationship {p}"
                );
                bytes[p + n - 1] ^= 1;
            }
            // Diagnostic source relocation is accepted and returned explicitly.
            for &g in shape.sources {
                let &(p, n, _) = shape.relocations.iter().find(|r| r.2 == g).unwrap();
                bytes[p + n - 1] ^= 1;
                let (_, sources) = shape.bind(&bytes, 0xa01000).unwrap();
                assert!(sources.contains(&read(&bytes, p, n)));
                bytes[p + n - 1] ^= 1;
            }
        }
    }
    #[test]
    fn clear_requires_queue_coverage_and_both_complete_callees() {
        let mut raw = alloc::vec![0xff;0x5000];
        crate::image::layout::install_test_layout(&mut raw, 0x1000);
        let setup = &[
            0x7a, 0, 0, 0xa0, 0x10, 0, 0x7a, 1, 0, 0xa0, 0x20, 0, 0x19, 0x22, 0x5d, 0x30,
        ];
        raw[0x2000..0x2010].copy_from_slice(setup);
        let leaf = &[
            0x6d, 0xf4, 0x0d, 0x24, 0x0f, 0x92, 0x1a, 0x82, 0x0d, 0x41, 0x5e, 0x41, 0x40, 0, 0x6d,
            0x74, 0x54, 0x70,
        ];
        raw[0x3000..0x3012].copy_from_slice(leaf);
        raw[0x4000..0x4000 + cache_writers::MEMSET.len()].copy_from_slice(cache_writers::MEMSET);
        assert_eq!(initial_zero_candidates(&raw, 0xa01000), alloc::vec![0x200e]);
        let proof = bind_initial_zero(&raw, 0xa01000, 0x200e, 0x413000).unwrap();
        assert_eq!((proof.count, proof.storage), (0xa01080, 0xa01082));
        assert!(bind_initial_zero(&raw, 0xa01f80, 0x200e, 0x413000).is_none());
        for i in 0..leaf.len() {
            raw[0x3000 + i] ^= 1;
            assert!(
                bind_initial_zero(&raw, 0xa01000, 0x200e, 0x413000).is_none(),
                "clear instruction/callee {i}"
            );
            raw[0x3000 + i] ^= 1;
        }
        raw[0x200f] = 0x40;
        assert_eq!(
            bind_initial_zero(&raw, 0xa01000, 0x200e, 0x413000)
                .unwrap()
                .target_register,
            4
        );
        raw[0x4000] ^= 1;
        assert!(bind_initial_zero(&raw, 0xa01000, 0x200e, 0x413000).is_none());
    }
    #[test]
    fn scalar_request_and_record_index_semantics_cannot_relocate() {
        for shape in SEMANTICS {
            let mut bytes = shape.bytes.to_vec();
            for &(p, n, g) in shape.relocations {
                let value = 0x1000 + g as u32 * 0x100;
                bytes[p..p + n].copy_from_slice(&value.to_be_bytes()[4 - n..]);
            }
            assert!(shape.bind(&bytes).is_some());
            for i in 0..bytes.len() {
                if shape
                    .relocations
                    .iter()
                    .any(|&(p, n, _)| (p..p + n).contains(&i))
                    || shape.branches.iter().any(|&(p, n)| (p..p + n).contains(&i))
                {
                    continue;
                }
                bytes[i] ^= 1;
                assert!(shape.bind(&bytes).is_none(), "scalar {i}");
                bytes[i] ^= 1;
            }
        }
    }
}
