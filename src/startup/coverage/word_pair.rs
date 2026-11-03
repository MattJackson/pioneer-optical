//! Two sequential parameter reads converted to four output bytes. Caller
//! domains remain local evidence; arbitrary computed aliases are not excluded.
use super::{
    argument::{self, Domain},
    CallKind,
};
use crate::image::layout::{Observation, Unresolved};
use alloc::{collections::BTreeMap, vec::Vec};
const BODY: &[u8] = &[
    0x01, 0x20, 0x6d, 0xf4, 0x0d, 0x1e, 0x0f, 0x85, 0x0d, 0x10, 0x5e, 0, 0, 0, 0x0d, 0x06, 0x0b,
    0x5e, 0x0d, 0xe0, 0x5e, 0, 0, 0, 0x0d, 0x04, 0x0c, 0x68, 0x55, 0x20, 0x68, 0xd8, 0x0c, 0xe8,
    0x55, 0x1a, 0x6e, 0xd8, 0x00, 0x01, 0x0c, 0x48, 0x55, 0x12, 0x6e, 0xd8, 0x00, 0x02, 0x0c, 0xc8,
    0x55, 0x0a, 0x6e, 0xd8, 0x00, 0x03, 0x01, 0x20, 0x6d, 0x76, 0x54, 0x70,
];
/// A direct caller's local first-index domain. The second index wraps at 16 bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    /// Decoded Normal offset of the call.
    pub offset: usize,
    /// Native call encoding.
    pub kind: CallKind,
    /// First instruction traced before the call.
    pub suffix_start: usize,
    /// Local first-index domain, not an all-path assertion.
    pub first_index: Domain,
}
/// One complete function and its instruction-shaped incoming references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// Decoded Normal entry offset.
    pub offset: usize,
    /// Byte-formatting helper called four times; requires a separate contract.
    pub formatter: usize,
    /// Direct/relative callers and their local argument observations.
    pub callers: Vec<Caller>,
    /// Literal address loads and absolute jumps require separate analysis.
    pub other_references: Vec<usize>,
}
fn matches(bytes: &[u8], getter: u32) -> bool {
    bytes.len() == BODY.len()
        && bytes.iter().zip(BODY).enumerate().all(|(i, (a, b))| {
            if (11..14).contains(&i) {
                *a == getter.to_be_bytes()[i - 10]
            } else if (21..24).contains(&i) {
                *a == getter.to_be_bytes()[i - 20]
            } else {
                a == b
            }
        })
}
/// Recognize complete functions, including all four writes and both bound
/// getter calls. Unknown caller arguments and non-call references are retained.
pub fn discover(normal: &[u8]) -> Observation<Vec<Block>> {
    let refs = match super::references(normal) {
        Observation::Known(r) => r,
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    if refs.argument_register != 0 {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    }
    let regions = crate::image::regions(normal).expect("stored references");
    let mut result = Vec::new();
    for call in refs.calls.iter().filter(|c| c.kind == CallKind::Absolute) {
        let Some(at) = call.offset.checked_sub(10) else {
            continue;
        };
        let Some(bytes) = normal.get(at..at + BODY.len()) else {
            continue;
        };
        if !matches(bytes, refs.getter) {
            continue;
        }
        if !regions.stored.iter().any(|r| {
            let start = r.as_ptr() as usize - normal.as_ptr() as usize;
            at >= start && at + BODY.len() <= start + r.len()
        }) {
            continue;
        }
        result.push(Block {
            offset: at,
            formatter: at + BODY.len(),
            callers: Vec::new(),
            other_references: Vec::new(),
        });
    }
    let mut targets: BTreeMap<i64, Vec<usize>> = BTreeMap::new();
    for (i, block) in result.iter().enumerate() {
        targets
            .entry(0x410000 + block.offset as i64)
            .or_default()
            .push(i);
    }
    // The blocks examined for one decoded reference: only those entered there.
    let lookup = |target: i64| {
        let blocks = targets.get(&target).map_or(&[][..], Vec::as_slice);
        #[cfg(test)]
        tests::BLOCK_CHECKS.with(|c| c.set(c.get() + blocks.len()));
        blocks
    };
    for region in &regions.stored {
        let base = region.as_ptr() as usize - normal.as_ptr() as usize;
        for local in (base & 1..region.len()).step_by(2) {
            let bytes = &region[local..];
            let at = base + local;
            let absolute = |b: &[u8]| u32::from_be_bytes([0, b[1], b[2], b[3]]) as i64;
            let incoming = if bytes.len() >= 4 && bytes[0] == 0x5e {
                Some((CallKind::Absolute, absolute(bytes)))
            } else if bytes.len() >= 2 && bytes[0] == 0x55 {
                Some((
                    CallKind::Relative8,
                    0x410000 + at as i64 + 2 + i64::from(bytes[1] as i8),
                ))
            } else if bytes.len() >= 4 && bytes[..2] == [0x5c, 0] {
                Some((
                    CallKind::Relative16,
                    0x410000 + at as i64 + 4 + i64::from(i16::from_be_bytes([bytes[2], bytes[3]])),
                ))
            } else {
                None
            };
            let other = if bytes.len() >= 4 && bytes[0] == 0x5a {
                Some(absolute(bytes))
            } else if bytes.len() >= 6 && bytes[0] == 0x7a && bytes[1] <= 7 {
                Some(u32::from_be_bytes(bytes[2..6].try_into().unwrap()) as i64)
            } else {
                None
            };
            // Only blocks whose entry is the decoded target are updated, so
            // many functions cost one scan; per-block order is unchanged.
            if let Some((kind, target)) = incoming {
                let matched = lookup(target);
                if !matched.is_empty() {
                    let (start, domain) = argument::suffix(region, local, 1);
                    for &i in matched {
                        result[i].callers.push(Caller {
                            offset: at,
                            kind,
                            suffix_start: base + start,
                            first_index: domain,
                        });
                    }
                }
            }
            if let Some(target) = other {
                for &i in lookup(target) {
                    result[i].other_references.push(at);
                }
            }
        }
    }
    Observation::Known(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    std::thread_local! {
        pub(super) static BLOCK_CHECKS: Cell<usize> = const { Cell::new(0) };
    }
    fn fixture(copies: usize) -> Vec<u8> {
        let mut raw = alloc::vec![0xff; 0x6000];
        crate::image::layout::install_test_layout(&mut raw, 0x1000);
        for k in 0..copies {
            let at = 0x2000 + k * 0x40;
            raw[at..at + BODY.len()].copy_from_slice(BODY);
            raw[at + 11..at + 14].copy_from_slice(&[0x41, 0x10, 0]);
            raw[at + 21..at + 24].copy_from_slice(&[0x41, 0x10, 0]);
        }
        raw[0x80..0x88].copy_from_slice(&[0x79, 1, 0, 0x9e, 0x5e, 0x41, 0x20, 0]);
        raw
    }
    #[test]
    fn many_functions_share_one_reference_scan_with_unchanged_callers() {
        let checks = |copies| {
            let raw = fixture(copies);
            BLOCK_CHECKS.with(|c| c.set(0));
            let Observation::Known(found) = discover(&raw) else {
                panic!("fixture")
            };
            assert_eq!(found.len(), copies);
            assert_eq!(found[0].callers.len(), 1);
            assert!(found[1..].iter().all(|b| b.callers.is_empty()));
            BLOCK_CHECKS.with(Cell::get)
        };
        assert_eq!(checks(20), checks(1));
    }
    #[test]
    fn relative_callers_and_absolute_jumps_are_retained() {
        let mut raw = fixture(2);
        raw[0x1ff0..0x1ff2].copy_from_slice(&[0x55, 0x0e]);
        raw[0x2100..0x2104].copy_from_slice(&[0x5c, 0, 0xfe, 0xfc]);
        raw[0x2110..0x2114].copy_from_slice(&[0x5a, 0x41, 0x20, 0]);
        raw[0x2120..0x2126].copy_from_slice(&[0x7a, 3, 0, 0x41, 0x20, 0x40]);
        let Observation::Known(found) = discover(&raw) else {
            panic!("fixture")
        };
        let calls: Vec<_> = found[0]
            .callers
            .iter()
            .map(|c| (c.offset, c.kind))
            .collect();
        assert_eq!(
            calls,
            alloc::vec![
                (0x84, CallKind::Absolute),
                (0x1ff0, CallKind::Relative8),
                (0x2100, CallKind::Relative16)
            ]
        );
        assert_eq!(found[0].other_references, alloc::vec![0x2110]);
        assert!(found[1].callers.is_empty());
        assert_eq!(found[1].other_references, alloc::vec![0x2120]);
    }
    #[test]
    fn every_instruction_output_and_getter_target_is_bound() {
        let getter = 0x411000u32;
        let mut body = BODY.to_vec();
        body[11..14].copy_from_slice(&getter.to_be_bytes()[1..]);
        body[21..24].copy_from_slice(&getter.to_be_bytes()[1..]);
        assert!(matches(&body, getter));
        for i in 0..body.len() {
            body[i] ^= 1;
            assert!(!matches(&body, getter), "byte {i}");
            body[i] ^= 1;
        }
    }
    #[test]
    fn callers_near_009f_and_literal_aliases_are_retained() {
        let mut raw = alloc::vec![0xff;0x6000];
        crate::image::layout::install_test_layout(&mut raw, 0x1000);
        raw[0x2000..0x2000 + BODY.len()].copy_from_slice(BODY);
        raw[0x200b..0x200e].copy_from_slice(&[0x41, 0x10, 0]);
        raw[0x2015..0x2018].copy_from_slice(&[0x41, 0x10, 0]);
        raw[0x80..0x88].copy_from_slice(&[0x79, 1, 0, 0x9e, 0x5e, 0x41, 0x20, 0]);
        raw[0x90..0x96].copy_from_slice(&[0x7a, 5, 0, 0x41, 0x20, 0]);
        let Observation::Known(found) = discover(&raw) else {
            panic!("fixture")
        };
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].callers[0].first_index, Domain::Constant(0x9e));
        assert_eq!(found[0].other_references, alloc::vec![0x90]);
    }
}
