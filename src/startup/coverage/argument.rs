//! Local H8 argument suffixes. These describe straight-line dataflow only:
//! an incoming branch could bypass the suffix, so this is not an acceptance proof.
use crate::image::layout::Observation;
use alloc::vec::Vec;

/// Index domain established by a contiguous instruction suffix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    /// Exact word, including native wrapping additions.
    Constant(u16),
    /// Zero-extended byte plus an addend, modulo 65536.
    BytePlus {
        /// Word register holding the zero-extended byte.
        register: u8,
        /// Native word addition after zero-extension.
        addend: u16,
    },
    /// Unsupported instruction or the bounded trace ended before a definition.
    Unresolved {
        /// Register still needing a definition.
        register: u8,
        /// Additions already traced.
        addend: u16,
    },
}
/// A local suffix bound to one native getter call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Argument {
    /// First instruction of the recognized suffix, in decoded Normal offsets.
    pub start: usize,
    /// Getter call offset; the suffix ends here.
    pub call: usize,
    /// Local argument domain. Does not imply all incoming paths execute it.
    pub domain: Domain,
}
pub(super) fn suffix(bytes: &[u8], end: usize, mut register: u8) -> (usize, Domain) {
    let mut at = end;
    let mut addend = 0u16;
    for _ in 0..8 {
        if at >= 4 && bytes[at - 4..at - 2] == [0x79, register] {
            return (
                at - 4,
                Domain::Constant(
                    u16::from_be_bytes([bytes[at - 2], bytes[at - 1]]).wrapping_add(addend),
                ),
            );
        }
        if at >= 4 && bytes[at - 4..at - 2] == [0x79, 0x10 | register] {
            addend = addend.wrapping_add(u16::from_be_bytes([bytes[at - 2], bytes[at - 1]]));
            at -= 4;
            continue;
        }
        if at < 2 {
            break;
        }
        let word = &bytes[at - 2..at];
        if word == [0x19, register * 17] {
            return (at - 2, Domain::Constant(addend));
        }
        if word[0] == 0x0d && word[1] & 15 == register {
            register = word[1] >> 4;
            at -= 2;
            continue;
        }
        if word[0] == 0x0f && word[1] & 0x88 == 0x80 && word[1] & 7 != register & 7 {
            at -= 2;
            continue;
        }
        if word == [0x17, 0x50 | register] {
            return (at - 2, Domain::BytePlus { register, addend });
        }
        break;
    }
    (at, Domain::Unresolved { register, addend })
}
/// Whether `start..end` is a chain of decoded instructions of the region.
pub(super) fn decoded(anchors: &mut super::Anchors<'_>, start: usize, end: usize) -> bool {
    let mut at = end;
    while at > start {
        match anchors.previous(at) {
            Some(p) if p >= start => at = p,
            _ => return false,
        }
    }
    at == start
}
/// Trace each stored getter call back through at most eight known instructions.
/// Suffixes never cross stored-region boundaries, and each suffix instruction
/// must lie on the region's decoded boundary chain (see the module limits in
/// `startup::coverage`); operand bytes of a longer instruction leave the
/// domain unresolved. Unknown definitions remain unresolved; callers must
/// separately establish entry paths.
pub fn discover(normal: &[u8]) -> Observation<Vec<Argument>> {
    let (refs, regions) = match super::references_in(normal) {
        Observation::Known(r) => r,
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    let mut result = Vec::new();
    let mut anchors: Vec<_> = regions
        .stored
        .iter()
        .map(|r| super::Anchors::new(r, r.as_ptr() as usize - normal.as_ptr() as usize))
        .collect();
    for call in refs.calls {
        let (index, region) = regions
            .stored
            .iter()
            .enumerate()
            .find(|(_, r)| {
                let start = r.as_ptr() as usize - normal.as_ptr() as usize;
                call.offset >= start && call.offset < start + r.len()
            })
            .expect("stored reference");
        let base = region.as_ptr() as usize - normal.as_ptr() as usize;
        let end = call.offset - base;
        let (mut start, mut domain) = suffix(region, end, refs.argument_register);
        // Every suffix instruction must be a decoded instruction, never the
        // operand tail of a longer earlier one.
        if !matches!(domain, Domain::Unresolved { .. }) && !decoded(&mut anchors[index], start, end)
        {
            (start, domain) = (
                end,
                Domain::Unresolved {
                    register: refs.argument_register,
                    addend: 0,
                },
            );
        }
        result.push(Argument {
            start: base + start,
            call: call.offset,
            domain,
        });
    }
    Observation::Known(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discover_traces_calls_in_regions_after_a_compressed_stream() {
        use std::io::Write;
        let mut raw = alloc::vec![0xff; 0x8000];
        crate::image::layout::install_test_layout(&mut raw, 0x3000);
        raw[0x1000..0x1004].copy_from_slice(b"COMP");
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[7; 32]).unwrap();
        let compressed = encoder.finish().unwrap();
        raw[0x2000..0x2004].copy_from_slice(&32u32.to_be_bytes());
        raw[0x2004..0x2004 + compressed.len()].copy_from_slice(&compressed);
        let start = 0x412000u32;
        raw[0x1004..0x1008].copy_from_slice(&start.to_be_bytes());
        raw[0x1008..0x100c].copy_from_slice(&(start + compressed.len() as u32).to_be_bytes());
        raw[0x20fe..0x2100].copy_from_slice(&[0x54, 0x70]);
        raw[0x2100..0x2108].copy_from_slice(&[0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x30, 0]);
        let regions = crate::image::regions(&raw).unwrap();
        assert_eq!(regions.expanded.len(), 1);
        assert!(regions.stored.len() >= 2 && regions.stored[1].as_ptr() > raw[0x2000..].as_ptr());
        let Observation::Known(found) = discover(&raw) else {
            panic!("fixture")
        };
        assert_eq!(
            found,
            alloc::vec![Argument {
                start: 0x2100,
                call: 0x2104,
                domain: Domain::Constant(0x9f)
            }]
        );
        // MOV.W @H'54701900:32,R0 embeds an RTS-shaped word and ends in
        // SUB.W R0,R0's bytes; neither is an instruction boundary.
        raw[0x20fe..0x2104].copy_from_slice(&[0x6b, 0x20, 0x54, 0x70, 0x19, 0]);
        let Observation::Known(found) = discover(&raw) else {
            panic!("fixture")
        };
        assert!(
            matches!(found[0].domain, Domain::Unresolved { .. }),
            "{:?}",
            found[0]
        );
        raw[0x20fe..0x2100].copy_from_slice(&[0x54, 0x70]);
        // JSR @H'411900 ends in SUB.W R0,R0's bytes; R0 is the callee's result.
        raw[0x2100..0x2104].copy_from_slice(&[0x5e, 0x41, 0x19, 0]);
        let Observation::Known(found) = discover(&raw) else {
            panic!("fixture")
        };
        assert!(
            matches!(found[0].domain, Domain::Unresolved { .. }),
            "{:?}",
            found[0]
        );
    }
    #[test]
    fn moves_additions_and_word_overflow_preserve_native_semantics() {
        let bytes = [0x79, 3, 0xff, 0xff, 0x0d, 0x30, 0x79, 0x10, 0, 0xa0];
        assert_eq!(suffix(&bytes, bytes.len(), 0), (0, Domain::Constant(0x9f)));
        assert_eq!(
            suffix(&[0x19, 0x11, 0x79, 0x11, 0, 0xa0], 6, 1),
            (0, Domain::Constant(0xa0))
        );
        assert_eq!(
            suffix(&[0x17, 0x50, 0x79, 0x10, 0, 0xa0], 6, 0),
            (
                0,
                Domain::BytePlus {
                    register: 0,
                    addend: 0xa0
                }
            )
        );
        assert_eq!(
            suffix(&[0x79, 1, 0, 0x9f, 0x0f, 0xe0], 6, 1),
            (0, Domain::Constant(0x9f))
        );
    }
    #[test]
    fn calls_branches_aliasing_moves_and_unknown_instructions_stop_the_trace() {
        for tail in [
            &[0x5e, 0x41, 0, 0][..],
            &[0x40, 0],
            &[0x0f, 0xe1],
            &[0x0f, 0x61],
            &[0, 0],
        ] {
            let mut bytes = alloc::vec![0x79, 1, 0, 0x9f];
            bytes.extend_from_slice(tail);
            assert!(matches!(
                suffix(&bytes, bytes.len(), 1).1,
                Domain::Unresolved { .. }
            ));
        }
        assert!(matches!(suffix(&[], 0, 0).1, Domain::Unresolved { .. }));
        let mut bytes = alloc::vec![0x79, 0, 0, 0x9f];
        for _ in 0..8 {
            bytes.extend_from_slice(&[0x0f, 0xe1]);
        }
        assert!(matches!(
            suffix(&bytes, bytes.len(), 0).1,
            Domain::Unresolved { .. }
        ));
    }
}
