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
/// Trace each stored getter call back through at most eight known instructions.
/// Suffixes never cross stored-region boundaries or skip calls/branches. Unknown
/// definitions remain unresolved; callers must separately establish entry paths.
pub fn discover(normal: &[u8]) -> Observation<Vec<Argument>> {
    let refs = match super::references(normal) {
        Observation::Known(r) => r,
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    let regions = crate::image::regions(normal).expect("references validated regions");
    let mut result = Vec::new();
    for call in refs.calls {
        let region = regions
            .stored
            .iter()
            .find(|r| {
                let start = r.as_ptr() as usize - normal.as_ptr() as usize;
                call.offset >= start && call.offset < start + r.len()
            })
            .expect("stored reference");
        let base = region.as_ptr() as usize - normal.as_ptr() as usize;
        let (start, domain) = suffix(region, call.offset - base, refs.argument_register);
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
