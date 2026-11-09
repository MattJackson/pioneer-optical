//! Exact native facts retained when no startup comparison is recognized.
//!
//! These facts explain a miss; they never establish absence of a startup
//! requirement. A word read without a recognized comparison, or no read at
//! all, still leaves the joined startup-path obligation open.
use crate::image::layout::{self, H8ReaderComponent, Observation, Unresolved};
use alloc::vec::Vec;

/// Bound getter owner, entry and index register, or why it is unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Getter {
    /// Complete native reader graph bound in this component.
    Bound(H8ReaderComponent, u32, u8),
    /// No complete reader is bound.
    Unbound(Unresolved),
    /// Native reader candidates conflict.
    Conflicting,
}

/// Native observations behind a stored-code miss of the 0x009F comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Miss {
    /// Getter evidence from the Normal and its supplied Kernel.
    pub getter: Getter,
    /// A recognized loader-flag comparison of a different word, if any.
    pub other_parameter: Option<super::Requirement>,
    /// CPU addresses of stored immediate 0x009F loads bound to an explicit
    /// call of the getter (or of the required resident entry). These are reads
    /// only: no comparison with a loader-flag mismatch arm follows them.
    pub reads: Vec<u32>,
    /// CPU addresses of stored wrappers of Kernel loader-flag service 0x400A1A.
    pub loader_flag_wrappers: Vec<u32>,
}

/// Describe why stored Normal code has no recognized 0x009F comparison.
/// `None` when stored regions are unavailable or a 0x009F comparison (or a
/// conflict) was recognized, so the miss is elsewhere.
pub fn inspect(normal: &[u8], kernel: Option<&[u8]>) -> Option<Miss> {
    let regions = crate::image::regions(normal)?;
    let mut stored = alloc::vec![0xff; normal.len()];
    for region in regions.stored {
        let start = region.as_ptr() as usize - normal.as_ptr() as usize;
        stored[start..start + region.len()].copy_from_slice(region);
    }
    let other_parameter = match super::discover(&stored) {
        Ok(None) => None,
        Ok(Some(r)) if r.parameter != 0x9f => Some(r),
        _ => return None,
    };
    let getter = match layout::discover_h8_reader(normal, kernel) {
        Observation::Known(e) => Getter::Bound(e.component, e.getter, e.argument_register),
        Observation::Unresolved(reason) => Getter::Unbound(reason),
        Observation::Conflicting => Getter::Conflicting,
    };
    // A required resident entry is the exact paired A4/A5 call target.
    let entry = match getter {
        Getter::Bound(_, entry, register) => Some((entry, register)),
        Getter::Unbound(Unresolved::ResidentCodeRequired(entry)) => Some((entry, 0)),
        _ => None,
    };
    let mut reads = Vec::new();
    let mut loader_flag_wrappers = Vec::new();
    for at in (0..stored.len().saturating_sub(5)).step_by(2) {
        let w = &stored[at..at + 6];
        if w == [0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70] {
            loader_flag_wrappers.push(super::BASE as u32 + at as u32);
        }
        let Some((entry, register)) = entry else {
            continue;
        };
        if w[..4] == [0x79, register, 0, 0x9f]
            && super::getter_call(&stored, at).is_some_and(|(g, _)| g == entry as usize)
        {
            reads.push(super::BASE as u32 + at as u32);
        }
    }
    Some(Miss {
        getter,
        other_parameter,
        reads,
        loader_flag_wrappers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // SAT 8600 BDW-PR1CPB-style startup slot (515b9fa7…, 0x45f66c): the word is
    // read and the next callee overwrites R0; no comparison or loader-flag arm.
    const READ_ONLY: &[u8] = &[
        0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x7a, 1, 0, 0x45, 0xf2, 0x4c, 1, 0, 0x6b, 0xa1, 0,
        0, 0x11, 0x46,
    ];

    fn normal() -> Vec<u8> {
        let mut normal = alloc::vec![0xff; 0x2000];
        layout::install_test_layout(&mut normal, 0x1000);
        normal
    }

    #[test]
    fn read_without_comparison_is_retained_as_a_read_only_fact() {
        let mut normal = normal();
        normal[0x80..0x80 + READ_ONLY.len()].copy_from_slice(READ_ONLY);
        normal[0x1800..0x1806].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        let miss = inspect(&normal, None).unwrap();
        assert_eq!(
            miss.getter,
            Getter::Bound(H8ReaderComponent::Normal, 0x411000, 0)
        );
        assert_eq!(miss.reads, alloc::vec![0x410080]);
        assert_eq!(miss.loader_flag_wrappers, alloc::vec![0x411800]);
        assert_eq!(miss.other_parameter, None);
        // Remains a miss: no known selection is made from a bare read.
        assert!(!matches!(
            super::super::bound_selection(&normal),
            Observation::Known(_)
        ));
        // A different index register or callee is not a read of this getter.
        normal[0x81] = 1;
        assert!(inspect(&normal, None).unwrap().reads.is_empty());
        normal[0x81] = 0;
        normal[0x86] = 0x20;
        assert!(inspect(&normal, None).unwrap().reads.is_empty());
    }

    #[test]
    fn empty_slot_and_recognized_comparison_are_distinguished() {
        let normal = normal();
        let miss = inspect(&normal, None).unwrap();
        assert!(miss.reads.is_empty() && miss.loader_flag_wrappers.is_empty());
        let mut gated = normal;
        gated[0x80..0x94].copy_from_slice(&[
            0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
            0x41, 0x18, 0,
        ]);
        gated[0x1800..0x1806].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        assert_eq!(inspect(&gated, None), None);
    }
}
