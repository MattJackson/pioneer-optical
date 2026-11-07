//! Exact SAT1 local rejection-predicate preservation for two native forms.
//!
//! Equal entry registers, stack, every read memory byte and related opaque
//! callee effects imply equal branches, ordered stores/calls and exits. Root
//! receipts bind call locations, not callee returns or upstream input equality.
//! This is not global acceptance, absence of 009F dependencies or host READY.
use super::{legacy_aliases, legacy_kernel::KernelBoundary, legacy_shapes};
use crate::image::layout::{self, H8ReaderComponent, H8ReaderEvidence, Observation};
use alloc::vec::Vec;
use core::ops::Range;

pub use super::legacy_aliases::AliasExclusion;

pub(super) struct Shape {
    pub offset: usize,
    pub packed: Range<usize>,
}
pub(super) struct Owner {
    pub entry: usize,
    pub end: usize,
    pub instructions: usize,
}
pub(super) struct Profile {
    pub name: &'static str,
    pub shapes: &'static [Shape],
    pub owners: &'static [Owner],
    pub owner_spans: &'static [(usize, usize)],
    pub predicates: &'static [(usize, usize)],
    pub references: &'static [(usize, u32)],
    pub exclusions: &'static [(usize, u32, usize, usize)],
    pub flags: &'static [usize],
    pub transfers: &'static [usize],
    pub length: usize,
    pub kernel_hash: [u8; 32],
    pub descriptor: usize,
}

/// A separately tagged, paired local-predicate contract. Its private authority
/// can only be constructed by complete discovery on the supplied components.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyPredicateCertificate {
    form: &'static str,
    reader: H8ReaderEvidence,
    bank: crate::startup::bank::LegacyPredicateBank,
    kernel_boundary: KernelBoundary,
    protected: Vec<Range<usize>>,
    exclusions: Vec<AliasExclusion>,
    incoming_refs: Vec<(usize, u32)>,
    absolute_byte_references: Vec<usize>,
}

impl LegacyPredicateCertificate {
    /// Every held native instruction, table, string, argument and header span.
    /// Normal's ordinary checksum word at 0x10 is owned by integrity repair.
    pub fn protected(&self) -> &[Range<usize>] {
        &self.protected
    }

    /// Complete Normal-owned reader; equality of layouts remains independently
    /// required between installed and incoming preservation profiles.
    pub fn reader(&self) -> &H8ReaderEvidence {
        &self.reader
    }

    /// Exact occurrence/target ownership exclusions, with no range wildcard.
    pub fn exclusions(&self) -> &[AliasExclusion] {
        &self.exclusions
    }

    /// Immutable resident authority and actual final header relationship.
    pub fn accepts_kernel(&self, normal: &[u8], kernel: &[u8]) -> bool {
        self.kernel_boundary.accepts(normal, kernel)
            && legacy_shapes::PROFILES
                .iter()
                .find(|p| p.name == self.form)
                .is_some_and(|p| legacy_aliases::closed(normal, kernel, p))
    }

    /// Structural preservation while composed Normal may await checksum repair.
    pub fn preserves(&self, original: &[u8], normal: &[u8], kernel: &[u8]) -> bool {
        original.len() == normal.len()
            && self
                .protected
                .iter()
                .all(|r| original.get(r.clone()) == normal.get(r.clone()))
            && discover(normal, kernel).as_ref() == Some(self)
    }

    /// Call on the actual authenticated paired decode after integrity repair.
    /// This verifies native sums; it does not authenticate an envelope itself.
    pub fn final_integrity(&self, normal: &[u8], kernel: &[u8]) -> bool {
        self.kernel_boundary.final_integrity(normal, kernel)
            && discover(normal, kernel).as_ref() == Some(self)
    }
}

/// Bind the exact two supported native compiler forms. No model-name test,
/// whole-Normal hash, modern wildcard, live word or persistent action is used.
/// Missing/replaced Kernel, resident readers and new incoming entries refuse.
pub fn discover(normal: &[u8], kernel: &[u8]) -> Option<LegacyPredicateCertificate> {
    let mut found = None;
    for profile in legacy_shapes::PROFILES {
        if normal.len() != profile.length
            || !profile.shapes.iter().all(|s| {
                normal.get(s.offset..s.offset + s.packed.len())
                    == Some(&legacy_shapes::BYTES[s.packed.clone()])
            })
        {
            continue;
        }
        let regions = crate::image::regions(normal)?;
        if !profile.shapes.iter().all(|s| {
            regions.stored.iter().any(|bytes| {
                let at = bytes.as_ptr() as usize - normal.as_ptr() as usize;
                at <= s.offset && s.offset + s.packed.len() <= at + bytes.len()
            })
        }) {
            return None;
        }
        let kernel_boundary = KernelBoundary::bind(normal, kernel, profile)?;
        let Observation::Known(reader) = layout::discover_h8_reader(normal, None) else {
            return None;
        };
        if reader.component != H8ReaderComponent::Normal {
            return None;
        }
        let (bank, selection) = profile.predicates[0];
        let bank = crate::startup::bank::legacy_predicate_witness(normal, bank, selection)?;
        if !profile
            .owners
            .iter()
            .all(|o| legacy_aliases::complete_owner(normal, o, profile))
            || !legacy_aliases::closed(normal, kernel, profile)
            || !legacy_aliases::flags(normal, profile)
            || !legacy_aliases::no_wide_flags(kernel)
            || !write_buffer(normal, profile)
        {
            return None;
        }
        let certificate = LegacyPredicateCertificate {
            form: profile.name,
            reader,
            bank,
            kernel_boundary,
            protected: profile
                .shapes
                .iter()
                .map(|s| s.offset..s.offset + s.packed.len())
                .collect(),
            exclusions: legacy_aliases::exclusions(profile),
            incoming_refs: profile.references.to_vec(),
            absolute_byte_references: profile.flags.to_vec(),
        };
        if found.replace(certificate).is_some() {
            return None;
        }
    }
    found
}

fn write_buffer(normal: &[u8], profile: &Profile) -> bool {
    // The shared binder's conservative raw-literal scan lacks operand owners.
    // Its census view omits only the exact occurrences already held by complete
    // native owner receipts. Actual callback bytes and all registry/initializer
    // candidates remain original; no modified firmware is emitted or executed.
    let mut census = normal.to_vec();
    let &(entry, end) = profile.predicates.last().unwrap();
    for &(at, target, _, _) in profile.exclusions {
        if (0x410000 + entry as u32..0x410000 + end as u32).contains(&target) {
            census[at] = 0xff;
        }
    }
    let sink = if profile.name == "w26" {
        0x1b20e0
    } else {
        0x1b50b0
    };
    super::sinks::write_buffer(&census, sink).is_some_and(|host| {
        host.instructions.len() == 682
            && host.instructions.first().is_some_and(|r| r.start == entry)
            && host.instructions.iter().chain(&host.tables).all(|span| {
                profile
                    .shapes
                    .iter()
                    .any(|s| s.offset <= span.start && span.end <= s.offset + s.packed.len())
            })
    })
}

#[cfg(all(test, feature = "envelope"))]
#[path = "legacy_tests.rs"]
mod tests;
