//! Complete R1 paired-reader initialization graph. Saved-register restoration
//! is established on native normal-return paths. External allocator and final
//! initialization calls remain explicit dependencies for startup reachability.
use super::{cache_flow::Reference, CallKind};
use crate::image::layout::Observation;
use alloc::vec::Vec;
pub(super) struct Pattern {
    pub bytes: &'static [u8],
    pub masks: &'static [(usize, usize)],
}
impl Pattern {
    fn matches(&self, b: &[u8]) -> bool {
        b.len() == self.bytes.len()
            && b[..4] == self.bytes[..4]
            && b.iter().zip(self.bytes).enumerate().all(|(i, (a, c))| {
                a == c || self.masks.iter().any(|&(p, n)| (p..p + n).contains(&i))
            })
    }
}
/// Caller-supplied local byte-index observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    /// Decoded Normal call offset.
    pub offset: usize,
    /// Native call encoding.
    pub kind: CallKind,
    /// Both byte indices, with native wrapping; unknown arguments stay None.
    pub indices: Option<[u8; 2]>,
}
/// Native graph and its remaining call dependencies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Graph {
    /// Paired-reader entry offset.
    pub offset: usize,
    /// Proven cache-reader call offsets.
    pub reads: [usize; 2],
    /// Shared initializer called before each read.
    pub initializer: usize,
    /// Complete constructor saving/restoring ER3 through ER6.
    pub constructor: usize,
    /// Exact native byte-fill implementation used for all nine fills.
    pub fill: usize,
    /// Constructor allocator and final initialization routine CPU addresses.
    /// Their startup behavior is a separate proof obligation.
    pub external_calls: [u32; 2],
    /// Initializer's runtime flag word address.
    pub flag: u32,
    /// Initializer's object address, exactly flag+2.
    pub object: u32,
    /// Incoming caller observations.
    pub callers: Vec<Caller>,
    /// Literal aliases and jumps not discharged by caller observations.
    pub other_references: Vec<Reference>,
}
fn value(b: &[u8], at: usize, n: usize) -> u32 {
    b[at..at + n]
        .iter()
        .fold(0, |v, b| (v << 8) | u32::from(*b))
}
fn native(normal: &[u8], address: u32, len: usize) -> Option<(usize, &[u8])> {
    let at = (address as usize).checked_sub(0x410000)?;
    if at & 1 != 0 {
        return None;
    }
    let end = at.checked_add(len)?;
    let regions = crate::image::regions(normal)?;
    if !regions.stored.iter().any(|r| {
        let start = r.as_ptr() as usize - normal.as_ptr() as usize;
        at >= start && end <= start + r.len()
    }) {
        return None;
    }
    Some((at, normal.get(at..end)?))
}
fn bind(normal: &[u8], at: usize, accessor: u32) -> Option<Graph> {
    use super::r1_pair_shapes::{CONSTRUCTOR, FILL, INITIALIZER, PAIR};
    let b = normal.get(at..at.checked_add(PAIR.bytes.len())?)?;
    if !PAIR.matches(b) {
        return None;
    }
    if value(b, 21, 3) != accessor || value(b, 37, 3) != accessor {
        return None;
    }
    let init = value(b, 13, 3);
    if value(b, 29, 3) != init {
        return None;
    }
    let (initializer, i) = native(normal, init, INITIALIZER.bytes.len())?;
    if !INITIALIZER.matches(i) {
        return None;
    }
    let object = value(i, 6, 4);
    let flag = value(i, 12, 4);
    if flag & 1 != 0 || flag.checked_add(2)? != object || value(i, 24, 4) != flag {
        return None;
    }
    let (constructor, c) = native(normal, value(i, 31, 3), CONSTRUCTOR.bytes.len())?;
    if !CONSTRUCTOR.matches(c) {
        return None;
    }
    let (fill, f) = native(normal, value(c, 46, 4), FILL.len())?;
    if f != FILL {
        return None;
    }
    let external_calls = [value(c, 17, 3), value(c, 179, 3)];
    for target in external_calls {
        native(normal, target, 2)?;
    }
    Some(Graph {
        offset: at,
        reads: [at + 20, at + 36],
        initializer,
        constructor,
        fill,
        external_calls,
        flag,
        object,
        callers: Vec::new(),
        other_references: Vec::new(),
    })
}
/// Bind complete pair/initializer/constructor/fill code and all native incoming
/// call observations. This is a normal-return register contract, not global
/// startup acceptance; external call dependencies are retained in each graph.
pub fn discover(normal: &[u8]) -> Observation<Vec<Graph>> {
    let caches = match super::cache::discover(normal) {
        Observation::Known(v) => v,
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    let regions = crate::image::regions(normal).expect("bound cache regions");
    let mut graphs = Vec::new();
    for cache in caches {
        for accessor in cache.accessors.iter().filter(|a| a.argument_register == 1) {
            for region in &regions.stored {
                let base = region.as_ptr() as usize - normal.as_ptr() as usize;
                for local in (base & 1..region.len()).step_by(2) {
                    if local + super::r1_pair_shapes::PAIR.bytes.len() > region.len() {
                        continue;
                    }
                    if let Some(graph) =
                        bind(normal, base + local, 0x410000 + accessor.offset as u32)
                    {
                        graphs.push(graph);
                    }
                }
            }
        }
    }
    for graph in &mut graphs {
        let target = 0x410000 + graph.offset as i64;
        for region in &regions.stored {
            let base = region.as_ptr() as usize - normal.as_ptr() as usize;
            for local in (base & 1..region.len()).step_by(2) {
                let b = &region[local..];
                let at = base + local;
                let call = if b.len() >= 4 && b[0] == 0x5e {
                    Some((CallKind::Absolute, value(b, 1, 3) as i64))
                } else if b.len() >= 2 && b[0] == 0x55 {
                    Some((
                        CallKind::Relative8,
                        0x410000 + at as i64 + 2 + i64::from(b[1] as i8),
                    ))
                } else if b.len() >= 4 && b[..2] == [0x5c, 0] {
                    Some((
                        CallKind::Relative16,
                        0x410000 + at as i64 + 4 + i64::from(i16::from_be_bytes([b[2], b[3]])),
                    ))
                } else {
                    None
                };
                if let Some((kind, _)) = call.filter(|(_, t)| *t == target) {
                    let index = if (local >= 4 && region[local - 4..local - 2] == [0x79, 1])
                        || (local >= 2 && region[local - 2] == 0xf9)
                    {
                        Some(region[local - 1])
                    } else {
                        None
                    };
                    graph.callers.push(Caller {
                        offset: at,
                        kind,
                        indices: index.map(|i| [i, i.wrapping_add(1)]),
                    });
                }
                if b.len() >= 4 && b[0] == 0x5a && i64::from(value(b, 1, 3)) == target {
                    graph.other_references.push(Reference::Stored(at));
                }
            }
            for (i, b) in region.windows(4).enumerate() {
                if b == (target as u32).to_be_bytes() {
                    graph.other_references.push(Reference::Stored(base + i));
                }
            }
        }
        for (stream, b) in regions.expanded.iter().enumerate() {
            for (offset, b) in b.windows(4).enumerate() {
                if b == (target as u32).to_be_bytes() {
                    graph
                        .other_references
                        .push(Reference::Expanded { stream, offset });
                }
            }
        }
    }
    Observation::Known(graphs)
}

#[cfg(test)]
mod tests {
    use super::super::r1_pair_shapes::{CONSTRUCTOR, FILL, INITIALIZER, PAIR};
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut raw = alloc::vec![0xff;0x7000];
        for (at, p) in [
            (0x1000, &PAIR),
            (0x2000, &INITIALIZER),
            (0x3000, &CONSTRUCTOR),
        ] {
            raw[at..at + p.bytes.len()].copy_from_slice(p.bytes);
        }
        raw[0x4000..0x4000 + FILL.len()].copy_from_slice(FILL);
        for p in [13, 29] {
            raw[0x1000 + p..0x1003 + p].copy_from_slice(&[0x41, 0x20, 0]);
        }
        for p in [21, 37] {
            raw[0x1000 + p..0x1003 + p].copy_from_slice(&[0x41, 0x60, 0]);
        }
        raw[0x2006..0x200a].copy_from_slice(&0x1802u32.to_be_bytes());
        for p in [12, 24] {
            raw[0x2000 + p..0x2004 + p].copy_from_slice(&0x1800u32.to_be_bytes());
        }
        raw[0x201f..0x2022].copy_from_slice(&[0x41, 0x30, 0]);
        raw[0x302e..0x3032].copy_from_slice(&0x414000u32.to_be_bytes());
        raw[0x3011..0x3014].copy_from_slice(&[0x41, 0x50, 0]);
        raw[0x30b3..0x30b6].copy_from_slice(&[0x41, 0x51, 0]);
        raw
    }
    #[test]
    fn every_fixed_instruction_in_the_initialization_graph_is_required() {
        let mut raw = fixture();
        assert!(bind(&raw, 0x1000, 0x416000).is_some());
        for (at, p) in [
            (0x1000, &PAIR),
            (0x2000, &INITIALIZER),
            (0x3000, &CONSTRUCTOR),
        ] {
            for i in 0..p.bytes.len() {
                if p.masks.iter().any(|&(s, n)| (s..s + n).contains(&i)) {
                    continue;
                }
                raw[at + i] ^= 1;
                assert!(bind(&raw, 0x1000, 0x416000).is_none(), "{at:x}+{i}");
                raw[at + i] ^= 1;
            }
        }
        for i in 0..FILL.len() {
            raw[0x4000 + i] ^= 1;
            assert!(bind(&raw, 0x1000, 0x416000).is_none());
            raw[0x4000 + i] ^= 1;
        }
    }
    #[test]
    fn both_calls_flag_addresses_and_constructor_dependencies_must_agree() {
        let raw = fixture();
        for p in [
            0x100f, 0x1017, 0x101f, 0x1027, 0x2009, 0x200f, 0x201b, 0x2021, 0x3031,
        ] {
            let mut changed = raw.clone();
            changed[p] ^= 2;
            assert!(bind(&changed, 0x1000, 0x416000).is_none(), "{p:x}");
        }
        let mut changed = raw.clone();
        changed[0x3011..0x3014].copy_from_slice(&[0x40, 0, 0]);
        assert!(bind(&changed, 0x1000, 0x416000).is_none());
    }
}
