//! Complete R1 paired-reader initialization graph. Saved-register restoration
//! is established on native normal-return paths. External allocator and final
//! initialization calls remain explicit dependencies for startup reachability.
use super::{cache_flow::Reference, CallKind};
use crate::image::layout::Observation;
use alloc::{collections::BTreeMap, vec::Vec};
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
/// `stored` must be `image::regions(normal)?.stored`, decoded once by the caller.
fn native<'a>(
    normal: &'a [u8],
    stored: &[&[u8]],
    address: u32,
    len: usize,
) -> Option<(usize, &'a [u8])> {
    let at = (address as usize).checked_sub(0x410000)?;
    if at & 1 != 0 {
        return None;
    }
    let end = at.checked_add(len)?;
    if !stored.iter().any(|r| {
        let start = r.as_ptr() as usize - normal.as_ptr() as usize;
        at >= start && end <= start + r.len()
    }) {
        return None;
    }
    Some((at, normal.get(at..end)?))
}
fn bind(normal: &[u8], stored: &[&[u8]], at: usize, accessor: u32) -> Option<Graph> {
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
    let (initializer, i) = native(normal, stored, init, INITIALIZER.bytes.len())?;
    if !INITIALIZER.matches(i) {
        return None;
    }
    let object = value(i, 6, 4);
    let flag = value(i, 12, 4);
    if flag & 1 != 0 || flag.checked_add(2)? != object || value(i, 24, 4) != flag {
        return None;
    }
    let (constructor, c) = native(normal, stored, value(i, 31, 3), CONSTRUCTOR.bytes.len())?;
    if !CONSTRUCTOR.matches(c) {
        return None;
    }
    let (fill, f) = native(normal, stored, value(c, 46, 4), FILL.len())?;
    if f != FILL {
        return None;
    }
    let external_calls = [value(c, 17, 3), value(c, 179, 3)];
    for target in external_calls {
        native(normal, stored, target, 2)?;
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
/// R1L immediate loaded by the instruction directly before the aligned call at
/// `local` (`MOV.W #imm,R1` or `MOV.B #imm,R1L`). The load must be the decoded
/// instruction ending at the call on the region's boundary chain
/// ([`super::Anchors`]); operand bytes F9 or 79 01 of a longer instruction or
/// a call off that chain leave the index unknown.
fn caller_index(anchors: &mut super::Anchors<'_>, region: &[u8], local: usize) -> Option<u8> {
    match anchors.previous(local)? {
        load if load + 4 == local && region[load..load + 2] == [0x79, 1] => Some(region[load + 3]),
        load if load + 2 == local && region[load] == 0xf9 => Some(region[load + 1]),
        _ => None,
    }
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
    use super::r1_pair_shapes::PAIR;
    let accessors: Vec<u32> = caches
        .iter()
        .flat_map(|cache| cache.accessors.iter())
        .filter(|a| a.argument_register == 1)
        .map(|a| 0x410000 + a.offset as u32)
        .collect();
    // One PAIR scan for every accessor; graphs stay in accessor-major order.
    let mut found: Vec<Vec<Graph>> = accessors.iter().map(|_| Vec::new()).collect();
    if !accessors.is_empty() {
        for region in &regions.stored {
            let base = region.as_ptr() as usize - normal.as_ptr() as usize;
            for local in (base & 1..region.len()).step_by(2) {
                let Some(b) = region.get(local..local + PAIR.bytes.len()) else {
                    continue;
                };
                if !PAIR.matches(b) {
                    continue;
                }
                let accessor = value(b, 21, 3);
                for (k, _) in accessors.iter().enumerate().filter(|(_, &a)| a == accessor) {
                    if let Some(graph) = bind(normal, &regions.stored, base + local, accessor) {
                        found[k].push(graph);
                    }
                }
            }
        }
    }
    let mut graphs: Vec<Graph> = found.into_iter().flatten().collect();
    // One scan for every graph: each call, jump and literal target is looked
    // up, so many wrappers cost O(image log graphs), in the same order.
    let mut targets: BTreeMap<i64, Vec<usize>> = BTreeMap::new();
    for (i, graph) in graphs.iter().enumerate() {
        targets
            .entry(0x410000 + graph.offset as i64)
            .or_default()
            .push(i);
    }
    let lookup = |target: i64| targets.get(&target).map_or(&[][..], Vec::as_slice);
    if graphs.is_empty() {
        return Observation::Known(graphs);
    }
    for region in &regions.stored {
        #[cfg(test)]
        tests::REGION_SCANS.with(|c| c.set(c.get() + 1));
        let base = region.as_ptr() as usize - normal.as_ptr() as usize;
        let mut anchors = super::Anchors::new(region, base);
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
            if let Some((kind, target)) = call {
                let found = lookup(target);
                if !found.is_empty() {
                    let index = caller_index(&mut anchors, region, local);
                    for &i in found {
                        graphs[i].callers.push(Caller {
                            offset: at,
                            kind,
                            indices: index.map(|i| [i, i.wrapping_add(1)]),
                        });
                    }
                }
            }
            if b.len() >= 4 && b[0] == 0x5a {
                for &i in lookup(i64::from(value(b, 1, 3))) {
                    graphs[i].other_references.push(Reference::Stored(at));
                }
            }
            // Branch tail transfers enter with an unrecorded caller input.
            if let Some(target) = super::branch_target(b, at)
                .filter(|&t| !lookup(t).is_empty() && !anchors.call_operand(local))
            {
                for &i in lookup(target) {
                    graphs[i].other_references.push(Reference::Stored(at));
                }
            }
        }
        for (i, b) in region.windows(4).enumerate() {
            for &g in lookup(i64::from(value(b, 0, 4))) {
                graphs[g].other_references.push(Reference::Stored(base + i));
            }
        }
    }
    for (stream, b) in regions.expanded.iter().enumerate() {
        for (offset, b) in b.windows(4).enumerate() {
            for &g in lookup(i64::from(value(b, 0, 4))) {
                graphs[g]
                    .other_references
                    .push(Reference::Expanded { stream, offset });
            }
        }
    }
    Observation::Known(graphs)
}

#[cfg(test)]
mod tests {
    use super::super::r1_pair_shapes::{CONSTRUCTOR, FILL, INITIALIZER, PAIR};
    use super::*;
    use core::cell::Cell;
    std::thread_local! {
        pub(super) static REGION_SCANS: Cell<usize> = const { Cell::new(0) };
    }
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
        assert!(bind(&raw, &[&raw], 0x1000, 0x416000).is_some());
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
                assert!(
                    bind(&raw, &[&raw], 0x1000, 0x416000).is_none(),
                    "{at:x}+{i}"
                );
                raw[at + i] ^= 1;
            }
        }
        for i in 0..FILL.len() {
            raw[0x4000 + i] ^= 1;
            assert!(bind(&raw, &[&raw], 0x1000, 0x416000).is_none());
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
            assert!(
                bind(&changed, &[&changed], 0x1000, 0x416000).is_none(),
                "{p:x}"
            );
        }
        let mut changed = raw.clone();
        changed[0x3011..0x3014].copy_from_slice(&[0x40, 0, 0]);
        assert!(bind(&changed, &[&changed], 0x1000, 0x416000).is_none());
    }
    const INIT: u32 = 0x415000;
    const ACCESSOR: u32 = 0x412100;
    /// Bulk cache at 0x2000 with an R1 accessor at 0x2100, the shared graph from
    /// 0x5000 and `copies` PAIR wrappers from 0x6000 (the first at 0x416000).
    fn graphs_fixture(copies: usize) -> Vec<u8> {
        let mut raw = alloc::vec![0xff; 0x10000];
        crate::image::layout::install_test_layout(&mut raw, 0x1000);
        let bulk = &super::super::cache_shapes::SHAPES[0];
        raw[0x2000..0x2000 + bulk.bytes.len()].copy_from_slice(bulk.bytes);
        raw[0x2000 + bulk.call + 1..0x2000 + bulk.call + 4].copy_from_slice(&[0x41, 0x10, 0]);
        for p in bulk.ram {
            raw[0x2000 + p..0x2004 + p].copy_from_slice(&0xa01000u32.to_be_bytes());
        }
        // Native R1 byte accessor leaf (cache.rs R1 head, RAM base, RTS).
        raw[0x2100..0x2110].copy_from_slice(&[
            0x1a, 0x80, 0x0c, 0x98, 0x78, 0, 0x6a, 0x28, 0, 0xa0, 0x10, 0, 0x54, 0x70, 0xff, 0xff,
        ]);
        for (at, p) in [(0x5000, &INITIALIZER), (0x5100, &CONSTRUCTOR)] {
            raw[at..at + p.bytes.len()].copy_from_slice(p.bytes);
        }
        raw[0x5300..0x5300 + FILL.len()].copy_from_slice(FILL);
        raw[0x5006..0x500a].copy_from_slice(&0x1802u32.to_be_bytes());
        for p in [12, 24] {
            raw[0x5000 + p..0x5004 + p].copy_from_slice(&0x1800u32.to_be_bytes());
        }
        raw[0x501f..0x5022].copy_from_slice(&[0x41, 0x51, 0]);
        raw[0x5100 + 46..0x5100 + 50].copy_from_slice(&0x415300u32.to_be_bytes());
        raw[0x5100 + 17..0x5100 + 20].copy_from_slice(&[0x41, 0x55, 0]);
        raw[0x5100 + 179..0x5100 + 182].copy_from_slice(&[0x41, 0x55, 2]);
        for k in 0..copies {
            let at = 0x6000 + k * 0x60;
            raw[at..at + PAIR.bytes.len()].copy_from_slice(PAIR.bytes);
            for p in [13, 29] {
                raw[at + p..at + p + 3].copy_from_slice(&INIT.to_be_bytes()[1..]);
            }
            for p in [21, 37] {
                raw[at + p..at + p + 3].copy_from_slice(&ACCESSOR.to_be_bytes()[1..]);
            }
        }
        raw
    }
    fn index(region: &[u8], local: usize) -> Option<u8> {
        caller_index(&mut super::super::Anchors::new(region, 0), region, local)
    }
    fn graphs(raw: &[u8]) -> Vec<Graph> {
        let Observation::Known(found) = discover(raw) else {
            panic!("fixture")
        };
        found
    }
    #[test]
    fn many_pair_wrappers_share_one_decode_and_one_caller_scan() {
        let work = |copies| {
            let raw = graphs_fixture(copies);
            crate::comp_streams::READS.with(|c| c.set(0));
            REGION_SCANS.with(|c| c.set(0));
            assert_eq!(graphs(&raw).len(), copies);
            (
                crate::comp_streams::READS.with(|c| c.get()),
                REGION_SCANS.with(|c| c.get()),
            )
        };
        assert_eq!(work(20), work(1));
    }
    #[test]
    fn branch_transfers_to_a_pair_entry_stay_visible() {
        for (at, branch) in [
            (0x5f80, &[0x40, 0x7e][..]),
            (0x5f80, &[0x47, 0x7e]),
            (0x5f00, &[0x58, 0x60, 0, 0xfc]),
        ] {
            let mut raw = graphs_fixture(1);
            raw[at..at + branch.len()].copy_from_slice(branch);
            let found = graphs(&raw);
            assert_eq!(
                found[0].other_references,
                alloc::vec![Reference::Stored(at)],
                "branch {branch:02x?}"
            );
        }
        // A JSR whose address word is branch-shaped is a call, not a branch:
        // 40 7e at 0x5f80 would be BRA to the PAIR entry at 0x416000.
        let mut raw = graphs_fixture(1);
        raw[0x5f7e..0x5f82].copy_from_slice(&[0x5e, 0x41, 0x40, 0x7e]);
        assert!(graphs(&raw)[0].other_references.is_empty());
    }
    #[test]
    fn caller_index_accepts_loads_after_operand_tails_of_earlier_instructions() {
        let call = [0x5e, 0x41, 0x60, 0];
        // The decode runs forward from the region start (here an RTS).
        let with = |prefix: &[u8]| [&[0x54, 0x70][..], prefix, &call[..]].concat();
        // JSR @0x416e12; MOV.B #5,R1L.
        assert_eq!(index(&with(&[0x5e, 0x41, 0x6e, 0x12, 0xf9, 5]), 8), Some(5));
        // JSR @0x417912; MOV.B #5,R1L.
        assert_eq!(index(&with(&[0x5e, 0x41, 0x79, 0x12, 0xf9, 5]), 8), Some(5));
        // MOV.L #0xa06b00,ER0; MOV.W #0x40,R1.
        let long = with(&[0x7a, 0, 0, 0xa0, 0x6b, 0, 0x79, 1, 0, 0x40]);
        assert_eq!(index(&long, 12), Some(0x40));
        assert_eq!(index(&with(&[0xf9, 0x40]), 4), Some(0x40));
        assert_eq!(index(&with(&[0x79, 1, 0, 0xff]), 6), Some(0xff));
        assert_eq!(index(&with(&[0, 0, 0, 0]), 6), None);
        // The region's first byte starts the decode.
        assert_eq!(index(&[0xf9, 0x40, 0x5e, 0x41, 0x60, 0], 2), Some(0x40));
        // An RTS-shaped operand word never restarts the decode:
        // MOV.W @0x5470F905:32,R0 ends in F9 05 directly before the call.
        assert_eq!(
            index(
                &[0x6b, 0x20, 0x54, 0x70, 0xf9, 0x05, 0x5e, 0x41, 0x60, 0],
                6
            ),
            None
        );
    }
    #[test]
    fn caller_index_rejects_r1_immediates_inside_longer_instructions() {
        let call = [0x5e, 0x41, 0x60, 0];
        let with = |prefix: &[u8]| [&[0x54, 0x70][..], prefix, &call[..]].concat();
        // MOV.B @0xF940:16,R1H: F9 40 is its address operand.
        assert_eq!(index(&with(&[0x6a, 0x09, 0xf9, 0x40]), 6), None);
        // ADD.W #0xF905,R1.
        assert_eq!(index(&with(&[0x79, 0x11, 0xf9, 0x05]), 6), None);
        // MOV.L #0x790100FF,ER0: 79 01 00 FF are its immediate bytes.
        assert_eq!(index(&with(&[0x7a, 0, 0x79, 1, 0, 0xff]), 8), None);
    }
    #[test]
    fn caller_indices_references_and_external_calls_are_bound() {
        let mut raw = graphs_fixture(2);
        raw[0x5ff0..0x5ff2].copy_from_slice(&[0x55, 0x0e]);
        // An RTS ending the preceding function; the decode runs forward from
        // the region start and needs no anchor here.
        raw[0x6ffe..0x7000].copy_from_slice(&[0x54, 0x70]);
        raw[0x7000..0x7006].copy_from_slice(&[0xf9, 0xff, 0x5e, 0x41, 0x60, 0]);
        raw[0x7010..0x7018].copy_from_slice(&[0x79, 1, 0, 0x40, 0x5e, 0x41, 0x60, 0]);
        // R1L immediates that are operand bytes of a longer instruction
        // (MOV.B @aa:16,R1H; ADD.W #imm,R1) are not index loads.
        raw[0x703e..0x7040].copy_from_slice(&[0x54, 0x70]);
        raw[0x7040..0x7048].copy_from_slice(&[0x6a, 0x09, 0xf9, 0x40, 0x5e, 0x41, 0x60, 0]);
        raw[0x7050..0x7058].copy_from_slice(&[0x79, 0x11, 0xf9, 0x05, 0x5e, 0x41, 0x60, 0]);
        raw[0x7021..0x7025].copy_from_slice(&0x416000u32.to_be_bytes());
        raw[0x7030..0x7034].copy_from_slice(&[0x5a, 0x41, 0x60, 0]);
        let found = graphs(&raw);
        assert_eq!(found.len(), 2);
        let g = &found[0];
        assert_eq!(
            (g.offset, g.reads, g.initializer, g.constructor, g.fill),
            (0x6000, [0x6014, 0x6024], 0x5000, 0x5100, 0x5300)
        );
        assert_eq!(
            (g.external_calls, g.flag, g.object),
            ([0x415500, 0x415502], 0x1800, 0x1802)
        );
        let caller = |offset, kind, indices| Caller {
            offset,
            kind,
            indices,
        };
        assert_eq!(
            g.callers,
            alloc::vec![
                caller(0x5ff0, CallKind::Relative8, None),
                caller(0x7002, CallKind::Absolute, Some([0xff, 0x00])),
                caller(0x7014, CallKind::Absolute, Some([0x40, 0x41])),
                caller(0x7044, CallKind::Absolute, None),
                caller(0x7054, CallKind::Absolute, None),
            ]
        );
        assert_eq!(
            g.other_references,
            // Per stored region: aligned jumps, then literals at any alignment.
            alloc::vec![Reference::Stored(0x7030), Reference::Stored(0x7021)]
        );
        assert!(found[1].callers.is_empty() && found[1].other_references.is_empty());
        raw[0x5100 + 19] = 1;
        assert!(graphs(&raw).is_empty(), "odd external call target");
    }
}
