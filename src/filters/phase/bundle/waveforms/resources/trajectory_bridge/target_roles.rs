use super::super::native_graph;
use super::*;

/// Native target code/data roles, established by full decoded graph matching.
/// Unlisted service and RAM operands remain exact external obligations.
#[derive(Clone, Debug)]
pub struct TargetRoles {
    canonical: Vec<Range<usize>>,
    actual: Vec<Range<usize>>,
    normal_digest: [u8; 32],
}
impl TargetRoles {
    /// Discover every native controller/profile/client role coherently.
    pub fn discover(normal: &[u8]) -> Option<Self> {
        let (reference, merged, data, pointers) = Self::parts(normal.len())?;
        let graph =
            native_graph::Graph::with_pointer_tables(&reference, BASE, &merged, &data, &pointers)?;
        let regions = crate::image::regions(normal)?;
        let stored: Vec<_> = regions
            .stored
            .iter()
            .map(|r| {
                let at = r.as_ptr() as usize - normal.as_ptr() as usize;
                at..at + r.len()
            })
            .collect();
        let found = graph.discover(normal, BASE, &stored);
        let [binding] = found.as_slice() else {
            return None;
        };
        let canonical: Vec<_> = merged.into_iter().chain(data).chain(pointers).collect();
        let actual = binding.ranges.clone();
        Some(Self {
            canonical,
            actual,
            normal_digest: Sha256::digest(normal).into(),
        })
    }
    fn parts(image_len: usize) -> Option<trajectory_profile::TargetGraphParts> {
        let (mut reference, mut code, mut data, pointers) =
            trajectory_profile::target_graph_parts(image_len.max(0x200000))?;
        let packed = include_bytes!("../trajectory_code/controller-target.bin");
        let mut cursor = 0;
        for &(a, z, digest) in TARGET.iter().chain(DIRECTION).chain(RETAINED) {
            let r = span(a, z);
            let bytes = packed.get(cursor..cursor + r.len())?;
            if Sha256::digest(bytes).as_slice() != digest {
                return None;
            }
            reference.get_mut(r.clone())?.copy_from_slice(bytes);
            cursor += r.len();
            code.push(r);
        }
        // Complete incoming movement clients and their original static data.
        // Provenance: decoded static Normal 8e02ed7244d8de7564f6e0606ba803f8614a6e2b87b5e24f7ee344cdcea71141.
        let clients = include_bytes!("../trajectory_code/target-clients.bin");
        let mut cursor = 0;
        for (index, (a, z)) in [
            (0x5381c0, 0x5387a2),
            (0x538900, 0x538a5a),
            (0x4f52fc, 0x4f53be),
            (0x538f82, 0x538f90),
            (0x5a4d0c, 0x5a4edc),
            (0x5a29fe, 0x5a2a2a),
        ]
        .into_iter()
        .enumerate()
        {
            let r = span(a, z);
            reference[r.clone()].copy_from_slice(clients.get(cursor..cursor + r.len())?);
            cursor += r.len();
            if index < 4 {
                code.push(r);
            } else {
                data.push(r);
            }
        }
        code.sort_by_key(|r| (r.start, r.end));
        let mut merged: Vec<Range<usize>> = Vec::new();
        for r in code {
            if let Some(last) = merged.last_mut() {
                if r.start < last.end {
                    last.end = last.end.max(r.end);
                    continue;
                }
            }
            merged.push(r);
        }
        Some((reference, merged, data, pointers))
    }
    /// Require the immutable original image from which these roles were bound.
    pub fn verify(&self, normal: &[u8]) -> bool {
        <[u8; 32]>::from(Sha256::digest(normal)) == self.normal_digest
    }
    /// Map a canonical CPU address to its positively bound target address.
    pub fn address(&self, canonical: u32) -> Option<u32> {
        let offset = canonical.checked_sub(BASE)? as usize;
        let index = self.canonical.iter().position(|r| r.contains(&offset))?;
        BASE.checked_add((self.actual[index].start + offset - self.canonical[index].start) as u32)
    }
    /// Map a canonical Normal-offset range within one complete bound object.
    pub fn span(&self, canonical: Range<usize>) -> Option<Range<usize>> {
        if canonical.is_empty() {
            return None;
        }
        let index = self
            .canonical
            .iter()
            .position(|r| r.start <= canonical.start && canonical.end <= r.end)?;
        let start = self.actual[index].start + canonical.start - self.canonical[index].start;
        Some(start..start + canonical.len())
    }
    /// Complete native graph witnesses at their actual target locations.
    pub fn protected(&self) -> &[Range<usize>] {
        &self.actual
    }
    /// Profile allocations inside bound retired controller/helper objects.
    pub fn auxiliary_slots(&self) -> Option<[Range<usize>; 2]> {
        Some([
            self.span(span(0x53966e, 0x539766))?,
            self.span(span(VTABLE + 20, 0x539b2c))?,
        ])
    }
    /// Target hardware-service entries; diagnostic adapter lies in the owned controller.
    pub fn services(&self) -> Option<trajectory_profile::Services> {
        Some(trajectory_profile::Services {
            report: [self.address(REPORT)?; 2],
            state_getter: self.address(0x538f56)?,
            hardware_mode: self.address(0x538f7e)?,
        })
    }
    /// Private RAM remains a fixed operand obligation of this native grammar.
    pub const fn private_ram(&self) -> u32 {
        PRIVATE
    }
}

impl TargetRoles {
    /// Locate retained roles and prospective emitted wrapper storage. The caller
    /// must validate the complete emitted controller/profile before using this
    /// locator result as a mechanism observation.
    pub(super) fn locate_emitted(normal: &[u8]) -> Option<Self> {
        let entry = unique_pattern(
            normal,
            &[
                1, 0, 0x6d, 0xf3, 1, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0, 0x24, 0x0f, 0x94, 0x0d, 0x9a,
                0x0d, 0xa1, 0x73, 9, 0x47, 2, 0x0b, 0x5a, 0x0d, 0xaa, 0x58, 0x70, 0, 0x30,
            ],
        )?;

        let init = unique_pattern(
            normal,
            &[0x0c, 0x99, 0x47, 4, 0x5a, -1, -1, -1, 0x5a, -1, -1, -1],
        )?;
        let update = unique_pattern(
            normal,
            &[0x6e, 2, 0, 14, 0x47, 4, 0x5a, -1, -1, -1, 0x5a, -1, -1, -1],
        )?;
        let guard = unique_pattern(
            normal,
            &[
                0x0c, 0x99, 0x46, 8, 0x79, 0x29, 0xff, 0xff, 0x46, 2, 0x19, 0x99, 0x5a, -1, -1, -1,
            ],
        )?;

        let dispatcher = super::super::dispatch_bridge::observe(normal).ok()?;

        let selector = BASE + dispatcher.selector.start as u32;
        let literal = dispatcher.kind == super::super::dispatch_bridge::Kind::Literal;
        let (mut reference, _, _, _) = Self::parts(normal.len())?;
        let (_, profile_code, mut data, pointers) =
            trajectory_profile::target_graph_parts(reference.len())?;
        let mut code: Vec<_> = profile_code.into_iter().skip(2).collect();
        if literal {
            code.push(span(0x538a88, 0x538f82));
        }
        code.extend(
            RETAINED
                .iter()
                .chain(DIRECTION)
                .map(|&(a, z, _)| span(a, z)),
        );
        code.extend(
            [
                (0x5381c0, 0x5387a2),
                (0x538900, 0x538a5a),
                (0x4f52fc, 0x4f53be),
                (0x538f82, 0x538f90),
            ]
            .into_iter()
            .map(|(a, z)| span(a, z)),
        );
        data.push(span(0x5a29fe, 0x5a2a2a));
        code.push(span(0x53956c, 0x53962e));
        reference[span(0x539586, 0x539590)].fill(0);
        reference[span(0x5395d6, 0x5395e2)].fill(0);
        // Only the complete, separately recognized call substitutions vary.
        // All remaining instruction fields and typed graph edges stay exact.
        for (at, to) in [
            (0x539496, init),
            (0x5393f2, update),
            (0x53951c, update),
            (0x5385d4, guard),
            (0x53898e, guard),
            (0x5389e2, guard),
            (0x538ad6, selector),
            (0x538b26, selector),
        ] {
            let at = (at - BASE) as usize;
            if reference[at] != 0x5e {
                return None;
            }
            reference[at + 1..at + 4].copy_from_slice(&to.to_be_bytes()[1..]);
        }
        code.sort_by_key(|r| (r.start, r.end));
        let mut merged: Vec<Range<usize>> = Vec::new();
        for r in code {
            if let Some(last) = merged.last_mut() {
                if r.start < last.end {
                    last.end = last.end.max(r.end);
                    continue;
                }
            }
            merged.push(r);
        }
        // The source abort setter retains its native entry but uses the owned
        // private byte. Its graph node supplies that location independently.
        let abort = span(0x537e26, 0x537e30);
        let bytes =
            native_graph::canonical(&reference[abort.clone()], &[(0x3264, 0x3265, PRIVATE)])?;
        reference[abort.clone()].copy_from_slice(&bytes);
        merged.push(abort);
        for r in &merged {
            let bytes =
                native_graph::canonical(&reference[r.clone()], &[(ENTRY, 0x539b2c, entry)])?;
            reference[r.clone()].copy_from_slice(&bytes);
        }
        let graph =
            native_graph::Graph::with_pointer_tables(&reference, BASE, &merged, &data, &pointers)?;
        let regions = crate::image::regions(normal)?;
        let stored: Vec<_> = regions
            .stored
            .iter()
            .map(|r| {
                let at = r.as_ptr() as usize - normal.as_ptr() as usize;
                at..at + r.len()
            })
            .collect();

        let found = graph.discover(normal, BASE, &stored);

        let [binding] = found.as_slice() else {
            return None;
        };
        let mut canonical: Vec<_> = merged.into_iter().chain(data).chain(pointers).collect();
        let mut actual = binding.ranges.clone();
        canonical.push(span(ENTRY, 0x539b2c));
        actual.push((entry - BASE) as usize..(entry - BASE + 0x539b2c - ENTRY) as usize);
        Some(Self {
            canonical,
            actual,
            normal_digest: Sha256::digest(normal).into(),
        })
    }
}
fn unique_pattern(normal: &[u8], pattern: &[i16]) -> Option<u32> {
    let regions = crate::image::regions(normal)?;
    let mut found = None;
    for bytes in regions.stored {
        let offset = bytes.as_ptr() as usize - normal.as_ptr() as usize;
        for (at, window) in bytes.windows(pattern.len()).enumerate() {
            if (offset + at) & 1 == 0
                && window
                    .iter()
                    .zip(pattern)
                    .all(|(&b, &p)| p < 0 || b == p as u8)
            {
                if found.is_some() {
                    return None;
                }
                found = Some(BASE + (offset + at) as u32);
            }
        }
    }
    found
}
