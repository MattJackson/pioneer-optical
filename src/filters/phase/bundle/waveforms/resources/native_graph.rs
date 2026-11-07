//! Complete native-body graph matching. A match proves only the supplied graph:
//! callers still own its reachability, service ABI, and storage-use proofs.
use alloc::vec::Vec;
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, encode_insn, Ea, Operand},
    Mode, Target,
};

/// A code/data graph captured from a decoded reference image. The first code
/// body is the discovery root; every other member must be reachable from it.
#[derive(Clone, Debug)]
pub struct Graph {
    base: u32,
    nodes: Vec<(Range<usize>, Vec<u8>)>,
    code_count: usize,
    pointer_start: usize,
}
/// Locations of the matched code bodies followed by the matched data bodies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Bound code and data locations in the graph's declared node order.
    /// Image offsets in reference-node order.
    pub ranges: Vec<Range<usize>>,
}
fn value(op: Operand) -> Option<u32> {
    match op {
        Operand::Address(Ea::Absolute { value, .. }) | Operand::Immediate { value, bits: 32 } => {
            Some(value)
        }
        Operand::Address(Ea::Displacement {
            value, bits: 32, ..
        }) => Some(value as u32),
        _ => None,
    }
}
fn replace(op: Operand, value: u32) -> Option<Operand> {
    Some(match op {
        Operand::Address(Ea::Absolute { bits, .. }) => {
            Operand::Address(Ea::Absolute { bits, value })
        }
        Operand::Immediate { bits, .. } => Operand::Immediate { bits, value },
        Operand::Address(Ea::Displacement { base, bits, .. }) => {
            Operand::Address(Ea::Displacement {
                base,
                bits,
                value: value as i32,
            })
        }
        _ => return None,
    })
}
fn decoded(body: &[u8]) -> Option<h8_asm::isa::Decoded> {
    let d = decode_insn(body, Target::H8S2000, Mode::Advanced).ok()?;
    if d.len == 0
        || encode_insn(d.insn, Target::H8S2000, Mode::Advanced).ok()? != body.get(..d.len)?
    {
        return None;
    }
    Some(d)
}
/// Relocate only decoded absolute, long immediate, and long displacement
/// operands. All other instruction fields remain byte-exact. Overlapping
/// mappings are accepted only when they agree on the resulting address.
pub fn canonical(body: &[u8], mapping: &[(u32, u32, u32)]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let d = decoded(&body[at..])?;
        let mut insn = d.insn;
        for op in &mut insn.operands {
            let Some(v) = value(*op) else { continue };
            let mut mapped = None;
            for &(a, z, to) in mapping {
                if (a..z).contains(&v) {
                    let next = to.checked_add(v - a)?;
                    if mapped.is_some_and(|old| old != next) {
                        return None;
                    }
                    mapped = Some(next);
                }
            }
            if let Some(v) = mapped {
                *op = replace(*op, v)?;
            }
        }
        let encoded = encode_insn(insn, Target::H8S2000, Mode::Advanced).ok()?;
        if encoded.len() != d.len {
            return None;
        }
        out.extend(encoded);
        at += d.len;
    }
    Some(out)
}
/// Relocate a complete native body, including relative call/branch targets.
/// Every instruction must keep its native encoded width; an out-of-range
/// relative displacement is refused rather than silently changed to a thunk.
pub fn relocate(body: &[u8], from: u32, to: u32, mapping: &[(u32, u32, u32)]) -> Option<Vec<u8>> {
    let absolute = canonical(body, mapping)?;
    let mut out = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let original = decoded(&body[at..])?;
        let mut insn = decoded(&absolute[at..])?.insn;
        for (old, new) in original.insn.operands.iter().zip(&mut insn.operands) {
            if let Operand::Address(Ea::PcRelative { value, bits }) = *old {
                let destination = from
                    .checked_add((at + original.len) as u32)?
                    .checked_add_signed(value)?;
                let mut rebound = (from..from.checked_add(body.len() as u32)?)
                    .contains(&destination)
                    .then(|| to + destination - from);
                for &(a, z, mapped) in mapping {
                    if (a..z).contains(&destination) {
                        let target = mapped.checked_add(destination - a)?;
                        if rebound.is_some_and(|old| old != target) {
                            return None;
                        }
                        rebound = Some(target);
                    }
                }
                let destination = rebound.unwrap_or(destination);
                let next = to.checked_add((at + original.len) as u32)?;
                *new = Operand::Address(Ea::PcRelative {
                    value: (i64::from(destination) - i64::from(next)).try_into().ok()?,
                    bits,
                });
            }
        }
        let bytes = encode_insn(insn, Target::H8S2000, Mode::Advanced).ok()?;
        if bytes.len() != original.len {
            return None;
        }
        out.extend(bytes);
        at += original.len;
    }
    Some(out)
}
impl Graph {
    /// Capture complete instruction bodies and exact scalar data. Relative
    /// branches must terminate at instruction boundaries within their body.
    /// Unlisted absolute references remain fixed external service obligations.
    pub fn new(
        reference: &[u8],
        base: u32,
        code: &[Range<usize>],
        data: &[Range<usize>],
    ) -> Option<Self> {
        if code.is_empty() {
            return None;
        }
        let mut nodes = Vec::new();
        for r in code.iter().chain(data) {
            if r.is_empty()
                || u32::try_from(r.end).ok()?.checked_add(base)? > 0x1000000
                || nodes
                    .iter()
                    .any(|(s, _): &(Range<usize>, Vec<u8>)| s.start < r.end && r.start < s.end)
            {
                return None;
            }
            nodes.push((r.clone(), reference.get(r.clone())?.to_vec()));
        }
        for (r, body) in &nodes[..code.len()] {
            if (base as usize + r.start) & 1 != 0 {
                return None;
            }
            let mut starts = Vec::new();
            let mut edges = Vec::new();
            let mut at = 0;
            while at < body.len() {
                let d = decoded(&body[at..])?;
                starts.push(at);
                for op in d.insn.operands {
                    if let Operand::Address(Ea::PcRelative { value, .. }) = op {
                        if d.insn.mnemonic != "BSR" {
                            edges.push((at + d.len).checked_add_signed(value as isize)?);
                        }
                    }
                }
                at += d.len;
            }
            if edges.iter().any(|e| !starts.contains(e)) {
                return None;
            }
        }
        let pointer_start = nodes.len();
        Some(Self {
            base,
            nodes,
            code_count: code.len(),
            pointer_start,
        })
    }
    /// Capture explicitly declared aligned 32-bit pointer tables as graph
    /// edges. These are distinct from opaque scalar/diagnostic data nodes.
    pub fn with_pointer_tables(
        reference: &[u8],
        base: u32,
        code: &[Range<usize>],
        data: &[Range<usize>],
        pointers: &[Range<usize>],
    ) -> Option<Self> {
        if pointers
            .iter()
            .any(|r| r.len() % 4 != 0 || (base as usize + r.start) & 1 != 0)
        {
            return None;
        }
        let all_data: Vec<_> = data.iter().chain(pointers).cloned().collect();
        let mut graph = Self::new(reference, base, code, &all_data)?;
        graph.pointer_start = code.len() + data.len();
        Some(graph)
    }
    fn edge(
        &self,
        expected: u32,
        actual: u32,
        base: u32,
        locations: &mut [Option<usize>],
        pending: &mut Vec<usize>,
    ) -> Option<bool> {
        let Some(off) = expected.checked_sub(self.base).map(|v| v as usize) else {
            return Some(false);
        };
        let Some(j) = self.nodes.iter().position(|(r, _)| r.contains(&off)) else {
            return Some(false);
        };
        let target =
            (actual.checked_sub(base)? as usize).checked_sub(off - self.nodes[j].0.start)?;
        match locations[j] {
            Some(old) if old != target => return None,
            Some(_) => (),
            None => {
                locations[j] = Some(target);
                pending.push(j);
            }
        }
        Some(true)
    }
    /// Bind a root at a caller-observed offset, following every typed graph
    /// edge. Conflicting aliases, overlapping members, altered instructions,
    /// missing nodes, and nodes outside stored spans fail closed.
    pub fn bind(
        &self,
        image: &[u8],
        base: u32,
        stored: &[Range<usize>],
        root: usize,
    ) -> Option<Binding> {
        let mut locations = alloc::vec![None; self.nodes.len()];
        locations[0] = Some(root);
        self.finish(self.bind_partial(image, base, stored, locations, 0)?)
    }
    fn bind_partial(
        &self,
        image: &[u8],
        base: u32,
        stored: &[Range<usize>],
        mut locations: Vec<Option<usize>>,
        seed: usize,
    ) -> Option<Vec<Option<usize>>> {
        let mut pending = alloc::vec![seed];
        while let Some(i) = pending.pop() {
            let start = locations[i]?;
            let end = start.checked_add(self.nodes[i].1.len())?;
            if u32::try_from(end).ok()?.checked_add(base)? > 0x1000000
                || !stored.iter().any(|r| r.start <= start && end <= r.end)
            {
                return None;
            }
            let actual = image.get(start..end)?;
            let expected = &self.nodes[i].1;
            if i >= self.pointer_start {
                for (a, e) in actual.chunks_exact(4).zip(expected.chunks_exact(4)) {
                    let av = u32::from_be_bytes(a.try_into().ok()?);
                    let ev = u32::from_be_bytes(e.try_into().ok()?);
                    if !self.edge(ev, av, base, &mut locations, &mut pending)? && av != ev {
                        return None;
                    }
                }
                continue;
            }
            if i >= self.code_count {
                if actual != expected {
                    return None;
                }
                continue;
            }
            if (base as usize + start) & 1 != 0 {
                return None;
            }
            let mut at = 0;
            while at < expected.len() {
                let a = decoded(&actual[at..])?;
                let e = decoded(&expected[at..])?;
                if a.len != e.len {
                    return None;
                }
                let mut restored = a.insn;
                for k in 0..3 {
                    if e.insn.mnemonic == "BSR" {
                        if let Operand::Address(Ea::PcRelative {
                            value: displacement,
                            bits,
                        }) = e.insn.operands[k]
                        {
                            let Operand::Address(Ea::PcRelative {
                                value: actual_displacement,
                                bits: actual_bits,
                            }) = a.insn.operands[k]
                            else {
                                return None;
                            };
                            if bits != actual_bits {
                                return None;
                            }
                            let expected_address =
                                (self.base as usize + self.nodes[i].0.start + at + e.len)
                                    .checked_add_signed(displacement as isize)?
                                    as u32;
                            let actual_address = (base as usize + start + at + a.len)
                                .checked_add_signed(actual_displacement as isize)?
                                as u32;
                            if !self.edge(
                                expected_address,
                                actual_address,
                                base,
                                &mut locations,
                                &mut pending,
                            )? && expected_address != actual_address
                            {
                                return None;
                            }
                            restored.operands[k] = e.insn.operands[k];
                            continue;
                        }
                    }
                    let Some(v) = value(e.insn.operands[k]) else {
                        continue;
                    };
                    let Some(off) = v.checked_sub(self.base).map(|v| v as usize) else {
                        continue;
                    };
                    let Some(j) = self.nodes.iter().position(|(r, _)| r.contains(&off)) else {
                        continue;
                    };
                    // Operand form, width and registers are compared below after
                    // reversing this one graph edge.
                    let av = value(a.insn.operands[k])?;
                    let target = (av.checked_sub(base)? as usize)
                        .checked_sub(off - self.nodes[j].0.start)?;
                    match locations[j] {
                        Some(old) if old != target => return None,
                        Some(_) => (),
                        None => {
                            locations[j] = Some(target);
                            pending.push(j);
                        }
                    }
                    restored.operands[k] = replace(a.insn.operands[k], v)?;
                }
                if restored != e.insn {
                    return None;
                }
                at += e.len;
            }
        }
        Some(locations)
    }
    fn finish(&self, locations: Vec<Option<usize>>) -> Option<Binding> {
        let ranges = locations
            .into_iter()
            .enumerate()
            .map(|(i, at)| {
                let at = at?;
                Some(at..at.checked_add(self.nodes[i].1.len())?)
            })
            .collect::<Option<Vec<_>>>()?;
        for (i, r) in ranges.iter().enumerate() {
            if ranges[..i]
                .iter()
                .any(|s| s.start < r.end && r.start < s.end)
            {
                return None;
            }
        }
        Some(Binding { ranges })
    }
    /// Find at most two complete bindings, including disconnected code roots.
    /// Two results mean ambiguous discovery; callers must not choose one by
    /// scan order. Data must be reached through typed code references.
    pub fn discover(&self, image: &[u8], base: u32, stored: &[Range<usize>]) -> Vec<Binding> {
        let mut found = Vec::new();
        self.search(
            image,
            base,
            stored,
            alloc::vec![None; self.nodes.len()],
            &mut found,
        );
        found
    }
    fn search(
        &self,
        image: &[u8],
        base: u32,
        stored: &[Range<usize>],
        locations: Vec<Option<usize>>,
        found: &mut Vec<Binding>,
    ) {
        if found.len() >= 2 {
            return;
        }
        let Some(i) = locations[..self.code_count]
            .iter()
            .position(Option::is_none)
        else {
            if let Some(binding) = self.finish(locations) {
                if !found.contains(&binding) {
                    found.push(binding);
                }
            }
            return;
        };
        for r in stored {
            let Some(last) = r.end.min(image.len()).checked_sub(self.nodes[i].1.len()) else {
                continue;
            };
            let Some(first) = r
                .start
                .checked_add(((base as usize).wrapping_add(r.start)) & 1)
            else {
                continue;
            };
            for at in (first..=last).step_by(2) {
                // None of the supported relocatable operand fields changes the
                // first opcode byte. This keeps image scanning inexpensive.
                if image[at] != self.nodes[i].1[0] {
                    continue;
                }
                let mut next = locations.clone();
                next[i] = Some(at);
                if let Some(next) = self.bind_partial(image, base, stored, next, i) {
                    self.search(image, base, stored, next, found);
                    if found.len() >= 2 {
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn follows_relocated_code_and_data_and_rejects_conflicts() {
        // Root loads a scalar pointer then calls another complete native body.
        let mut reference = alloc::vec![0xff; 48];
        reference[..12]
            .copy_from_slice(&[0x7a, 0, 0, 0, 0x10, 0x20, 0x5e, 0, 0x10, 0x10, 0x54, 0x70]);
        reference[16..18].copy_from_slice(&[0x54, 0x70]);
        reference[32..36].copy_from_slice(&[1, 2, 3, 4]);
        let graph = Graph::new(&reference, 0x1000, &[0..12, 16..18], &[32..36]).unwrap();
        let mut image = alloc::vec![0xff; 80];
        image[8..20].copy_from_slice(
            &canonical(
                &reference[..12],
                &[(0x1010, 0x1012, 0x2030), (0x1020, 0x1024, 0x2040)],
            )
            .unwrap(),
        );
        image[48..50].copy_from_slice(&reference[16..18]);
        image[64..68].copy_from_slice(&reference[32..36]);
        assert_eq!(
            graph.discover(&image, 0x2000, &[0..80]),
            alloc::vec![Binding {
                ranges: alloc::vec![8..20, 48..50, 64..68]
            }]
        );
        image[64] ^= 1;
        assert!(graph.discover(&image, 0x2000, &[0..80]).is_empty());
        image[64] ^= 1;
        image[17] = 0x31; // Call now targets an odd/nonmatching code body.
        assert!(graph.discover(&image, 0x2000, &[0..80]).is_empty());
    }
    #[test]
    fn explicit_pointer_tables_follow_edges_without_reinterpreting_scalar_data() {
        let mut reference = alloc::vec![0xff; 48];
        reference[..8].copy_from_slice(&[0x7a, 0, 0, 0, 0x10, 0x20, 0x54, 0x70]);
        reference[16..18].copy_from_slice(&[0x54, 0x70]);
        reference[32..36].copy_from_slice(&0x1010u32.to_be_bytes());
        let graph = Graph::with_pointer_tables(&reference, 0x1000, &[0..8, 16..18], &[], &[32..36])
            .unwrap();
        let mut image = alloc::vec![0xff; 80];
        image[8..16]
            .copy_from_slice(&canonical(&reference[..8], &[(0x1020, 0x1024, 0x2040)]).unwrap());
        image[48..50].copy_from_slice(&reference[16..18]);
        image[64..68].copy_from_slice(&0x2030u32.to_be_bytes());
        assert!(graph.bind(&image, 0x2000, &[0..80], 8).is_some());
        let scalar = Graph::new(&reference, 0x1000, &[0..8, 16..18], &[32..36]).unwrap();
        assert!(scalar.discover(&image, 0x2000, &[0..80]).is_empty());
    }
    #[test]
    fn canonical_rejects_conflicting_aliases() {
        assert!(canonical(
            &[0x5e, 0, 0x10, 0x10],
            &[(0x1010, 0x1012, 0x2030), (0x1010, 0x1012, 0x2040)]
        )
        .is_none());
    }
}
