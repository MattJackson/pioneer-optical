//! Bounded native H8 parameter-reader graph recognition.
use super::{
    h8_shapes::{GRAPHS, SHAPES},
    *,
};
use alloc::vec;

pub(super) struct Shape {
    pub bytes: &'static [u8],
    // Offset, width, kind: control target / diagnostic pointer / RAM slot.
    pub masks: &'static [(usize, usize, u8)],
}

impl Shape {
    fn matches(&self, body: &[u8], at: usize) -> bool {
        let Some(bytes) = at
            .checked_add(self.bytes.len())
            .and_then(|end| body.get(at..end))
        else {
            return false;
        };
        if !bytes.iter().zip(self.bytes).enumerate().all(|(i, (a, b))| {
            a == b
                || self
                    .masks
                    .iter()
                    .any(|(off, len, _)| (*off..off + len).contains(&i))
        }) {
            return false;
        }
        for &(offset, len, kind) in self.masks {
            let value = bytes[offset..offset + len]
                .iter()
                .fold(0u32, |v, b| (v << 8) | u32::from(*b));
            if (kind == 0 && (value == 0 || value & 1 != 0)) || (kind == 2 && value >= 0x10000) {
                return false;
            }
        }
        true
    }
}

pub(super) struct Edge {
    pub from: usize,
    pub offset: usize,
    pub to: usize,
    pub delta: usize,
    // Absolute 24-bit JSR/JMP, BSR:8, BSR:16.
    pub kind: u8,
}

/// Record semantics supplied only by explicitly qualified complete grammars.
pub(super) struct RecordRole {
    pub first: u16,
    pub last: u16,
    pub coordinate_operand: usize,
    pub record_bytes: u32,
    pub allocation_bytes: u32,
}

pub(super) struct Graph {
    pub nodes: &'static [usize],
    pub edges: &'static [Edge],
    // Node and immediate operand offset for resolver/width/region comparisons.
    // Mapper window bounds are not primary-location operands.
    pub primary: &'static [(usize, usize)],
    pub address: u32,
    pub count: u16,
    pub record_roles: Option<&'static [RecordRole]>,
}

fn destination(body: &[u8], at: usize, edge: &Edge, base: u32) -> Option<usize> {
    let start = at.checked_add(edge.offset)?;
    match edge.kind {
        0 => {
            let bytes = body.get(start..start.checked_add(4)?)?;
            if !matches!(bytes[0], 0x5e | 0x5a) {
                return None;
            }
            let address = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]);
            usize::try_from(address.checked_sub(base)?).ok()
        }
        1 => {
            let bytes = body.get(start..start.checked_add(2)?)?;
            if bytes[0] != 0x55 {
                return None;
            }
            start
                .checked_add(2)?
                .checked_add_signed(isize::from(bytes[1] as i8))
        }
        2 => {
            let bytes = body.get(start..start.checked_add(4)?)?;
            if bytes[..2] != [0x5c, 0] {
                return None;
            }
            start
                .checked_add(4)?
                .checked_add_signed(isize::from(i16::from_be_bytes([bytes[2], bytes[3]])))
        }
        _ => None,
    }
}

struct Binding {
    locations: Vec<usize>,
    primary_address: u32,
}

fn binding_locations(graph: &Graph, body: &[u8], root: usize, base: u32) -> Option<Binding> {
    let mut locations = vec![None; graph.nodes.len()];
    locations[0] = Some(root);
    for _ in 0..graph.nodes.len() {
        let mut changed = false;
        for edge in graph.edges {
            let Some(from) = locations[edge.from] else {
                continue;
            };
            let target =
                destination(body, from, edge, base).and_then(|t| t.checked_sub(edge.delta))?;
            if let Some(previous) = locations[edge.to] {
                if previous != target {
                    return None;
                }
            } else {
                locations[edge.to] = Some(target);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    if graph.address < 0x10000 && graph.nodes.len() == 9 {
        let mapper = locations[8]?;
        let slots: Vec<_> = SHAPES[graph.nodes[8]]
            .masks
            .iter()
            .filter(|(_, _, kind)| *kind == 2)
            .collect();
        if slots.len() != 2 {
            return None;
        }
        let read_slot = |offset: usize| {
            body.get(mapper + offset..mapper + offset + 4)
                .map(|b| u32::from_be_bytes(b.try_into().expect("four bytes")))
        };
        let (Some(first), Some(second)) = (read_slot(slots[0].0), read_slot(slots[1].0)) else {
            return None;
        };
        if first.checked_add(4) != Some(second) {
            return None;
        }
    }
    let locations = locations.into_iter().collect::<Option<Vec<_>>>()?;
    let mut primary_address = None;
    for &(node, offset) in graph.primary {
        let at = locations.get(node)?.checked_add(offset)?;
        let value = u32::from_be_bytes(body.get(at..at.checked_add(4)?)?.try_into().ok()?);
        if primary_address.is_some_and(|previous| previous != value) {
            return None;
        }
        primary_address = Some(value);
    }
    let primary_address = primary_address?;
    let allowed = primary_address == graph.address
        || matches!(
            (
                graph.nodes.len(),
                graph.count,
                graph.address,
                primary_address
            ),
            (7, 40, 0x5e0000 | 0x7f0000, 0x5e0000 | 0x7f0000)
                | (9, 20, 0x5984 | 0x9984, 0x5984 | 0x9984)
        );
    if !allowed {
        return None;
    }
    for (node, (&shape, &at)) in graph.nodes.iter().zip(&locations).enumerate() {
        let shape = &SHAPES[shape];
        let mut canonical = body.get(at..at.checked_add(shape.bytes.len())?)?.to_vec();
        for &(field_node, offset) in graph.primary {
            if field_node == node {
                canonical
                    .get_mut(offset..offset.checked_add(4)?)?
                    .copy_from_slice(&graph.address.to_be_bytes());
            }
        }
        if !shape.matches(&canonical, 0) {
            return None;
        }
    }
    Some(Binding {
        locations,
        primary_address,
    })
}

fn bound_layout(graph: &Graph, binding: &Binding, body: &[u8]) -> Option<ParameterLayout> {
    if let Some(roles) = graph.record_roles {
        // These grammars bind RecordBytes as their fourth complete function.
        let record_bytes = *binding.locations.get(3)?;
        let mut regions = Vec::with_capacity(roles.len());
        let mut domains = Vec::with_capacity(roles.len());
        for role in roles {
            let at = record_bytes.checked_add(role.coordinate_operand)?;
            let address = u32::from_be_bytes(body.get(at..at.checked_add(4)?)?.try_into().ok()?);
            let count = role
                .allocation_bytes
                .checked_div(role.record_bytes.checked_add(2)?)?;
            let record_count = u16::try_from(count).ok()?;
            let header_bytes = record_count.checked_mul(2)?;
            let region = regions.len();
            regions.push(RecordRegion {
                address,
                basis: AddressBasis::SelectedBank,
                allocation_bytes: Some(role.allocation_bytes),
                record_bytes: role.record_bytes,
                record_count,
                header_bytes,
                header_test: HeaderTest::ByteFf,
            });
            domains.push(LogicalDomain {
                first: role.first,
                last: role.last,
                region,
            });
        }
        return Some(ParameterLayout::FlashRecords {
            regions,
            encoding: WordEncoding::LittleEndian,
            domains,
        });
    }
    Some(ParameterLayout::FlashRecords {
        regions: vec![RecordRegion {
            address: binding.primary_address,
            basis: if graph.address < 0x10000 {
                AddressBasis::SelectedBank
            } else {
                AddressBasis::Absolute
            },
            allocation_bytes: None,
            record_bytes: 320,
            record_count: graph.count,
            header_bytes: 2 * graph.count,
            header_test: HeaderTest::ByteFf,
        }],
        encoding: WordEncoding::LittleEndian,
        domains: vec![LogicalDomain {
            first: 0,
            last: 159,
            region: 0,
        }],
    })
}

#[cfg(test)]
fn bind(graph: &Graph, body: &[u8], root: usize, base: u32) -> bool {
    binding_locations(graph, body, root, base).is_some()
}

/// Recognize the H8 primary parameter reader in one decoded component.
///
/// `cpu_base` must be its actual CPU load address (`0x410000` for Normal,
/// `0x400000` for the audited Kernel readers). For a Kernel-owned reader, the
/// caller must supply the exact associated Kernel; this function does not infer
/// a missing Kernel from a related model or revision.
///
/// Complete getter, resolver, record, geometry, header and scanner shapes are
/// checked. Where the read uses a mapped byte interface, that reader and mapper
/// must also be reached through their native calls. Arithmetic/diagnostic
/// runtime calls remain external; this does not execute code or certify writes.
pub fn discover_h8_component(body: &[u8], cpu_base: u32) -> Observation<ParameterLayout> {
    match reader(body, cpu_base).unwrap_or(Observation::Unresolved(Unresolved::ReaderNotRecognized))
    {
        Observation::Known((_, layout)) => Observation::Known(layout),
        Observation::Unresolved(reason) => Observation::Unresolved(reason),
        Observation::Conflicting => Observation::Conflicting,
    }
}

/// The component's unique complete reader graph. `None` only when no getter
/// root shape occurs at all; a root whose graph does not bind is unresolved.
fn reader(body: &[u8], cpu_base: u32) -> Option<Observation<(u32, ParameterLayout)>> {
    if cpu_base & 1 != 0
        || cpu_base
            .checked_add(u32::try_from(body.len()).unwrap_or(u32::MAX))
            .is_none()
    {
        return Some(Observation::Unresolved(Unresolved::TruncatedEvidence));
    }
    let mut result = None;
    // Even offsets of every 8-byte window, as `windows(8).step_by(2)` would
    // visit them, without the generic iterator's per-step bookkeeping.
    for at in (0..body.len().saturating_sub(7)).step_by(2) {
        if !matches!(body[at], 0x01 | 0x6d) {
            continue;
        }
        let prefix = &body[at..at + 8];
        let mut candidate = false;
        let mut matched = None;
        for graph in GRAPHS {
            let root = &SHAPES[graph.nodes[0]];
            if prefix != &root.bytes[..8] || !root.matches(body, at) {
                continue;
            }
            candidate = true;
            let Some(binding) = binding_locations(graph, body, at, cpu_base) else {
                continue;
            };
            let Some(layout) = bound_layout(graph, &binding, body) else {
                return Some(Observation::Unresolved(Unresolved::TruncatedEvidence));
            };
            if matched.as_ref().is_some_and(|old| old != &layout) {
                return Some(Observation::Conflicting);
            }
            matched = Some(layout);
        }
        if !candidate {
            continue;
        }
        let Some(layout) = matched else {
            return Some(Observation::Unresolved(Unresolved::ReaderNotRecognized));
        };
        if result.is_some() {
            return Some(Observation::Unresolved(Unresolved::AmbiguousReader));
        }
        result = Some((cpu_base + at as u32, layout));
    }
    result.map(Observation::Known)
}

fn native_body(body: &[u8]) -> Option<Vec<u8>> {
    let regions = super::super::regions(body)?;
    let mut bytes = vec![0xff; body.len()];
    for r in regions.stored {
        let at = r.as_ptr() as usize - body.as_ptr() as usize;
        bytes[at..at + r.len()].copy_from_slice(r);
    }
    Some(bytes)
}

fn index_register(bytes: &[u8], at: usize) -> Option<u8> {
    if bytes.get(at + 8..at + 10) == Some(&[0x0d, 0x1e][..]) {
        Some(1)
    } else if matches!(
        bytes.get(at + 8..at + 10),
        Some([0x0d, 0x04] | [0x0d, 0x0d])
    ) || bytes.get(at + 6..at + 8) == Some(&[0x0d, 0x04][..])
    {
        Some(0)
    } else {
        None
    }
}

fn reader_evidence(
    bytes: &[u8],
    component: H8ReaderComponent,
    getter: u32,
    layout: ParameterLayout,
) -> Observation<H8ReaderEvidence> {
    use H8ReaderRole::*;
    const ROLES: &[H8ReaderRole] = &[
        Getter,
        Resolver,
        Record,
        RecordBytes,
        RegionBytes,
        HeaderBytes,
        Scanner,
        ByteReader,
        AddressMapper,
    ];
    let base = match component {
        H8ReaderComponent::Normal => 0x410000,
        H8ReaderComponent::Kernel => 0x400000,
    };
    let Some(at) = getter.checked_sub(base).map(|at| at as usize) else {
        return Observation::Unresolved(Unresolved::TruncatedEvidence);
    };
    let Some(argument_register) = index_register(bytes, at) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    for graph in GRAPHS {
        if !matches!(graph.nodes.len(), 7 | 9) || !SHAPES[graph.nodes[0]].matches(bytes, at) {
            continue;
        }
        let Some(binding) = binding_locations(graph, bytes, at, base) else {
            continue;
        };
        let functions = graph
            .nodes
            .iter()
            .zip(binding.locations)
            .zip(ROLES)
            .map(|((&shape, offset), &role)| H8ReaderFunction {
                role,
                address: base + offset as u32,
                bytes: SHAPES[shape].bytes.len(),
            })
            .collect();
        return Observation::Known(H8ReaderEvidence {
            component,
            getter,
            argument_register,
            functions,
            layout,
        });
    }
    Observation::Unresolved(Unresolved::ReaderNotRecognized)
}

/// Recognize the complete Normal reader graph and its native index register.
pub(crate) fn normal_reader(normal: &[u8]) -> Observation<(u32, u8, ParameterLayout)> {
    let Some(bytes) = native_body(normal) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    match reader(&bytes, 0x410000)
        .unwrap_or(Observation::Unresolved(Unresolved::ReaderNotRecognized))
    {
        Observation::Known((entry, layout)) => {
            let at = (entry - 0x410000) as usize;
            let argument = index_register(&bytes, at);
            argument.map_or(
                Observation::Unresolved(Unresolved::ReaderNotRecognized),
                |argument| Observation::Known((entry, argument, layout)),
            )
        }
        Observation::Unresolved(reason) => Observation::Unresolved(reason),
        Observation::Conflicting => Observation::Conflicting,
    }
}

/// Bind a comparison to the exact recognized getter and its argument convention.
pub(crate) fn normal_reader_binding(
    normal: &[u8],
    entry: u32,
    argument_register: u8,
) -> Observation<ParameterLayout> {
    match normal_reader(normal) {
        Observation::Known((actual, argument, layout))
            if actual == entry && argument == argument_register =>
        {
            Observation::Known(layout)
        }
        Observation::Known(_) => Observation::Unresolved(Unresolved::ReaderNotRecognized),
        Observation::Unresolved(reason) => Observation::Unresolved(reason),
        Observation::Conflicting => Observation::Conflicting,
    }
}

fn external_parameter_reader(normal: &[u8]) -> Observation<u32> {
    let mut target = None;
    for at in (0..normal.len().saturating_sub(23)).step_by(2) {
        let b = &normal[at..at + 24];
        if b[..5] != [0x79, 0, 0, 0xa4, 0x5e]
            || b[8..17] != [0x6f, 0xf0, 0, 4, 0x79, 0, 0, 0xa5, 0x5e]
            || b[20..24] != [0x6f, 0xf0, 0, 6]
            || b[5..8] != b[17..20]
        {
            continue;
        }
        let address = u32::from_be_bytes([0, b[5], b[6], b[7]]);
        if !(0x400000..0x410000).contains(&address) || address & 1 != 0 {
            continue;
        }
        if target.is_some_and(|old| old != address) {
            return Observation::Conflicting;
        }
        target = Some(address);
    }
    target.map_or(
        Observation::Unresolved(Unresolved::ReaderNotRecognized),
        Observation::Known,
    )
}

/// Recognize the primary parameter layout in H8 Normal or its supplied Kernel.
///
/// A resident reader is accepted only when Normal's paired A4/A5 parameter
/// reads call the exact recognized Kernel getter entry. The complete getter
/// graph independently establishes its primary 0000–009F record layout.
/// The caller must supply the associated decoded Kernel, not a sibling image.
/// Missing resident code remains unresolved with its required CPU address.
pub fn discover_h8(normal: &[u8], kernel: Option<&[u8]>) -> Observation<ParameterLayout> {
    match discover_h8_reader(normal, kernel) {
        Observation::Known(reader) => Observation::Known(reader.layout),
        Observation::Unresolved(reason) => Observation::Unresolved(reason),
        Observation::Conflicting => Observation::Conflicting,
    }
}

/// Bind the complete primary reader graph and identify its owning component.
/// Normal-to-Kernel delegation requires the exact paired A4/A5 calls and getter
/// entry match. Compressed bytes cannot supply native functions. Ownership does
/// not establish that an edit to that component is necessary: a Normal-side
/// replacement still requires separate read/write/erase/initialization proof.
pub fn discover_h8_reader(normal: &[u8], kernel: Option<&[u8]>) -> Observation<H8ReaderEvidence> {
    let Some(normal) = native_body(normal) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    // Only a Normal with no getter root at all may delegate to the Kernel; a
    // Normal getter whose graph does not bind is not proven unused.
    match reader(&normal, 0x410000) {
        Some(Observation::Known((entry, layout))) => {
            return reader_evidence(&normal, H8ReaderComponent::Normal, entry, layout)
        }
        Some(Observation::Conflicting) => return Observation::Conflicting,
        Some(Observation::Unresolved(reason)) => return Observation::Unresolved(reason),
        None => {}
    }
    let address = match external_parameter_reader(&normal) {
        Observation::Known(address) => address,
        Observation::Conflicting => return Observation::Conflicting,
        Observation::Unresolved(reason) => return Observation::Unresolved(reason),
    };
    let Some(kernel) = kernel else {
        return Observation::Unresolved(Unresolved::ResidentCodeRequired(address));
    };
    let Some(kernel) = native_body(kernel) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    match reader(&kernel, 0x400000)
        .unwrap_or(Observation::Unresolved(Unresolved::ReaderNotRecognized))
    {
        Observation::Known((entry, layout)) if entry == address => {
            reader_evidence(&kernel, H8ReaderComponent::Kernel, entry, layout)
        }
        Observation::Known(_) => Observation::Unresolved(Unresolved::ReaderNotRecognized),
        Observation::Unresolved(reason) => Observation::Unresolved(reason),
        Observation::Conflicting => Observation::Conflicting,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    const BASE: u32 = 0x410000;

    fn fixture(graph: &Graph) -> (Vec<u8>, Vec<usize>) {
        fixture_at(graph, 0x100, 0x1000)
    }
    fn fixture_at(graph: &Graph, start: usize, stride: usize) -> (Vec<u8>, Vec<usize>) {
        let mut cursor = start;
        let mut locations: Vec<_> = (0..graph.nodes.len())
            .map(|i| {
                if stride != 0 {
                    start + i * stride
                } else {
                    let at = cursor;
                    cursor += (SHAPES[graph.nodes[i]].bytes.len() + 31) & !15;
                    at
                }
            })
            .collect();
        // Fixed relative byte-reader calls constrain mapper placement.
        for edge in graph.edges.iter().filter(|e| e.kind != 0) {
            let shape = &SHAPES[graph.nodes[edge.from]];
            let offset = edge.offset;
            let delta = if edge.kind == 1 {
                isize::from(shape.bytes[offset + 1] as i8)
            } else {
                isize::from(i16::from_be_bytes([
                    shape.bytes[offset + 2],
                    shape.bytes[offset + 3],
                ]))
            };
            locations[edge.to] = locations[edge.from]
                .checked_add(offset + if edge.kind == 1 { 2 } else { 4 })
                .unwrap()
                .checked_add_signed(delta)
                .unwrap()
                - edge.delta;
        }
        let size = graph
            .nodes
            .iter()
            .zip(&locations)
            .map(|(n, at)| at + SHAPES[*n].bytes.len())
            .max()
            .unwrap();
        let mut body = vec![0; size];
        for (node, at) in graph.nodes.iter().zip(&locations) {
            let shape = &SHAPES[*node];
            body[*at..at + shape.bytes.len()].copy_from_slice(shape.bytes);
            for &(offset, len, kind) in shape.masks {
                let value: u32 = match kind {
                    0 => 0x105000,
                    1 => 0x900000,
                    _ => 0x3000,
                };
                body[at + offset..at + offset + len]
                    .copy_from_slice(&value.to_be_bytes()[4 - len..]);
            }
        }
        if graph.address < 0x10000 && graph.nodes.len() == 9 {
            for (i, (offset, _, _)) in SHAPES[graph.nodes[8]]
                .masks
                .iter()
                .filter(|(_, _, kind)| *kind == 2)
                .enumerate()
            {
                let at = locations[8] + offset;
                body[at..at + 4].copy_from_slice(&(0x3000u32 + 4 * i as u32).to_be_bytes());
            }
        }
        for edge in graph.edges.iter().filter(|e| e.kind == 0) {
            let address = BASE + u32::try_from(locations[edge.to] + edge.delta).unwrap();
            let at = locations[edge.from] + edge.offset + 1;
            body[at..at + 3].copy_from_slice(&address.to_be_bytes()[1..]);
        }
        (body, locations)
    }

    pub(crate) fn install(body: &mut [u8], at: usize) {
        install_variant(body, at, 0);
    }

    pub(crate) fn install_variant(body: &mut [u8], at: usize, variant: usize) {
        let (fixture, locations) = fixture_at(&GRAPHS[variant], at, 0);
        assert!(
            bind(&GRAPHS[variant], &fixture, at, BASE),
            "positions {locations:?}; sizes {:?}",
            GRAPHS[variant]
                .nodes
                .iter()
                .map(|n| SHAPES[*n].bytes.len())
                .collect::<Vec<_>>()
        );
        body[at..fixture.len()].copy_from_slice(&fixture[at..]);
        assert!(matches!(discover_h8(body, None), Observation::Known(_)));
    }

    #[test]
    fn paired_reader_requires_the_exact_normal_call_target() {
        let graph = &GRAPHS[0];
        let (mut kernel, locations) = fixture(graph);
        for edge in graph.edges.iter().filter(|e| e.kind == 0) {
            let address = 0x400000 + u32::try_from(locations[edge.to] + edge.delta).unwrap();
            let at = locations[edge.from] + edge.offset + 1;
            kernel[at..at + 3].copy_from_slice(&address.to_be_bytes()[1..]);
        }
        let mut normal = vec![0xff; 64];
        normal[..24].copy_from_slice(&[
            0x79, 0, 0, 0xa4, 0x5e, 0x40, 1, 0, 0x6f, 0xf0, 0, 4, 0x79, 0, 0, 0xa5, 0x5e, 0x40, 1,
            0, 0x6f, 0xf0, 0, 6,
        ]);
        assert!(matches!(
            discover_h8(&normal, Some(&kernel)),
            Observation::Known(_)
        ));
        assert!(matches!(
            discover_h8(&normal, None),
            Observation::Unresolved(Unresolved::ResidentCodeRequired(0x400100))
        ));
        normal[7] = 2;
        normal[19] = 2;
        assert!(!matches!(
            discover_h8(&normal, Some(&kernel)),
            Observation::Known(_)
        ));
        normal[19] = 0;
        assert!(!matches!(
            discover_h8(&normal, Some(&kernel)),
            Observation::Known(_)
        ));
    }
    #[test]
    fn an_unbound_normal_getter_is_not_replaced_by_the_kernel_reader() {
        let graph = &GRAPHS[0];
        let (mut kernel, locations) = fixture(graph);
        for edge in graph.edges.iter().filter(|e| e.kind == 0) {
            let address = 0x400000 + u32::try_from(locations[edge.to] + edge.delta).unwrap();
            let at = locations[edge.from] + edge.offset + 1;
            kernel[at..at + 3].copy_from_slice(&address.to_be_bytes()[1..]);
        }
        let mut normal = vec![0xff; 0x400];
        normal[..24].copy_from_slice(&[
            0x79, 0, 0, 0xa4, 0x5e, 0x40, 1, 0, 0x6f, 0xf0, 0, 4, 0x79, 0, 0, 0xa5, 0x5e, 0x40, 1,
            0, 0x6f, 0xf0, 0, 6,
        ]);
        assert!(matches!(
            discover_h8(&normal, Some(&kernel)),
            Observation::Known(_)
        ));
        // Normal also carries its own getter root whose graph does not bind.
        let root = SHAPES[graph.nodes[0]].bytes.len();
        normal[0x100..0x100 + root].copy_from_slice(&kernel[locations[0]..locations[0] + root]);
        assert!(matches!(
            reader(&native_body(&normal).unwrap(), 0x410000),
            Some(Observation::Unresolved(Unresolved::ReaderNotRecognized))
        ));
        assert!(!matches!(
            discover_h8(&normal, Some(&kernel)),
            Observation::Known(_)
        ));
    }

    #[test]
    fn all_native_graph_forms_bind_after_relocation() {
        assert_eq!(GRAPHS.len(), 10);
        for graph in GRAPHS {
            let (body, locations) = fixture(graph);
            assert!(bind(graph, &body, locations[0], BASE));
            let Observation::Known(ParameterLayout::FlashRecords { regions, .. }) =
                discover_h8_component(&body, BASE)
            else {
                panic!("relocated graph not recognized")
            };
            assert_eq!(regions[0].address, graph.address);
            assert_eq!(regions[0].record_count, graph.count);
        }
    }

    #[test]
    fn two_complete_readers_in_one_component_are_ambiguous() {
        let (first, _) = fixture_at(&GRAPHS[0], 0x100, 0);
        let (mut body, _) = fixture_at(&GRAPHS[0], 0x4000, 0);
        assert!(first.len() <= 0x4000);
        assert!(matches!(
            discover_h8_component(&body, BASE),
            Observation::Known(_)
        ));
        body[0x100..first.len()].copy_from_slice(&first[0x100..]);
        assert!(matches!(
            discover_h8_component(&body, BASE),
            Observation::Unresolved(Unresolved::AmbiguousReader)
        ));
    }

    #[test]
    fn redirected_required_calls_never_keep_the_layout() {
        for graph in GRAPHS {
            let (body, locations) = fixture(graph);
            for edge in graph.edges.iter().filter(|edge| edge.kind == 0) {
                let mut changed = body.clone();
                let at = locations[edge.from] + edge.offset + 1;
                changed[at..at + 3].copy_from_slice(&[0x40, 0, 0]);
                assert!(!bind(graph, &changed, locations[0], BASE));
            }
        }
    }

    #[test]
    fn relocated_bank_pointer_slots_must_stay_adjacent() {
        for graph in GRAPHS.iter().filter(|g| g.address < 0x10000) {
            let (mut body, locations) = fixture(graph);
            let offset = SHAPES[graph.nodes[8]]
                .masks
                .iter()
                .filter(|(_, _, k)| *k == 2)
                .nth(1)
                .unwrap()
                .0;
            body[locations[8] + offset + 3] ^= 4;
            assert!(!bind(graph, &body, locations[0], BASE));
        }
    }

    #[test]
    fn native_geometry_and_scanner_mutations_are_rejected() {
        for graph in GRAPHS {
            let (body, locations) = fixture(graph);
            for role in [3, 4, 5, 6] {
                let shape = &SHAPES[graph.nodes[role]];
                for offset in 0..shape.bytes.len() {
                    if shape
                        .masks
                        .iter()
                        .any(|(at, len, _)| (*at..at + len).contains(&offset))
                    {
                        continue;
                    }
                    let mut changed = body.clone();
                    changed[locations[role] + offset] ^= 1;
                    assert!(
                        !bind(graph, &changed, locations[0], BASE),
                        "accepted geometry/scanner byte {role}:{offset}"
                    );
                }
            }
        }
    }
    fn modern_graphs() -> [&'static Graph; 5] {
        [&GRAPHS[3], &GRAPHS[4], &GRAPHS[5], &GRAPHS[6], &GRAPHS[8]]
    }

    fn modern_layout(graph: &Graph) -> ParameterLayout {
        let addresses = if graph.address == 0x5984 {
            [0x5984, 0x4000, 0x820c, 0xa534, 0x4352, 0xa932]
        } else {
            [0x9984, 0x8000, 0xc20c, 0xe534, 0x8352, 0xe932]
        };
        let rows = [
            (0x000, 0x09f, 320, 6440, 20, 40),
            (0x0a0, 0x0af, 32, 850, 25, 50),
            (0x0b0, 0x18f, 448, 9000, 20, 40),
            (0x190, 0x19f, 32, 510, 15, 30),
            (0x1a0, 0x1a0, 2, 50, 12, 24),
            (0x210, 0x28f, 256, 5160, 20, 40),
        ];
        let regions = rows
            .iter()
            .zip(addresses)
            .map(
                |(&(_, _, record_bytes, allocation, record_count, header_bytes), address)| {
                    RecordRegion {
                        address,
                        basis: AddressBasis::SelectedBank,
                        allocation_bytes: Some(allocation),
                        record_bytes,
                        record_count,
                        header_bytes,
                        header_test: HeaderTest::ByteFf,
                    }
                },
            )
            .collect();
        let domains = rows
            .iter()
            .enumerate()
            .map(|(region, &(first, last, _, _, _, _))| LogicalDomain {
                first,
                last,
                region,
            })
            .collect();
        ParameterLayout::FlashRecords {
            regions,
            domains,
            encoding: WordEncoding::LittleEndian,
        }
    }

    #[test]
    fn complete_modern_readers_expose_six_regions_and_545_words() {
        for graph in modern_graphs() {
            let (body, _) = fixture(graph);
            let Observation::Known(layout) = discover_h8_component(&body, BASE) else {
                panic!("complete modern reader was not recognized")
            };
            assert_eq!(layout, modern_layout(graph));
            let ParameterLayout::FlashRecords {
                regions, domains, ..
            } = &layout
            else {
                unreachable!()
            };
            assert_eq!(regions.len(), 6);
            assert_eq!(
                domains
                    .iter()
                    .map(|domain| usize::from(domain.last - domain.first + 1))
                    .sum::<usize>(),
                545
            );
            assert_eq!(
                regions
                    .iter()
                    .map(|region| region.record_bytes)
                    .sum::<u32>(),
                1090
            );
            assert!(
                matches!(discover_h8(&body, None), Observation::Known(actual) if actual == layout)
            );
            let Observation::Known(evidence) = discover_h8_reader(&body, None) else {
                panic!("complete evidence missing")
            };
            assert_eq!(evidence.layout, layout);
            assert_eq!(evidence.functions.len(), 9);
            for (function, &shape) in evidence.functions.iter().zip(graph.nodes) {
                assert_eq!(function.bytes, SHAPES[shape].bytes.len());
            }
        }
    }

    #[test]
    fn modern_schema_survives_code_and_mapper_slot_relocation() {
        for graph in modern_graphs() {
            for (start, stride) in [(0x100, 0x1000), (0x800, 0x200)] {
                let (mut body, locations) = fixture_at(graph, start, stride);
                for (index, &(offset, _, _)) in SHAPES[graph.nodes[8]]
                    .masks
                    .iter()
                    .filter(|(_, _, kind)| *kind == 2)
                    .enumerate()
                {
                    let at = locations[8] + offset;
                    body[at..at + 4].copy_from_slice(&(0x4300u32 + 4 * index as u32).to_be_bytes());
                }
                assert!(
                    matches!(discover_h8_component(&body, BASE), Observation::Known(actual) if actual == modern_layout(graph))
                );
            }
        }
    }

    #[test]
    fn agreed_primary_operands_relocate_only_region_zero() {
        for graph in modern_graphs() {
            let (mut body, locations) = fixture(graph);
            let address = if graph.address == 0x5984 {
                0x9984u32
            } else {
                0x5984u32
            };
            let mut expected = modern_layout(graph);
            let ParameterLayout::FlashRecords { regions, .. } = &mut expected else {
                unreachable!()
            };
            regions[0].address = address;
            for &(node, offset) in graph.primary {
                let at = locations[node] + offset;
                body[at..at + 4].copy_from_slice(&address.to_be_bytes());
            }
            assert!(
                matches!(discover_h8_component(&body, BASE), Observation::Known(actual) if actual == expected)
            );
            let (mut disagree, locations) = fixture(graph);
            let (node, offset) = graph.primary[0];
            let at = locations[node] + offset;
            disagree[at..at + 4].copy_from_slice(&address.to_be_bytes());
            assert!(!matches!(
                discover_h8_component(&disagree, BASE),
                Observation::Known(_)
            ));
        }
    }

    #[test]
    fn modern_domain_coordinate_geometry_header_and_graph_mutations_refuse() {
        for graph in modern_graphs() {
            let (body, locations) = fixture(graph);
            let domain = SHAPES[graph.nodes[1]]
                .bytes
                .windows(4)
                .position(|w| w == [0x79, 0x25, 0, 0xa0])
                .unwrap()
                + 3;
            let edge = graph
                .edges
                .iter()
                .find(|edge| edge.from == 0 && edge.to == 1)
                .unwrap();
            for (node, offset) in [(1, domain), (3, 21), (3, 13), (4, 13), (5, 0)] {
                let mut changed = body.clone();
                changed[locations[node] + offset] ^= 1;
                assert!(
                    !matches!(discover_h8_component(&changed, BASE), Observation::Known(_)),
                    "accepted role {node} byte {offset}"
                );
            }
            let mut changed = body.clone();
            let at = locations[edge.from] + edge.offset + 1;
            changed[at..at + 3].copy_from_slice(&[0x40, 0, 0]);
            assert!(!matches!(
                discover_h8_component(&changed, BASE),
                Observation::Known(_)
            ));
        }
    }

    #[test]
    fn every_modern_region_selects_native_records_within_its_allocation() {
        for graph in modern_graphs() {
            let (body, _) = fixture(graph);
            let Observation::Known(ParameterLayout::FlashRecords { regions, .. }) =
                discover_h8_component(&body, BASE)
            else {
                panic!("reader missing")
            };
            for region in &regions {
                assert_eq!(region.selected_record(&[]), None);
                for empty in 0..=region.record_count {
                    let mut header = vec![0; usize::from(region.header_bytes)];
                    if empty < region.record_count {
                        header[usize::from(empty) * 2] = 0xff;
                    }
                    let selected = region.selected_record(&header).unwrap();
                    assert_eq!(selected, empty.saturating_sub(1));
                    let end = u32::from(region.header_bytes)
                        + u32::from(selected + 1) * region.record_bytes;
                    assert!(end <= region.allocation_bytes.unwrap());
                    assert_eq!(region.selected_record(&header[..header.len() - 1]), None);
                }
            }
            let scalar = &regions[4];
            assert_eq!(
                scalar.allocation_bytes.unwrap()
                    - (scalar.record_bytes * u32::from(scalar.record_count)
                        + u32::from(scalar.header_bytes)),
                2
            );
        }
    }

    #[test]
    fn nonmodern_grammars_keep_primary_only_representation() {
        for graph in [&GRAPHS[0], &GRAPHS[1], &GRAPHS[2], &GRAPHS[7], &GRAPHS[9]] {
            let (body, _) = fixture(graph);
            let Observation::Known(ParameterLayout::FlashRecords {
                regions, domains, ..
            }) = discover_h8_component(&body, BASE)
            else {
                panic!("nonmodern reader missing")
            };
            assert_eq!(regions.len(), 1);
            assert_eq!(regions[0].address, graph.address);
            assert_eq!(regions[0].allocation_bytes, None);
            assert_eq!(regions[0].record_bytes, 320);
            assert_eq!(regions[0].record_count, graph.count);
            assert_eq!(
                domains,
                vec![LogicalDomain {
                    first: 0,
                    last: 159,
                    region: 0
                }]
            );
        }
    }
}
