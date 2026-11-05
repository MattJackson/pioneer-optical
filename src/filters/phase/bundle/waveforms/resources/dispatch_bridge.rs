//! Whole native dispatcher/selector adaptation with explicit table relocation.
//! This stage preserves caller entries and target RAM state coordinates. It
//! does not create tables or prove runtime-buffer ownership; composition must
//! supply resources populated by its separately proved donor waveform graph.
use super::*;
use crate::filters::phase::native::encoding;
use h8_asm::{
    isa::{decode_insn, Ea, Operand},
    Mode, Target,
};

/// Complete native dispatch representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Native image literals plus the selected software-table pointer.
    Literal,
    /// Native software-table pointer, including runtime-produced choices.
    Software,
    /// Parameter-selected motion pointer cells and an additional input ABI.
    Pointer,
}
/// Native command caller's extra-byte input convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argument {
    /// Command callers read their existing object byte at offset five.
    StateByte,
    /// Command callers explicitly supply zero; movement still supplies zero/one.
    Zero,
}
/// Bound dispatcher, selector and their shared state/table coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Representation of the complete dispatcher.
    pub kind: Kind,
    /// Extra-byte preparation proved at the native command callers.
    pub argument: Argument,
    /// Complete dispatcher body.
    pub dispatch: Range<usize>,
    /// Complete mode selector body.
    pub selector: Range<usize>,
    /// Full-step state byte, selector mode byte, selected-table pointer cell.
    pub state: [u32; 3],
    /// Distinct native table addresses in first-use order.
    pub tables: Vec<u32>,
    /// Complete direct-call instructions to dispatch and selector respectively.
    pub callers: [Vec<Range<usize>>; 2],
}
/// A resource or native caller contract was not established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Complete native caller/callee graph is missing or ambiguous.
    Unresolved,
    /// Pointer dispatch callers use a different extra-argument convention.
    CallerContract,
    /// Supplied donor-to-target table mapping is missing or ambiguous.
    Resources,
    /// A growing body needs explicitly owned executable storage.
    SpaceRequired,
    /// Reserved storage is occupied, overlapping, or outside stored Normal.
    InvalidSpace,
    /// Emitted graph failed native rebinding.
    Verification,
}
fn fields(kind: Kind) -> (&'static [usize], &'static [usize], &'static [usize]) {
    match kind {
        Kind::Literal => (&[10, 20, 68, 126], &[40, 56, 90], &[79, 99, 135, 159]),
        Kind::Software => (&[16, 6], &[], &[31, 63, 87]),
        Kind::Pointer => (
            &[10, 22, 100, 164],
            &[40, 54, 78, 124, 138],
            &[47, 87, 111, 131, 173, 197],
        ),
    }
}
fn direct_calls(n: &[u8], span: &Range<usize>) -> Result<Vec<Range<usize>>, Failure> {
    direct_calls_inner(n, span, false)
}
fn direct_calls_inner(
    n: &[u8],
    span: &Range<usize>,
    followed: bool,
) -> Result<Vec<Range<usize>>, Failure> {
    let address = 0x410000 + span.start as u32;
    let needle = &address.to_be_bytes()[1..];
    let regions = crate::image::regions(n).ok_or(Failure::Unresolved)?;
    let mut sites = Vec::new();
    let mut alias = None;
    for region in regions.stored {
        let origin = region.as_ptr() as usize - n.as_ptr() as usize;
        for (offset, bytes) in region.windows(3).enumerate() {
            if bytes != needle {
                continue;
            }
            let at = origin + offset;
            if offset == 0 || (at - 1) & 1 != 0 {
                return Err(Failure::CallerContract);
            }
            let d = decode_insn(&n[at - 1..], Target::H8S2000, Mode::Advanced)
                .map_err(|_| Failure::CallerContract)?;
            if d.len != 4
                || !matches!(d.insn.mnemonic, "JSR" | "JMP")
                || d.insn.operands[0]
                    != Operand::Address(Ea::Absolute {
                        value: address,
                        bits: 24,
                    })
            {
                return Err(Failure::CallerContract);
            }
            if d.insn.mnemonic == "JMP" {
                if followed || alias.replace(at - 1..at + 3).is_some() {
                    return Err(Failure::CallerContract);
                }
            } else {
                sites.push(at - 1..at + 3);
            }
        }
    }
    if let Some(alias) = alias {
        if !sites.is_empty() {
            return Err(Failure::CallerContract);
        }
        return direct_calls_inner(n, &alias, true);
    }
    Ok(sites)
}
fn caller_contract(n: &[u8], calls: &[Vec<Range<usize>>; 2]) -> Result<Argument, Failure> {
    // These complete argument preparations define all direct native call sites.
    // R0H is the row, R0L the existing object[5]/movement state. Their target
    // callees return row&63 and preserve ER3..ER6 in both representations.
    let mut count = [0; 3];
    let mut state_arguments = 0;
    let mut zero_arguments = 0;
    for call in &calls[0] {
        let before = &n[..call.start];
        let role = if before.ends_with(&[0x0c, 0x40, 0x0c, 0x98])
            || before.ends_with(&[0x19, 0, 0x0c, 0xcc, 0x4d, 2, 0xf8, 1, 0x0c, 0x40])
        {
            0
        } else if before.ends_with(&[0xf8, 1, 0x0c, 0x90]) {
            1
        } else if before.ends_with(&[0x6e, 0x38, 0, 5, 0x6e, 0x30, 0, 4]) {
            state_arguments += 1;
            2
        } else if before.ends_with(&[0x6e, 0x30, 0, 4, 0x18, 0x88]) {
            zero_arguments += 1;
            2
        } else {
            return Err(Failure::CallerContract);
        };
        count[role] += 1;
    }
    if count != [1, 1, 3] {
        return Err(Failure::CallerContract);
    }
    let mut count = [0; 3];
    for call in &calls[1] {
        let before = &n[..call.start];
        let role = if before.ends_with(&[0x18, 0x88])
            || before.ends_with(&[0x18, 0x88, 0x6e, 0xb8, 0, 10])
        {
            0
        } else if before.ends_with(&[0xf8, 1]) {
            1
        } else if before.ends_with(&[0x0c, 0x98]) {
            2
        } else {
            return Err(Failure::CallerContract);
        };
        count[role] += 1;
    }
    if count != [3, 1, 1] {
        return Err(Failure::CallerContract);
    }
    match (state_arguments, zero_arguments) {
        (3, 0) => Ok(Argument::StateByte),
        (0, 3) => Ok(Argument::Zero),
        _ => Err(Failure::CallerContract),
    }
}
/// Observe the complete dispatch and selector, linked through their pointer.
/// Literal/software callers must establish the native common two-byte input ABI.
pub fn observe(n: &[u8]) -> Result<Binding, Failure> {
    let Observation::Known(coils) = native::discover_pair(n) else {
        return Err(Failure::Unresolved);
    };
    let regions = crate::image::regions(n).ok_or(Failure::Unresolved)?;
    bundle::step_source(n, &regions.stored, &coils).map_err(|_| Failure::Unresolved)?;
    let mut found = Vec::new();
    for (kind, shape) in [
        (Kind::Literal, shapes::STATIC_DISPATCH),
        (Kind::Software, shapes::SOFTWARE_DISPATCH),
        (Kind::Pointer, shapes::POINTER_DISPATCH),
    ] {
        for start in sites(n, &regions.stored, shape) {
            found.push((kind, start..start + shape.len()));
        }
    }
    let [(kind, dispatch)] = found.as_slice() else {
        return Err(Failure::Unresolved);
    };
    let body = &n[dispatch.clone()];
    let (state_fields, table_fields, call_fields) = fields(*kind);
    let state = match kind {
        Kind::Literal => [word(body, 10), word(body, 20), word(body, 68)],
        Kind::Pointer => [word(body, 10), word(body, 22), word(body, 100)],
        Kind::Software => [word(body, 16), 0, word(body, 6)],
    };
    let ram_byte = |address: u32| {
        (address > 0 && address < 0x100000) || (0xa00000..=0xafffff).contains(&address)
    };
    if !ram_byte(state[0])
        || !ram_byte(state[2])
        || !ram_byte(state[2].checked_add(3).ok_or(Failure::Unresolved)?)
        || state[2] & 1 != 0
    {
        return Err(Failure::Unresolved);
    }
    if state_fields.len() == 4 && word(body, state_fields[2]) != word(body, state_fields[3]) {
        return Err(Failure::Unresolved);
    }
    let targets = call_fields
        .iter()
        .map(|at| bundle::resolve_call(n, call(body, *at)))
        .collect::<Option<Vec<_>>>()
        .ok_or(Failure::Unresolved)?;
    if targets[0] == *targets.last().unwrap()
        || !coils.functions.contains(&targets[0])
        || !coils.functions.contains(targets.last().unwrap())
        || targets[..targets.len() - 1]
            .iter()
            .any(|at| *at != targets[0])
    {
        return Err(Failure::Unresolved);
    }
    let mut selectors = Vec::new();
    for (shape, store) in [
        (shapes::SOFTWARE_ROM_SELECTOR, 44),
        (shapes::SOFTWARE_RUNTIME_SELECTOR, 52),
    ] {
        for start in sites(n, &regions.stored, shape) {
            if word(&n[start..start + shape.len()], store) == state[2] {
                selectors.push(start..start + shape.len());
            }
        }
    }
    let [selector] = selectors.as_slice() else {
        return Err(Failure::Unresolved);
    };
    let mode = word(&n[selector.clone()], 2);
    if !ram_byte(mode) || mode == state[0] || (*kind != Kind::Software && mode != state[1]) {
        return Err(Failure::Unresolved);
    }
    if (state[2]..state[2] + 4).contains(&mode) || (state[2]..state[2] + 4).contains(&state[0]) {
        return Err(Failure::Unresolved);
    }
    if selector.len() == shapes::SOFTWARE_RUNTIME_SELECTOR.len() {
        let body = &n[selector.clone()];
        let modes = [body[7], body[11], body[15]];
        if modes != [1, 3, 2] && modes != [1, 4, 3] {
            return Err(Failure::Unresolved);
        }
    }
    let state = [state[0], mode, state[2]];
    let mut tables = Vec::new();
    for address in table_fields.iter().map(|at| word(body, *at)).chain(
        (20..selector.len() - 6)
            .step_by(8)
            .map(|at| word(&n[selector.clone()], at)),
    ) {
        if address == 0 || address & 1 != 0 {
            return Err(Failure::Resources);
        }
        if !tables.contains(&address) {
            tables.push(address);
        }
    }
    let callers = [direct_calls(n, dispatch)?, direct_calls(n, selector)?];
    let argument = caller_contract(n, &callers)?;
    Ok(Binding {
        kind: *kind,
        argument,
        dispatch: dispatch.clone(),
        selector: selector.clone(),
        state,
        tables,
        callers,
    })
}
/// Replace both complete native bodies and relocate every bound state, table
/// and coil operand. Resources maps each distinct donor table address exactly
/// once to a caller-owned 256-byte resource. RAM ownership/initialization and
/// image table contents are obligations of the composition supplying this map.
/// Pointer dispatch is refused until its differing caller arguments are adapted.
struct Prepared {
    destination: Binding,
    source: Binding,
    bodies: [Vec<u8>; 2],
}
fn prepare(
    target: &[u8],
    donor: &[u8],
    resources: &[(u32, u32)],
    reservations: &[Option<Range<usize>>; 2],
) -> Result<Prepared, Failure> {
    let destination = observe(target)?;
    let source = observe(donor)?;
    if destination.kind == Kind::Pointer
        || source.kind == Kind::Pointer
        || (source.kind == Kind::Literal && destination.argument != source.argument)
    {
        return Err(Failure::CallerContract);
    }
    if resources.len() != source.tables.len()
        || source.tables.iter().any(|address| {
            resources
                .iter()
                .filter(|(from, to)| from == address && *to != 0 && *to & 1 == 0)
                .count()
                != 1
        })
    {
        return Err(Failure::Resources);
    }
    let regions = crate::image::regions(target).ok_or(Failure::Unresolved)?;
    for (index, (_, address)) in resources.iter().enumerate() {
        if resources[index + 1..]
            .iter()
            .any(|(_, other)| other == address)
        {
            return Err(Failure::Resources);
        }
        if (0xa00000..=0xafff00).contains(address) {
            continue;
        }
        let start = address.checked_sub(0x410000).ok_or(Failure::Resources)? as usize;
        let end = start.checked_add(256).ok_or(Failure::Resources)?;
        if !regions.stored.iter().any(|r| {
            let at = r.as_ptr() as usize - target.as_ptr() as usize;
            start >= at && end <= at + r.len()
        }) || [&destination.dispatch, &destination.selector]
            .into_iter()
            .chain(reservations.iter().flatten())
            .any(|span| start < span.end && span.start < end)
        {
            return Err(Failure::Resources);
        }
    }
    let mut bodies = [
        donor[source.dispatch.clone()].to_vec(),
        donor[source.selector.clone()].to_vec(),
    ];
    let (state_fields, table_fields, call_fields) = fields(source.kind);
    let state_indices: &[usize] = if source.kind == Kind::Literal {
        &[0, 1, 2, 2]
    } else {
        &[0, 2]
    };
    for (field, index) in state_fields.iter().zip(state_indices) {
        encoding::retarget_field(&mut bodies[0], *field, 4, destination.state[*index])
            .ok_or(Failure::Verification)?;
    }
    for field in table_fields {
        let old = word(&bodies[0], *field);
        let new = resources
            .iter()
            .find(|(from, _)| *from == old)
            .ok_or(Failure::Resources)?
            .1;
        encoding::retarget_field(&mut bodies[0], *field, 4, new).ok_or(Failure::Verification)?;
    }
    let (_, _, target_fields) = fields(destination.kind);
    let target_body = &target[destination.dispatch.clone()];
    for (index, field) in call_fields.iter().enumerate() {
        let field_target = if index + 1 == call_fields.len() {
            *target_fields.last().unwrap()
        } else {
            target_fields[0]
        };
        encoding::retarget_field(&mut bodies[0], *field, 3, call(target_body, field_target))
            .ok_or(Failure::Verification)?;
    }
    encoding::retarget_field(&mut bodies[1], 2, 4, destination.state[1])
        .ok_or(Failure::Verification)?;
    let store = bodies[1].len() - 6;
    for field in (20..store).step_by(8) {
        let old = word(&bodies[1], field);
        let new = resources
            .iter()
            .find(|(from, _)| *from == old)
            .ok_or(Failure::Resources)?
            .1;
        encoding::retarget_field(&mut bodies[1], field, 4, new).ok_or(Failure::Verification)?;
    }
    encoding::retarget_field(&mut bodies[1], store, 4, destination.state[2])
        .ok_or(Failure::Verification)?;
    Ok(Prepared {
        destination,
        source,
        bodies,
    })
}
/// Transplant whole native dispatcher and selector bodies, retaining original
/// caller entries through bounded in-place bodies or entry jumps. Table data
/// and executable/RAM ownership must be established by the composing operation.
pub fn transplant(
    target: &[u8],
    donor: &[u8],
    resources: &[(u32, u32)],
    reservations: [Option<Range<usize>>; 2],
) -> Result<Vec<u8>, Failure> {
    let Prepared {
        destination,
        source,
        bodies,
    } = prepare(target, donor, resources, &reservations)?;
    let regions = crate::image::regions(target).ok_or(Failure::Unresolved)?;
    let originals = [destination.dispatch.clone(), destination.selector.clone()];
    let mut writes: Vec<(Range<usize>, Vec<u8>)> = Vec::new();
    for (index, body) in bodies.into_iter().enumerate() {
        let original = originals[index].clone();
        let mut entry = alloc::vec![0;original.len()];
        encoding::nops(&mut entry).ok_or(Failure::Verification)?;
        if body.len() <= entry.len() {
            entry[..body.len()].copy_from_slice(&body);
        } else {
            let space = reservations[index].clone().ok_or(Failure::SpaceRequired)?;
            if space.start > space.end
                || space.start & 1 != 0
                || space.end & 1 != 0
                || space.len() < body.len()
                || !regions.stored.iter().any(|r| {
                    let at = r.as_ptr() as usize - target.as_ptr() as usize;
                    space.start >= at && space.end <= at + r.len()
                })
                || !target
                    .get(space.clone())
                    .is_some_and(|b| b.iter().all(|v| *v == 255))
                || originals
                    .iter()
                    .any(|r| r.start < space.end && space.start < r.end)
                || writes
                    .iter()
                    .any(|(r, _)| r.start < space.end && space.start < r.end)
            {
                return Err(Failure::InvalidSpace);
            }
            let address = u32::try_from(space.start)
                .ok()
                .and_then(|a| a.checked_add(0x410000))
                .filter(|a| *a <= 0xffffff)
                .ok_or(Failure::InvalidSpace)?;
            let jump = encoding::jump(address).ok_or(Failure::Verification)?;
            entry[..jump.len()].copy_from_slice(&jump);
            let mut emitted = alloc::vec![0;space.len()];
            encoding::nops(&mut emitted).ok_or(Failure::Verification)?;
            emitted[..body.len()].copy_from_slice(&body);
            writes.push((space, emitted));
        }
        writes.push((original, entry));
    }
    let mut changed = target.to_vec();
    for (span, bytes) in writes {
        changed[span].copy_from_slice(&bytes);
    }
    let actual = observe(&changed)?;
    let expected_tables = source
        .tables
        .iter()
        .map(|from| {
            resources
                .iter()
                .find(|(address, _)| address == from)
                .unwrap()
                .1
        })
        .collect::<Vec<_>>();
    if actual.kind != source.kind
        || actual.state != destination.state
        || actual.tables != expected_tables
        || actual.callers != destination.callers
    {
        return Err(Failure::Verification);
    }
    Ok(changed)
}

/// Relocate both entire native bodies and retarget all positively bound direct
/// caller JSRs. The composition must prove that these are the complete external
/// references, including Kernel and raw pointers, before retiring old entries.
/// Old dispatcher/selector bytes become erased storage; no neighboring routine
/// is retired. New ranges must be erased or wholly within those retired bodies.
pub fn transplant_relocating_entries(
    target: &[u8],
    donor: &[u8],
    resources: &[(u32, u32)],
    new_dispatch: Range<usize>,
    new_selector: Range<usize>,
) -> Result<Vec<u8>, Failure> {
    let spaces = [Some(new_dispatch.clone()), Some(new_selector.clone())];
    let Prepared {
        destination,
        source,
        bodies,
    } = prepare(target, donor, resources, &spaces)?;
    let originals = [destination.dispatch.clone(), destination.selector.clone()];
    let regions = crate::image::regions(target).ok_or(Failure::Unresolved)?;
    let ranges = [new_dispatch, new_selector];
    for (index, space) in ranges.iter().enumerate() {
        if space.start > space.end
            || space.start & 1 != 0
            || space.end & 1 != 0
            || space.len() < bodies[index].len()
            || !regions.stored.iter().any(|r| {
                let at = r.as_ptr() as usize - target.as_ptr() as usize;
                space.start >= at && space.end <= at + r.len()
            })
            || !target.get(space.clone()).is_some_and(|bytes| {
                bytes.iter().enumerate().all(|(at, b)| {
                    *b == 255
                        || originals
                            .iter()
                            .any(|old| old.contains(&(space.start + at)))
                })
            })
            || ranges[index + 1..]
                .iter()
                .any(|other| space.start < other.end && other.start < space.end)
            || destination
                .callers
                .iter()
                .flatten()
                .any(|call| space.start < call.end && call.start < space.end)
        {
            return Err(Failure::InvalidSpace);
        }
    }
    let mut output = target.to_vec();
    for original in originals {
        output[original].fill(255);
    }
    for (index, (range, body)) in ranges.iter().zip(bodies).enumerate() {
        let address = u32::try_from(range.start)
            .ok()
            .and_then(|at| at.checked_add(0x410000))
            .filter(|at| *at <= 0xffffff)
            .ok_or(Failure::InvalidSpace)?;
        encoding::nops(&mut output[range.clone()]).ok_or(Failure::Verification)?;
        output[range.start..range.start + body.len()].copy_from_slice(&body);
        for call in &destination.callers[index] {
            encoding::retarget_call(&mut output, call.start, address)
                .ok_or(Failure::Verification)?;
        }
    }
    let actual = observe(&output)?;
    let expected_tables = source
        .tables
        .iter()
        .map(|from| {
            resources
                .iter()
                .find(|(address, _)| address == from)
                .unwrap()
                .1
        })
        .collect::<Vec<_>>();
    if actual.kind != source.kind
        || actual.state != destination.state
        || actual.tables != expected_tables
        || actual.callers != destination.callers
        || actual.dispatch.start != ranges[0].start
        || actual.selector.start != ranges[1].start
    {
        return Err(Failure::Verification);
    }
    Ok(output)
}
