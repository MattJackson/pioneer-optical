//! Native byte physical driver adapted to a split target's software contract.
//!
//! The donor describes installed hardware. Its byte MMIO, trajectory and table
//! values are copied intact; the target retains its complete state lifecycle.
//! No conversion of ten-bit values into bytes is performed here.
use super::*;
const BYTE_ZERO: &[u8] = &[
    0x18, 0x88, 0x6a, 0x88, 0xf9, 0x08, 0x6a, 0x88, 0xf9, 0x09, 0x54, 0x70,
];

fn capacity(binding: &Binding, required: usize) -> Result<Range<usize>, Error> {
    let mut tables = binding.tables.clone();
    tables.sort_unstable_by_key(|range| range.start);
    if tables.windows(2).any(|pair| pair[0].end != pair[1].start) {
        return Err(Error::ResourceMismatch);
    }
    let range = tables[0].start..tables[4].end;
    if range.len() < required {
        return Err(Error::ResourceMismatch);
    }
    // Claim only bytes actually written. Other table bytes may have aliases
    // and need not be reclaimed merely because they share an old bank.
    Ok(range.end - required..range.end)
}

fn exclusive(
    target: &[u8],
    kernel: &[u8],
    binding: &Binding,
    storage: &Range<usize>,
) -> Result<(), Error> {
    if kernel.len() != crate::image::KERNEL_LEN {
        return Err(Error::Ownership);
    }
    // The complete command is unmodified, and the caller and zero entry retain
    // their ABI. Only their interiors, the retired output and reclaimed tables
    // need exclusive ownership.
    let protected = |address: usize| {
        address.checked_sub(0x410000).is_some_and(|offset| {
            (binding.zero.contains(&offset) && offset != binding.zero.start)
                || (binding.caller.contains(&offset) && offset != binding.caller.start)
                || binding.output.contains(&offset)
                || storage.contains(&offset)
        })
    };
    for (bytes, base) in [(target, 0x410000usize), (kernel, 0x400000)] {
        let regions = crate::image::regions(bytes).ok_or(Error::Ownership)?;
        for region in regions.stored {
            let start = region.as_ptr() as usize - bytes.as_ptr() as usize;
            for local in 0..region.len() {
                let offset = start + local;
                if base == 0x410000
                    && [
                        &binding.command,
                        &binding.caller,
                        &binding.output,
                        &binding.zero,
                        &binding.jump_table,
                    ]
                    .iter()
                    .copied()
                    .chain(binding.tables.iter())
                    .any(|range| range.contains(&offset))
                {
                    continue;
                }
                if local + 4 <= region.len() && protected(read(region, local, 4) as usize) {
                    return Err(Error::Ownership);
                }
                if offset & 1 != 0 {
                    continue;
                }
                let Ok(decoded) = decode_insn(&region[local..], Target::H8S2000, Mode::Advanced)
                else {
                    continue;
                };
                for operand in decoded.insn.operands {
                    let address = match operand {
                        O::Immediate {
                            value,
                            bits: 24 | 32,
                        }
                        | O::Address(Ea::Absolute {
                            value,
                            bits: 24 | 32,
                        }) => Some(value as usize),
                        O::Address(Ea::PcRelative { value, .. }) => {
                            (base + offset + decoded.len).checked_add_signed(value as isize)
                        }
                        O::Address(Ea::Displacement {
                            value, bits: 32, ..
                        }) => Some(value as usize),
                        _ => None,
                    };
                    if address.is_some_and(protected) {
                        return Err(Error::Ownership);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Complete adapted command, target software services and donor physical driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adapted {
    /// Exact donor grammar used by the specialized physical driver.
    pub shape: usize,
    /// Unmodified target phase command, including all state writes.
    pub command: Range<usize>,
    /// Target software-service prefix and exact byte-driver ABI adapter.
    pub caller: Range<usize>,
    /// Original zero entry with the donor's native byte hardware stores.
    pub zero: Range<usize>,
    /// Exclusively owned, retired split-word output body.
    pub retired_output: Range<usize>,
    /// Donor output slice with all original branches and MMIO stores.
    pub driver: Range<usize>,
    /// Donor's native coefficient banks in grammar reference order.
    pub tables: Vec<Range<usize>>,
    /// Original target mode getter.
    pub mode_getter: Range<usize>,
}

// The byte command's initial MOV copies both mode and phase into r2 before
// bookkeeping. Its output starts with AND #63,r2l, which overwrites CCR. The
// only other live input is r1l, untouched by bookkeeping. Every output path
// defines r0, er1 and er3 before reading them. The final phase-state store is
// after the last MMIO store and has no outgoing branch. These two slices can
// therefore be removed while retaining the target command's state lifecycle.
fn driver(code: &[u8], shape: usize) -> Result<(Vec<u8>, Vec<usize>), Error> {
    let keep: Vec<Range<usize>> = match shape {
        0 => alloc::vec![0..6, 66..260, 266..272],
        1 => alloc::vec![0..6, 64..264, 268..274],
        2 => alloc::vec![0..10, 68..70, 136..396, 400..406],
        6 => alloc::vec![0..8, 66..68, 134..394, 398..404],
        _ => return Err(Error::Unresolved),
    };
    if code.len() != templates::TEMPLATES[shape].bytes.len() {
        return Err(Error::Unresolved);
    }
    let mut map = alloc::vec![usize::MAX;code.len()+1];
    let mut result = Vec::new();
    for range in keep {
        for old in range {
            map[old] = result.len();
            result.push(code[old]);
        }
    }
    map[code.len()] = result.len();
    let instructions = decoded(&result)?;
    for (offset, instruction, len) in &instructions {
        if let O::Address(Ea::PcRelative { value, .. }) = instruction.operands[0] {
            let destination = (offset + len)
                .checked_add_signed(value as isize)
                .ok_or(Error::Verification)?;
            if !instructions.iter().any(|(at, _, _)| *at == destination) {
                return Err(Error::Verification);
            }
        }
    }
    Ok((result, map))
}
fn bank_references(template: &Template) -> Vec<u32> {
    let mut banks: Vec<_> = template
        .relocations
        .iter()
        .filter(|field| {
            matches!(field.kind, RelocationKind::Address) && field.reference >= 0x410000
        })
        .map(|field| field.reference & !1)
        .collect();
    banks.sort_unstable();
    banks.dedup();
    banks
}
fn physical_value(
    template: &Template,
    map: &[usize],
    field: &Relocation,
    body: usize,
    tables: &[Range<usize>],
    direction: u32,
) -> Result<u32, Error> {
    match field.kind {
        RelocationKind::Address if field.reference >= 0x410000 => {
            let references = bank_references(template);
            let index = references
                .iter()
                .position(|value| *value == field.reference & !1)
                .ok_or(Error::ResourceMismatch)?;
            Ok(0x410000 + tables[index].start as u32 + (field.reference & 1))
        }
        RelocationKind::Address => Ok(direction),
        RelocationKind::Jump => {
            let old = (field.reference - template.reference_cpu) as usize;
            let offset = *map.get(old).ok_or(Error::ResourceMismatch)?;
            if offset == usize::MAX {
                return Err(Error::ResourceMismatch);
            }
            Ok(0x410000 + body as u32 + offset as u32)
        }
        _ => Err(Error::Unresolved),
    }
}
type PhysicalBinding = (usize, Range<usize>, Vec<Range<usize>>);
fn bind_driver(normal: &[u8], address: u32, direction: u32) -> Result<PhysicalBinding, Error> {
    for shape_id in [0, 1, 2, 6] {
        let template = &templates::TEMPLATES[shape_id];
        let (code, map) = driver(template.bytes, shape_id)?;
        let mut shape: Vec<_> = code.into_iter().map(Some).collect();
        let fields: Vec<_> = template
            .relocations
            .iter()
            .filter(|field| map[field.start] != usize::MAX)
            .collect();
        for field in &fields {
            shape[map[field.start]..map[field.start] + field.end - field.start].fill(None);
        }
        let body = stored(normal, address, shape.len())?;
        let bytes = &normal[body.clone()];
        if !fits(bytes, &shape) {
            continue;
        }
        let references = bank_references(template);
        let tables: Vec<_> = (0..references.len())
            .map(|index| stored(normal, 0x410000 + body.end as u32 + index as u32 * 128, 128))
            .collect::<Result<_, _>>()?;
        if fields.iter().any(|field| {
            physical_value(template, &map, field, body.start, &tables, direction).ok()
                != Some(read(bytes, map[field.start], field.end - field.start))
        }) {
            continue;
        }
        return Ok((shape_id, body, tables));
    }
    Err(Error::Unresolved)
}

/// Independently bind the entire adapted graph, not just its output signature.
pub fn observe_normal(normal: &[u8]) -> Result<Adapted, Error> {
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let mut result = None;
    for command_start in
        crate::filters::phase::bundle::sites(normal, &regions.stored, &COMMAND[..16])
    {
        let command = stored(normal, 0x410000 + command_start as u32, 174)?;
        let code = &normal[command.clone()];
        if !fits(code, COMMAND) || read(code, 134, 4) != read(code, 156, 4) {
            continue;
        }
        let caller_start = command.end + 2;
        let Some(caller_code) = normal.get(caller_start..caller_start + 84) else {
            continue;
        };
        if !fits(&caller_code[..66], &DIRECT_CALLER[..66])
            || caller_code[66..75] != [0x0d, 0xe0, 0x0c, 0x80, 0x0c, 0x68, 0x0c, 0xe9, 0x5e]
            || caller_code[78..] != [0x01, 0x20, 0x6d, 0x76, 0x54, 0x70]
        {
            continue;
        }
        let Ok((shape_id, output, tables)) =
            bind_driver(normal, read(caller_code, 75, 3), read(code, 134, 4))
        else {
            continue;
        };
        let state = read(code, 12, 4);
        let flag = read(caller_code, 38, 4);
        if state == 0
            || state.checked_add(17).map_or(true, |end| end >= 0x400000)
            || flag.checked_add(2) != Some(read(code, 134, 4))
            || read(caller_code, 63, 3) < 0x400000
            || read(caller_code, 63, 3) & 1 != 0
        {
            continue;
        }
        let getter = stored(normal, read(caller_code, 45, 3), 18)?;
        let getter_code = &normal[getter.clone()];
        if getter_code[..2] != [0x6a, 0x28]
            || read(getter_code, 2, 4) != state + 13
            || getter_code[6..] != [0xa8, 3, 0x46, 4, 0xf8, 1, 0x40, 2, 0x18, 0x88, 0x54, 0x70]
        {
            continue;
        }
        for capacity in [146, 152] {
            let caller = stored(normal, 0x410000 + caller_start as u32, capacity)?;
            let zero = stored(normal, 0x410000 + caller.end as u32, 20)?;
            let retired = stored(normal, 0x410000 + zero.end as u32, 174)?;
            if normal[caller_start + 84..caller.end]
                .iter()
                .any(|b| *b != 0)
                || normal[zero.start..zero.start + 12] != *BYTE_ZERO
                || normal[zero.start + 12..zero.end].iter().any(|b| *b != 0)
                || normal[retired.clone()].iter().any(|b| *b != 0)
            {
                continue;
            }
            let graph = Adapted {
                shape: shape_id,
                command: command.clone(),
                caller,
                zero,
                retired_output: retired,
                driver: output.clone(),
                tables: tables.clone(),
                mode_getter: getter.clone(),
            };
            let mut ranges = alloc::vec![
                &graph.command,
                &graph.caller,
                &graph.zero,
                &graph.retired_output,
                &graph.driver,
                &graph.mode_getter,
            ];
            ranges.extend(graph.tables.iter());
            if ranges.iter().enumerate().any(|(index, a)| {
                ranges[index + 1..]
                    .iter()
                    .any(|b| a.start < b.end && b.start < a.end)
            }) {
                return Err(Error::ResourceMismatch);
            }
            if result.as_ref().is_some_and(|old| *old != graph) {
                return Err(Error::Unresolved);
            }
            result = Some(graph);
        }
    }
    result.ok_or(Error::Unresolved)
}

/// Keep the target's complete state and software-service contract while
/// installing the donor's native physical driver without quantization.
pub fn transplant(target: &[u8], target_kernel: &[u8], donor: &[u8]) -> Result<Vec<u8>, Error> {
    let target_binding = super::observe(target, target_kernel)?;
    let target_graph = bind(target)?;
    if target_graph.selector_compact != 0 || target_graph.compact {
        return Err(Error::Unresolved);
    }
    let donor_binding = byte_pair::observe_normal(donor)?;
    if !matches!(donor_binding.shape, 0..=2) || !donor_binding.complete_command {
        return Err(Error::Unresolved);
    }
    let donor_regions = crate::image::regions(donor).ok_or(Error::Unresolved)?;
    let zero_shape: Vec<_> = BYTE_ZERO.iter().copied().map(Some).collect();
    let zero_sites =
        crate::filters::phase::bundle::sites(donor, &donor_regions.stored, &zero_shape);
    if zero_sites.len() != 1 {
        return Err(Error::Unresolved);
    }
    let (mut physical, map) = driver(&donor[donor_binding.body.clone()], donor_binding.shape)?;
    let template = &templates::TEMPLATES[donor_binding.shape];
    let references = bank_references(template);
    if references.len() != donor_binding.coefficients.len() {
        return Err(Error::ResourceMismatch);
    }
    let storage = capacity(&target_binding, physical.len() + references.len() * 128)?;
    exclusive(target, target_kernel, &target_binding, &storage)?;
    let body = storage.start..storage.start + physical.len();
    let coefficient_start = body.end;
    let tables: Vec<_> = (0..references.len())
        .map(|index| coefficient_start + index * 128..coefficient_start + (index + 1) * 128)
        .collect();
    for relocation in template
        .relocations
        .iter()
        .filter(|field| map[field.start] != usize::MAX)
    {
        field(
            &mut physical,
            map[relocation.start],
            relocation.end - relocation.start,
            physical_value(
                template,
                &map,
                relocation,
                body.start,
                &tables,
                target_binding.state[1],
            )?,
        )?;
    }
    let mut changed = target.to_vec();
    for range in [
        &target_binding.caller,
        &target_binding.output,
        &target_binding.zero,
        &storage,
    ] {
        encoding::nops(&mut changed[range.clone()]).ok_or(Error::ResourceMismatch)?;
    }
    changed[body.clone()].copy_from_slice(&physical);
    for (index, source) in donor_binding.coefficients.iter().enumerate() {
        let byte_pair::Coefficients::Rom(source) = source else {
            return Err(Error::ResourceMismatch);
        };
        if index >= references.len() || source.len() != 128 {
            return Err(Error::ResourceMismatch);
        }
        let destination = coefficient_start + index * 128;
        changed[destination..destination + 128].copy_from_slice(&donor[source.clone()]);
    }
    changed[target_binding.zero.start..target_binding.zero.start + 12]
        .copy_from_slice(&donor[zero_sites[0]..zero_sites[0] + 12]);
    let mut caller = target_graph.caller_code[..66].to_vec();
    // Saved E6 holds mode; r6h holds phase; r6l holds the output-mode argument.
    caller.extend_from_slice(&[
        0x0d, 0xe0, 0x0c, 0x80, 0x0c, 0x68, 0x0c, 0xe9, 0x5e, 0, 0, 0,
    ]);
    field(&mut caller, 75, 3, 0x410000 + body.start as u32)?;
    caller.extend_from_slice(&target_graph.caller_code[target_graph.caller_code.len() - 6..]);
    decoded(&caller)?;
    changed[target_binding.caller.start..target_binding.caller.start + caller.len()]
        .copy_from_slice(&caller);
    let rebound = observe_normal(&changed).map_err(|_| Error::Verification)?;
    if rebound.command != target_binding.command
        || rebound.driver != body
        || changed[rebound.command.clone()] != target[rebound.command.clone()]
    {
        return Err(Error::Verification);
    }
    Ok(changed)
}

/// Compare the independently rebound complete mechanism after shared edits.
pub fn verify(
    target: &[u8],
    target_kernel: &[u8],
    donor: &[u8],
    changed: &[u8],
) -> Result<(), Error> {
    let expected = transplant(target, target_kernel, donor)?;
    let original = super::observe(target, target_kernel)?;
    if observe_normal(changed).map_err(|_| Error::Verification)? != observe_normal(&expected)? {
        return Err(Error::Verification);
    }
    for range in [
        &original.command,
        &original.caller,
        &original.output,
        &original.zero,
        &original.jump_table,
        &original.mode_getter,
    ]
    .into_iter()
    .chain(original.tables.iter())
    {
        if changed.get(range.clone()) != expected.get(range.clone()) {
            return Err(Error::Verification);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split_fixture() -> (Vec<u8>, Vec<u8>) {
        let fixtures: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../tests/fixtures/phase-sat1-native.json"
        ))
        .unwrap();
        let fixture = &fixtures[0];
        let mut normal = alloc::vec![255; fixture["normal_len"].as_u64().unwrap() as usize];
        let mut kernel = alloc::vec![255; crate::image::KERNEL_LEN];
        for span in fixture["spans"].as_array().unwrap() {
            let address = span[0].as_u64().unwrap() as usize;
            let (destination, offset) = if address >= 0x410000 {
                (&mut normal, address - 0x410000)
            } else {
                (&mut kernel, address - 0x400000)
            };
            let hex = span[1].as_str().unwrap();
            for index in 0..hex.len() / 2 {
                destination[offset + index] =
                    u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
            }
        }
        (normal, kernel)
    }

    #[test]
    fn complete_byte_driver_relocates_into_owned_split_rom() {
        let (target, kernel) = split_fixture();
        let template = &templates::TEMPLATES[0];
        let mut donor = alloc::vec![255; 0x210000];
        let entry = (template.reference_cpu - 0x410000) as usize;
        donor[entry..entry + template.bytes.len()].copy_from_slice(template.bytes);
        donor[entry + template.bytes.len() + 2..entry + template.bytes.len() + 2 + BYTE_ZERO.len()]
            .copy_from_slice(BYTE_ZERO);
        let donor_binding = byte_pair::observe_normal(&donor).unwrap();
        for (index, coefficient) in donor_binding.coefficients.iter().enumerate() {
            let byte_pair::Coefficients::Rom(range) = coefficient else {
                panic!()
            };
            for (offset, byte) in donor[range.clone()].iter_mut().enumerate() {
                *byte = (offset + index * 31) as u8;
            }
        }
        let before = observe(&target, &kernel).unwrap();
        let changed = transplant(&target, &kernel, &donor).unwrap();
        verify(&target, &kernel, &donor, &changed).unwrap();
        assert_eq!(
            super::super::super::discover(&changed).compare(&super::super::super::discover(&donor)),
            Some(true)
        );
        let after = observe_normal(&changed).unwrap();
        for (source, destination) in donor_binding.coefficients.iter().zip(&after.tables) {
            let byte_pair::Coefficients::Rom(source) = source else {
                panic!()
            };
            assert_eq!(donor[source.clone()], changed[destination.clone()]);
        }
        for (offset, (old, new)) in target.iter().zip(&changed).enumerate() {
            if old != new {
                assert!(
                    before.command.contains(&offset)
                        || before.caller.contains(&offset)
                        || before.output.contains(&offset)
                        || before.zero.contains(&offset)
                        || before.tables.iter().any(|range| range.contains(&offset))
                );
            }
        }
        let mut corrupted = changed.clone();
        corrupted[before.command.start + 3] ^= 2;
        assert_eq!(
            verify(&target, &kernel, &donor, &corrupted),
            Err(Error::Verification)
        );
        let mut aliased = kernel.clone();
        // An alias to untouched table storage does not prevent reclaiming the
        // independently owned tail. This includes numerical data that happens
        // to look like an address, without a heuristic exemption for strings.
        aliased[64..68].copy_from_slice(&(0x410000 + before.tables[0].start as u32).to_be_bytes());
        assert_eq!(transplant(&target, &aliased, &donor).unwrap(), changed);
        aliased[64..68].copy_from_slice(&(0x410000 + after.driver.start as u32).to_be_bytes());
        assert_eq!(transplant(&target, &aliased, &donor), Err(Error::Ownership));
        assert_eq!(
            transplant(&target, &[], &donor),
            Err(Error::ResourceMismatch)
        );
    }
}
