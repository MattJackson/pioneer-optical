//! Native byte-pair resource graphs. Output-only shapes deliberately do not
//! establish the upstream command or the initialization of RAM coefficients.
use super::*;
mod command;
/// Native three-bank coefficient production graph.
pub mod generated;

/// Proven coefficient storage; RAM banks require a separately bound initializer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Coefficients {
    /// Sixty-four interleaved byte pairs stored in Normal ROM.
    Rom(Range<usize>),
    /// Sixty-four interleaved byte pairs read from live RAM.
    Ram(u32),
}
/// Resource binding for one exact native byte-pair instruction graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Exact instruction grammar identity; equality is required for table copying.
    pub shape: usize,
    /// Entire matched instruction body.
    pub body: Range<usize>,
    /// Separate upstream command when the native output body is a leaf.
    pub command: Option<Range<usize>>,
    /// Whether this body includes its command and persistent-state updates.
    pub complete_command: bool,
    /// Native coefficient banks, sorted by the grammar's reference address.
    pub coefficients: Vec<Coefficients>,
    /// Target-owned RAM operands other than coefficient banks.
    pub state: Vec<u32>,
    /// Retained direct second-output leaf, when the body uses one.
    pub output_leaf: Option<Range<usize>>,
}

fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

fn bind_at(normal: &[u8], shape: usize, t: &Template, at: usize) -> Result<Binding, Error> {
    if !template_matches(t, normal, at) {
        return Err(Error::Unresolved);
    }
    let body = stored(normal, 0x410000 + at as u32, t.bytes.len())?;
    let code = &normal[body.clone()];
    let complete_command = matches!(t.bytes.len(), 272 | 274 | 404 | 406);
    // The two short output selectors consume RAM banks. Their literals must
    // never be mistaken for persistent-state slots or offsets into Normal ROM.
    let ram_tables = matches!(t.bytes.len(), 118 | 156);
    let mut banks: Vec<(u32, u32)> = Vec::new();
    let mut state = Vec::new();
    let mut output_leaf = None;
    for r in t.relocations {
        let value = integer(&code[r.start..r.end]);
        match r.kind {
            RelocationKind::Address if r.reference >= 0x410000 || ram_tables => {
                let reference = r.reference & !1;
                let base = value
                    .checked_sub(r.reference & 1)
                    .ok_or(Error::ResourceMismatch)?;
                if base & 1 != 0 {
                    return Err(Error::ResourceMismatch);
                }
                if let Some((_, existing)) = banks.iter().find(|(key, _)| *key == reference) {
                    if *existing != base {
                        return Err(Error::ResourceMismatch);
                    }
                } else {
                    banks.push((reference, base));
                }
            }
            RelocationKind::Address => {
                if value == 0 || value >= 0x400000 {
                    return Err(Error::ResourceMismatch);
                }
                if !state.contains(&value) {
                    state.push(value);
                }
            }
            RelocationKind::Call => {
                let leaf = stored(normal, value, 6)?;
                if normal[leaf.clone()] != [0x6a, 0x88, 0xf9, 9, 0x54, 0x70]
                    || output_leaf.as_ref().is_some_and(|old| *old != leaf)
                {
                    return Err(Error::ResourceMismatch);
                }
                output_leaf = Some(leaf);
            }
            RelocationKind::Jump => {
                // No external transfer can be admitted as a complete graph.
                if !(0x410000 + body.start as u32..0x410000 + body.end as u32).contains(&value) {
                    return Err(Error::ResourceMismatch);
                }
            }
        }
    }
    banks.sort_unstable_by_key(|(reference, _)| *reference);
    // All native banks are contiguous 128-byte records. This also binds the
    // relationships that the legacy matcher only checks for adjacent bytes.
    for pair in banks.windows(2) {
        if pair[1].1.checked_sub(pair[0].1) != pair[1].0.checked_sub(pair[0].0) {
            return Err(Error::ResourceMismatch);
        }
    }
    let mut coefficients = Vec::new();
    for (_, address) in banks {
        if ram_tables {
            if address == 0 || address.checked_add(128).map_or(true, |end| end >= 0x400000) {
                return Err(Error::ResourceMismatch);
            }
            coefficients.push(Coefficients::Ram(address));
        } else {
            let table = stored(normal, address, 128)?;
            if overlaps(&body, &table)
                || output_leaf
                    .as_ref()
                    .is_some_and(|leaf| overlaps(leaf, &table))
                || coefficients
                    .iter()
                    .any(|other| matches!(other, Coefficients::Rom(r) if overlaps(r, &table)))
            {
                return Err(Error::ResourceMismatch);
            }
            coefficients.push(Coefficients::Rom(table));
        }
    }
    if coefficients.is_empty() {
        return Err(Error::ResourceMismatch);
    }
    // Every relative transfer must terminate at a decoded native instruction.
    // Absolute internal jumps were already checked by the template matcher.
    let instructions = decoded(code)?;
    for (offset, instruction, length) in &instructions {
        if let O::Address(Ea::PcRelative { value, .. }) = instruction.operands[0] {
            let destination = (offset + length)
                .checked_add_signed(value as isize)
                .ok_or(Error::ResourceMismatch)?;
            if !instructions.iter().any(|(at, _, _)| *at == destination) {
                return Err(Error::ResourceMismatch);
            }
        }
    }
    Ok(Binding {
        // Grammar 9 is grammar 4 with its two internal jump destinations
        // written literally instead of listed as relocations.
        shape: if shape == 9 { 4 } else { shape },
        body,
        command: None,
        complete_command,
        coefficients,
        state,
        output_leaf,
    })
}

/// Bind all native byte-pair output shapes without conflating output recognition
/// with complete upstream command or RAM-initialization proof.
pub fn observe_normal(normal: &[u8]) -> Result<Binding, Error> {
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let mut result = None;
    for (shape, template) in templates::TEMPLATES.iter().enumerate() {
        if template.interface != Interface::BytePair {
            continue;
        }
        let prefix: Vec<_> = template.bytes[..4].iter().copied().map(Some).collect();
        for at in crate::filters::phase::bundle::sites(normal, &regions.stored, &prefix) {
            if let Ok(mut binding) = bind_at(normal, shape, template, at) {
                // Output discovery remains useful without a command proof; the
                // correction gate requires complete_command below.
                let _ = command::bind(normal, &mut binding);
                if result.as_ref().is_some_and(|old| *old != binding) {
                    return Err(Error::Unresolved);
                }
                result = Some(binding);
            }
        }
    }
    result.ok_or(Error::Unresolved)
}

/// Copy coefficients only between identical complete command grammars. Target
/// code, persistent-state addresses and output ABI remain byte-for-byte intact.
/// Cross-grammar and RAM-backed cases require a separate semantic lowering.
pub fn transplant(target: &[u8], target_kernel: &[u8], donor: &[u8]) -> Result<Vec<u8>, Error> {
    let a = observe_normal(target)?;
    let b = observe_normal(donor)?;
    if !a.complete_command || !b.complete_command || a.shape != b.shape {
        return Err(Error::Unresolved);
    }
    if target_kernel.len() != crate::image::KERNEL_LEN {
        return Err(Error::ResourceMismatch);
    }
    let tables = |binding: &Binding| -> Result<Vec<Range<usize>>, Error> {
        binding
            .coefficients
            .iter()
            .map(|table| match table {
                Coefficients::Rom(range) => Ok(range.clone()),
                Coefficients::Ram(_) => Err(Error::Unresolved),
            })
            .collect()
    };
    let destinations = tables(&a)?;
    let sources = tables(&b)?;
    if destinations.len() != sources.len() {
        return Err(Error::ResourceMismatch);
    }
    if destinations
        .iter()
        .zip(&sources)
        .all(|(x, y)| target[x.clone()] == donor[y.clone()])
    {
        return Ok(target.to_vec());
    }
    // Refuse visible table aliases outside the positively bound command body.
    // Checking byte windows includes unaligned pointers embedded in data.
    for (bytes, is_normal) in [(target, true), (target_kernel, false)] {
        let regions = crate::image::regions(bytes).ok_or(Error::Ownership)?;
        for region in regions.stored {
            let start = region.as_ptr() as usize - bytes.as_ptr() as usize;
            for (offset, window) in region.windows(4).enumerate() {
                if is_normal
                    && (a.body.contains(&(start + offset))
                        || a.command
                            .as_ref()
                            .is_some_and(|range| range.contains(&(start + offset))))
                {
                    continue;
                }
                let protects = |value: u32| {
                    value.checked_sub(0x410000).is_some_and(|address| {
                        destinations
                            .iter()
                            .any(|range| range.contains(&(address as usize)))
                    })
                };
                if protects(integer(window)) {
                    return Err(Error::Ownership);
                }
                if (start + offset) & 1 == 0 {
                    if let Ok(decoded) =
                        decode_insn(&region[offset..], Target::H8S2000, Mode::Advanced)
                    {
                        for operand in decoded.insn.operands {
                            let address = match operand {
                                O::Immediate {
                                    value,
                                    bits: 24 | 32,
                                }
                                | O::Address(Ea::Absolute {
                                    value,
                                    bits: 24 | 32,
                                }) => Some(value),
                                O::Address(Ea::Displacement {
                                    value, bits: 32, ..
                                }) => Some(value as u32),
                                _ => None,
                            };
                            if address.is_some_and(protects) {
                                return Err(Error::Ownership);
                            }
                        }
                    }
                }
            }
        }
    }
    let mut changed = target.to_vec();
    for (destination, source) in destinations.iter().zip(&sources) {
        changed[destination.clone()].copy_from_slice(&donor[source.clone()]);
    }
    if observe_normal(&changed)? != a || changed[a.body.clone()] != target[a.body.clone()] {
        return Err(Error::Verification);
    }
    Ok(changed)
}

/// Rebind and compare every owned instruction and coefficient byte after shared
/// composition; unrelated owners may change disjoint resources.
pub fn verify(
    target: &[u8],
    target_kernel: &[u8],
    donor: &[u8],
    changed: &[u8],
) -> Result<(), Error> {
    let expected = transplant(target, target_kernel, donor)?;
    let binding = observe_normal(&expected)?;
    if observe_normal(changed)? != binding
        || expected[binding.body.clone()] != changed[binding.body.clone()]
    {
        return Err(Error::Verification);
    }
    if let Some(command) = &binding.command {
        if expected[command.clone()] != changed[command.clone()] {
            return Err(Error::Verification);
        }
    }
    for table in &binding.coefficients {
        let Coefficients::Rom(range) = table else {
            return Err(Error::Verification);
        };
        if expected[range.clone()] != changed[range.clone()] {
            return Err(Error::Verification);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn fixture(shape: usize) -> Vec<u8> {
        let template = &templates::TEMPLATES[shape];
        let mut normal = alloc::vec![255; 0x210000];
        let at = (template.reference_cpu - 0x410000) as usize;
        normal[at..at + template.bytes.len()].copy_from_slice(template.bytes);
        for relocation in template.relocations {
            if matches!(relocation.kind, RelocationKind::Call) {
                let offset = (relocation.reference - 0x410000) as usize;
                normal[offset..offset + 6].copy_from_slice(&[0x6a, 0x88, 0xf9, 9, 0x54, 0x70]);
            }
        }
        normal
    }

    #[test]
    fn byte_pair_resource_graphs_distinguish_rom_ram_and_command_scope() {
        for (shape, template) in templates::TEMPLATES.iter().enumerate() {
            if template.interface != Interface::BytePair {
                continue;
            }
            let normal = fixture(shape);
            let binding = bind_at(
                &normal,
                shape,
                template,
                (template.reference_cpu - 0x410000) as usize,
            )
            .unwrap();
            assert_eq!(binding.complete_command, matches!(shape, 0 | 1 | 2 | 6));
            assert_eq!(
                binding
                    .coefficients
                    .iter()
                    .all(|table| matches!(table, Coefficients::Ram(_))),
                matches!(shape, 7 | 8)
            );
        }
    }

    #[test]
    fn byte_pair_rejects_detached_repeated_table_operands() {
        let mut normal = fixture(0);
        let template = &templates::TEMPLATES[0];
        let at = (template.reference_cpu - 0x410000) as usize;
        // Normal table is repeated far apart, not merely in adjacent bytes.
        normal[at + 201] ^= 2;
        assert!(bind_at(&normal, 0, template, at).is_err());
    }

    #[test]
    fn byte_pair_same_shape_copy_preserves_code_and_rejects_visible_aliases() {
        let target = fixture(0);
        let mut donor = fixture(0);
        let binding = observe_normal(&target).unwrap();
        let Coefficients::Rom(table) = &binding.coefficients[0] else {
            panic!()
        };
        donor[table.clone()].fill(37);
        let kernel = alloc::vec![255; crate::image::KERNEL_LEN];
        let changed = transplant(&target, &kernel, &donor).unwrap();
        assert_eq!(changed[table.clone()], donor[table.clone()]);
        verify(&target, &kernel, &donor, &changed).unwrap();
        let mut corrupted = changed.clone();
        corrupted[table.start] ^= 1;
        assert_eq!(
            verify(&target, &kernel, &donor, &corrupted),
            Err(Error::Verification)
        );
        assert_eq!(changed[binding.body.clone()], target[binding.body.clone()]);
        let mut aliased = target.clone();
        aliased[64..68].copy_from_slice(&(0x410000 + table.start as u32).to_be_bytes());
        assert_eq!(transplant(&aliased, &kernel, &donor), Err(Error::Ownership));
        assert_eq!(
            transplant(&target, &kernel, &fixture(1)),
            Err(Error::Unresolved)
        );
    }
}
