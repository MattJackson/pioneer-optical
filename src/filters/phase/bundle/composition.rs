//! Compose independent native rewrites against one immutable target image.
//! Callers retain code-space, live-prerequisite, codec and checksum authority.
use super::{conversions, waveforms, Bundle, Unbound};
use crate::filters::phase::native::{calibration, sources};
use alloc::vec::Vec;
use core::ops::Range;

/// Explicit caller-owned executable reservations for growing routines.
#[derive(Clone, Debug, Default)]
pub struct Space {
    /// Base, offset and step conversion programs, respectively.
    pub conversions: [Option<Range<usize>>; 3],
    /// Calibration-word reader.
    pub calibration: Option<Range<usize>>,
    /// Source-word exchange program.
    pub sources: Option<Range<usize>>,
}

/// A complete atomic composition was not proved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A complete convention bundle was not bound.
    Bundle(Unbound),
    /// Conversion stage refused.
    Conversions(conversions::Error),
    /// Calibration reader refused.
    Calibration(calibration::Error),
    /// Source exchange refused.
    Sources(sources::Error),
    /// Waveform stage refused.
    Waveforms(waveforms::Error),
    /// Two stages or reservations conflict, or final native facts disagree.
    VerificationFailed,
    /// A growing composition lacks exact resident evidence or has an observed
    /// external entry/address-taken use of its retired native routine.
    ComponentOwnership,
}

/// Compare the bound static convention apart from its separately owned coil
/// assignment, and every selected image waveform.
/// Equal coil labels and arithmetic template identifiers alone do not establish
/// a no-op: two images can use identical programs with different table words.
/// Both native parameter-selection branches must agree before skipping the
/// operation, because a no-op carries no live selection prerequisite.
pub fn equivalent(target: &[u8], installed: &[u8]) -> Result<bool, Error> {
    if super::bind(target).map_err(Error::Bundle)?.without_coil()
        != super::bind(installed)
            .map_err(Error::Bundle)?
            .without_coil()
        || calibration::observe(target).map_err(Error::Calibration)?
            != calibration::observe(installed).map_err(Error::Calibration)?
    {
        return Ok(false);
    }
    let output = |image| {
        crate::filters::phase::native::encoders::observe(image)
            .map(|binding| binding.representation)
            .map_err(|_| Error::Sources(sources::Error::Unresolved))
    };
    if output(target)? != output(installed)? {
        return Ok(false);
    }
    let destination = waveforms::resources::observe(target)
        .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?;
    let source = waveforms::resources::observe(installed)
        .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?;
    if destination.erased_parameter.is_some() != source.erased_parameter.is_some() {
        return Ok(false);
    }
    if !waveforms::resources::static_tables::equivalent(target, installed)
        .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?
    {
        return Ok(false);
    }
    Ok(core::iter::once(&destination.selected)
        .chain(&destination.erased_parameter)
        .zip(core::iter::once(&source.selected).chain(&source.erased_parameter))
        .all(|(a, b)| {
            a.motion
                .iter()
                .chain(&a.coefficients)
                .zip(b.motion.iter().chain(&b.coefficients))
                .all(|(a, b)| target[a.clone()] == installed[b.clone()])
        }))
}

/// Preserve complete native code witnesses, including unchanged helper and
/// relocation operands, when disjoint filter owners compose their effects.
pub(crate) fn verify_program_bytes(expected: &[u8], changed: &[u8]) -> Result<(), Error> {
    let mut protected = conversions::protected_ranges(expected).map_err(Error::Conversions)?;
    protected.extend(calibration::protected_ranges(expected).map_err(Error::Calibration)?);
    let output = crate::filters::phase::native::encoders::observe(expected)
        .map_err(|_| Error::Sources(sources::Error::Unresolved))?;
    protected.extend(output.programs.into_iter().flatten());
    protected.push(output.leaf);
    let resources = waveforms::resources::observe(expected)
        .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?;
    protected.push(resources.dispatch);
    protected.extend(resources.initializer);
    protected.push(
        waveforms::resources::static_tables::observe(expected)
            .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?
            .selector,
    );
    let loader = waveforms::loader::observe(expected)
        .map_err(|e| Error::Waveforms(waveforms::Error::Loader(e)))?;
    protected.extend(loader.spans);
    let reader = waveforms::loader::readback::observe(expected, loader.readback, loader.writer)
        .map_err(|e| Error::Waveforms(waveforms::Error::Loader(e)))?;
    protected.push(reader.program);
    protected.extend(reader.clear);
    protected.push(
        waveforms::loader::writer::observe(expected, loader.writer)
            .map_err(|e| Error::Waveforms(waveforms::Error::Loader(e)))?
            .program,
    );
    for table in loader.tables.into_iter().flatten() {
        if let waveforms::loader::Table::Pointer(address) = table {
            if let Some(at) = address.checked_sub(0x410000) {
                protected.push(at as usize..at as usize + 4);
            }
        }
    }
    let regions = crate::image::regions(expected).ok_or(Error::VerificationFailed)?;
    for template in super::MODE {
        for inverted in [false, true] {
            let mut template = template.to_vec();
            if inverted {
                template[6] = Some(0x47);
            }
            protected.extend(
                super::sites(expected, &regions.stored, &template)
                    .into_iter()
                    .map(|at| at..at + template.len()),
            );
        }
    }
    for template in super::CONTROLLER {
        protected.extend(
            super::sites(expected, &regions.stored, template)
                .into_iter()
                .map(|at| at..at + template.len()),
        );
    }
    if protected
        .iter()
        .any(|span| expected.get(span.clone()) != changed.get(span.clone()))
    {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

/// Compose actual OEM donor routines and tables, with target helper relocation.
/// The caller owns all executable reservations and live read prerequisites.
/// Indirect donor table loads use read-only pointer cells in loader_space.
/// Source routines, conversions and calibration readers reuse original space and spill overflow
/// only at instruction boundaries with no relative branches crossing the split.
/// Loader growth also retains the original prefix and spills only its suffix.
pub fn transplant(
    target: &[u8],
    installed: &[u8],
    space: Space,
    loader_space: Option<Range<usize>>,
) -> Result<Vec<u8>, Error> {
    transplant_with_waveforms(target, installed, space, loader_space, false, None)
}

/// Compose the installed effective waveform using native plain-load
/// specialization. This allocates no code or pointer cells outside the bound
/// target routines and preserves the read-only selection prerequisite.
pub fn transplant_specialized(target: &[u8], installed: &[u8]) -> Result<Vec<u8>, Error> {
    transplant_specialized_with_kernel(target, installed, None)
}

/// Include exact resident evidence for native conversion scratch-register
/// liveness when a bound Normal caller enters a Kernel helper.
pub fn transplant_specialized_with_kernel(
    target: &[u8],
    installed: &[u8],
    kernel: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    transplant_with_waveforms(target, installed, Space::default(), None, true, kernel)
}

fn transplant_with_waveforms(
    target: &[u8],
    installed: &[u8],
    space: Space,
    loader_space: Option<Range<usize>>,
    specialized: bool,
    kernel: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let before = super::bind(target).map_err(Error::Bundle)?;
    let required = super::bind(installed).map_err(Error::Bundle)?;
    let calibration_caller = calibration::callers::observe(target).map_err(Error::Calibration)?;
    calibration::callers::observe(installed).map_err(Error::Calibration)?;
    let resources = waveforms::resources::observe(target)
        .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?;
    let loader = waveforms::loader::observe(target)
        .map_err(|e| Error::Waveforms(waveforms::Error::Loader(e)))?;
    let static_tables = waveforms::resources::static_tables::observe(target)
        .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?;
    let protected: Vec<_> = core::iter::once(&resources.dispatch)
        .chain(core::iter::once(&static_tables.selector))
        .chain(&static_tables.tables)
        .chain(core::iter::once(&calibration_caller.program))
        .chain(&loader.spans)
        .chain(resources.initializer.as_ref())
        .chain(
            core::iter::once(&resources.selected)
                .chain(&resources.erased_parameter)
                .flat_map(|tables| tables.motion.iter().chain(&tables.coefficients)),
        )
        .collect();
    let reservations: Vec<_> = space
        .conversions
        .iter()
        .chain([&space.calibration, &space.sources, &loader_space])
        .filter_map(Option::as_ref)
        .collect();
    for (i, a) in reservations.iter().enumerate() {
        if protected.iter().any(|b| a.start < b.end && b.start < a.end)
            || reservations[i + 1..]
                .iter()
                .any(|b| a.start < b.end && b.start < a.end)
        {
            return Err(Error::VerificationFailed);
        }
    }
    let stages = [
        if specialized {
            conversions::rewrite_specialized_with_kernel(
                target,
                installed,
                space.conversions,
                kernel,
            )
            .map_err(Error::Conversions)?
        } else {
            conversions::rewrite_compact(target, installed, space.conversions)
                .map_err(Error::Conversions)?
        },
        conversions::rewrite_controls(target, installed).map_err(Error::Conversions)?,
        super::rewrite_step_offsets(
            target,
            required.step_minus_source ^ u8::from(before.coil != required.coil),
        )
        .map_err(Error::Bundle)?,
        sources::transplant(target, installed, space.sources).map_err(Error::Sources)?,
        if specialized {
            calibration::transplant_effective(target, installed).map_err(Error::Calibration)?
        } else {
            calibration::transplant(target, installed, space.calibration)
                .map_err(Error::Calibration)?
        },
        if specialized
            && required.loader == super::Loader::AscendingNegated17
            && matches!(
                loader.loader,
                super::Loader::Ascending | super::Loader::Descending
            )
        {
            waveforms::specialize_ascending(target, installed).map_err(Error::Waveforms)?
        } else {
            waveforms::transplant(target, installed, loader_space).map_err(Error::Waveforms)?
        },
    ];
    let mut changed = target.to_vec();
    for stage in stages {
        if stage.len() != target.len() {
            return Err(Error::VerificationFailed);
        }
        for ((original, composed), next) in target.iter().zip(&mut changed).zip(stage) {
            if next != *original {
                if *composed != *original && *composed != next {
                    return Err(Error::VerificationFailed);
                }
                *composed = next;
            }
        }
    }
    if specialized {
        verify_effective_result(target, installed, &changed, true, kernel)?;
    } else {
        verify_result(target, installed, &changed)?;
    }
    Ok(changed)
}

/// Rebind the complete convention, callers and consumed data after composition.
pub(crate) fn verify_result(target: &[u8], installed: &[u8], changed: &[u8]) -> Result<(), Error> {
    verify_effective_result(target, installed, changed, false, None)
}

pub(crate) fn verify_effective_result(
    target: &[u8],
    installed: &[u8],
    changed: &[u8],
    specialized: bool,
    kernel: Option<&[u8]>,
) -> Result<(), Error> {
    if specialized {
        conversions::verify_specialized_callers(changed, kernel).map_err(Error::Conversions)?;
        verify_conversion_retirements(target, changed, kernel)?;
    }
    let before = super::bind(target).map_err(Error::Bundle)?;
    let required = super::bind(installed).map_err(Error::Bundle)?;
    let calibration_caller = calibration::callers::observe(target).map_err(Error::Calibration)?;
    let actual = super::bind(changed).map_err(Error::Bundle)?;
    let original_loader = waveforms::loader::observe(target)
        .map_err(|error| Error::Waveforms(waveforms::Error::Loader(error)))?;
    let actual_loader = waveforms::loader::observe(changed)
        .map_err(|error| Error::Waveforms(waveforms::Error::Loader(error)))?;
    let normalized = specialized
        && required.loader == super::Loader::AscendingNegated17
        && actual_loader.loader == super::Loader::Ascending;
    if actual_loader.coefficient_getter != original_loader.coefficient_getter
        || actual_loader.writer != original_loader.writer
        || actual_loader.readback != original_loader.readback
    {
        return Err(Error::VerificationFailed);
    }
    waveforms::loader::readback::observe(changed, actual_loader.readback, actual_loader.writer)
        .map_err(|error| Error::Waveforms(waveforms::Error::Loader(error)))?;
    let after_resources = waveforms::resources::observe(changed)
        .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?;
    let donor_resources = waveforms::resources::observe(installed)
        .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?;
    let before_static = waveforms::resources::static_tables::observe(target)
        .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?;
    let after_static = waveforms::resources::static_tables::observe(changed)
        .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?;
    if before_static != after_static
        || !waveforms::resources::static_tables::equivalent(changed, installed)
            .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?
    {
        return Err(Error::VerificationFailed);
    }
    for tables in
        core::iter::once(&after_resources.selected).chain(&after_resources.erased_parameter)
    {
        for (role, (to, from)) in tables
            .motion
            .iter()
            .chain(&tables.coefficients)
            .zip(
                donor_resources
                    .selected
                    .motion
                    .iter()
                    .chain(&donor_resources.selected.coefficients),
            )
            .enumerate()
        {
            let normalized_table;
            let expected = if normalized && role >= 2 {
                let coefficients = installed[from.clone()]
                    .try_into()
                    .map_err(|_| Error::VerificationFailed)?;
                normalized_table = waveforms::plain_coefficients(coefficients, required.loader);
                &normalized_table[..]
            } else {
                &installed[from.clone()]
            };
            if &changed[to.clone()] != expected {
                return Err(Error::VerificationFailed);
            }
        }
    }
    // The target retains its motion-pointer initializer. Its DSP loader now
    // uses explicit coefficient addresses; the read-only selection is external.
    let expected = Bundle {
        table_select_0x28f: before.table_select_0x28f,
        loader: if normalized {
            super::Loader::Ascending
        } else {
            required.loader
        },
        ..required
    };
    let mut actual_caller = calibration::callers::observe(changed).map_err(Error::Calibration)?;
    if specialized {
        actual_caller.high_byte_modes = calibration_caller.high_byte_modes;
    }
    if actual_caller != calibration_caller
        || actual != expected
        || calibration::observe(changed).map_err(Error::Calibration)?
            != calibration::observe(installed).map_err(Error::Calibration)?
        || changed.get(..16) != target.get(..16)
        || changed.get(20..24) != target.get(20..24)
    {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

fn verify_conversion_retirements(
    target: &[u8],
    changed: &[u8],
    kernel: Option<&[u8]>,
) -> Result<(), Error> {
    let original_conversions = conversions::protected_ranges(target).map_err(Error::Conversions)?;
    let mut actual_storage = conversions::protected_ranges(changed).map_err(Error::Conversions)?;
    let mut retired = conversions::retired_tails(target, changed).map_err(Error::Conversions)?;
    let before_loader = waveforms::loader::observe(target)
        .map_err(|e| Error::Waveforms(waveforms::Error::Loader(e)))?;
    let after_loader = waveforms::loader::observe(changed)
        .map_err(|e| Error::Waveforms(waveforms::Error::Loader(e)))?;
    actual_storage.extend(after_loader.spans.iter().cloned());
    for table in after_loader.tables.into_iter().flatten() {
        if let waveforms::loader::Table::Pointer(address) = table {
            if let Some(at) = address.checked_sub(0x410000) {
                actual_storage.push(at as usize..at as usize + 4);
            }
        }
    }
    let before_reader = calibration::protected_ranges(target).map_err(Error::Calibration)?;
    let after_reader = calibration::protected_ranges(changed).map_err(Error::Calibration)?;
    for (original, current) in [
        (&before_loader.program, &after_loader.program),
        (&before_reader[0], &after_reader[0]),
    ] {
        if original.start == current.start && current.end < original.end {
            retired.push(conversions::Retirement {
                program: original.clone(),
                tail: current.end..original.end,
            });
        }
    }
    retired.retain(|body| {
        actual_storage
            .iter()
            .any(|span| span.start < body.tail.end && body.tail.start < span.end)
    });
    if retired.is_empty() {
        return Ok(());
    }
    let kernel = kernel.ok_or(Error::ComponentOwnership)?;
    let mut references = changed.to_vec();
    for span in original_conversions
        .iter()
        .chain(&before_loader.spans)
        .chain(&before_reader)
    {
        references[span.clone()].copy_from_slice(&target[span.clone()]);
    }
    for body in retired {
        crate::filters::phase::native::placement::retirement_loader_references_clear(
            &references,
            kernel,
            &body.program,
            &body.tail,
        )
        .ok_or(Error::ComponentOwnership)?;
    }
    Ok(())
}

/// Compose without an external code reservation by reusing the tail of a
/// shrinking OEM calibration reader. No arbitrary erased gap is allocated.
/// Caller/component prerequisites still belong to the complete operation:
/// Normal reference checks do not prove absent indirect or resident-code edges.
pub fn transplant_reusing_reader(target: &[u8], installed: &[u8]) -> Result<Vec<u8>, Error> {
    let mut prepared =
        calibration::transplant(target, installed, None).map_err(Error::Calibration)?;
    let retired = calibration::retired_tail(target, &prepared).map_err(Error::Calibration)?;
    if let Some(tail) = &retired {
        // The old reader was positively bound and replaced. Erasure here is an
        // in-memory staging marker for the shared reservation validator.
        prepared[tail.clone()].fill(0xff);
    }
    transplant(&prepared, installed, Space::default(), retired)
}

/// Reuse a shrinking calibration reader with exact resident-component
/// ownership. Unlike the reservation-only staging entry above, this establishes
/// both Normal and Kernel references before donating the reader's suffix.
/// An absent Kernel cannot establish that resident code has no alternate entry.
pub fn transplant_reusing_reader_with_kernel(
    target: &[u8],
    installed: &[u8],
    kernel: &[u8],
) -> Result<Vec<u8>, Error> {
    use crate::filters::phase::native::placement;
    let mut prepared =
        calibration::transplant(target, installed, None).map_err(Error::Calibration)?;
    let tail = calibration::retired_tail(target, &prepared)
        .map_err(Error::Calibration)?
        .ok_or(Error::ComponentOwnership)?;
    let ranges = calibration::protected_ranges(target).map_err(Error::Calibration)?;
    let original = ranges.first().ok_or(Error::ComponentOwnership)?;
    placement::retirement_loader_references_clear(target, kernel, original, &tail)
        .ok_or(Error::ComponentOwnership)?;
    prepared[tail.clone()].fill(0xff);
    let changed = transplant(&prepared, installed, Space::default(), Some(tail))?;
    verify_result(target, installed, &changed)?;
    verify_reader_retirement(target, kernel, &changed)?;
    Ok(changed)
}

/// Recheck reader-retirement authority after disjoint owners have composed
/// their changes. Restore the replaced reader and loader in the reference scan:
/// the bound new loader owns the intentional spill/cell references into the
/// reader tail. Any new external reference into that storage is rejected.
pub fn verify_reader_retirement(target: &[u8], kernel: &[u8], changed: &[u8]) -> Result<(), Error> {
    let before = calibration::protected_ranges(target).map_err(Error::Calibration)?;
    let after = calibration::protected_ranges(changed).map_err(Error::Calibration)?;
    let original = before.first().ok_or(Error::ComponentOwnership)?;
    let current = after.first().ok_or(Error::ComponentOwnership)?;
    if target.len() != changed.len()
        || original.start != current.start
        || current.end >= original.end
    {
        return Err(Error::ComponentOwnership);
    }
    let tail = current.end..original.end;
    let mut references = changed.to_vec();
    references[original.clone()].copy_from_slice(&target[original.clone()]);
    let loader = waveforms::loader::observe(target)
        .map_err(|e| Error::Waveforms(waveforms::Error::Loader(e)))?;
    for span in loader.spans {
        references[span.clone()].copy_from_slice(&target[span]);
    }
    crate::filters::phase::native::placement::retirement_loader_references_clear(
        &references,
        kernel,
        original,
        &tail,
    )
    .ok_or(Error::ComponentOwnership)
}

/// Specialize without allocating an unowned gap. Complete shrinking OEM
/// loaders, readers and conversions may donate their unreachable suffixes to
/// growing conversions and loaders. Every suffix has exact Normal/Kernel reference proof;
/// reservations are sized from complete instruction-boundary spills.
pub fn transplant_reusing_loader(
    target: &[u8],
    installed: &[u8],
    kernel: &[u8],
) -> Result<Vec<u8>, Error> {
    use crate::filters::phase::native::placement;
    let mut prepared = conversions::rewrite_shrinking(target, installed, Some(kernel))
        .map_err(Error::Conversions)?;
    let mut retired = conversions::retired_tails(target, &prepared).map_err(Error::Conversions)?;
    if let Ok(reader) = calibration::transplant(&prepared, installed, None) {
        if let Some(tail) =
            calibration::retired_tail(&prepared, &reader).map_err(Error::Calibration)?
        {
            let original =
                calibration::protected_ranges(target).map_err(Error::Calibration)?[0].clone();
            retired.push(conversions::Retirement {
                program: original,
                tail,
            });
        }
        prepared = reader;
    }
    let before = waveforms::loader::observe(target)
        .map_err(|e| Error::Waveforms(waveforms::Error::Loader(e)))?;
    let growing_loader = match waveforms::transplant(&prepared, installed, None) {
        Ok(image) => {
            prepared = image;
            false
        }
        Err(waveforms::Error::Loader(waveforms::loader::Error::SpaceRequired)) => true,
        Err(error) => return Err(Error::Waveforms(error)),
    };
    let after = waveforms::loader::observe(&prepared)
        .map_err(|e| Error::Waveforms(waveforms::Error::Loader(e)))?;
    if before.spans.len() == 1
        && after.spans.len() == 1
        && before.program.start == after.program.start
        && after.program.end < before.program.end
    {
        retired.push(conversions::Retirement {
            program: before.program.clone(),
            tail: after.program.end..before.program.end,
        });
    }
    let mut available = Vec::new();
    for body in &retired {
        placement::retirement_loader_references_clear(target, kernel, &body.program, &body.tail)
            .ok_or(Error::ComponentOwnership)?;
        if prepared[body.tail.clone()]
            .chunks_exact(2)
            .any(|bytes| bytes != [0, 0])
            || available.iter().any(|range: &Range<usize>| {
                range.start < body.tail.end && body.tail.start < range.end
            })
        {
            return Err(Error::ComponentOwnership);
        }
        available.push(body.tail.clone());
    }
    if growing_loader {
        let mut candidates: Vec<_> = available.iter().cloned().enumerate().collect();
        candidates.sort_by_key(|(_, span)| span.len());
        let mut placed = None;
        for (index, span) in candidates {
            let mut staged = prepared.clone();
            staged[span.clone()].fill(0xff);
            if let Ok(image) = waveforms::transplant(&staged, installed, Some(span.clone())) {
                placed = Some((index, span, image));
                break;
            }
        }
        let (index, span, image) = placed.ok_or(Error::ComponentOwnership)?;
        prepared = image;
        available.remove(index);
        let loader = waveforms::loader::observe(&prepared)
            .map_err(|e| Error::Waveforms(waveforms::Error::Loader(e)))?;
        let mut used: Vec<_> = loader
            .spans
            .into_iter()
            .filter(|body| body.start >= span.start && body.end <= span.end)
            .collect();
        for table in loader.tables.into_iter().flatten() {
            if let waveforms::loader::Table::Pointer(address) = table {
                if let Some(at) = address.checked_sub(0x410000) {
                    let cell = at as usize..at as usize + 4;
                    if cell.start >= span.start && cell.end <= span.end {
                        used.push(cell);
                    }
                }
            }
        }
        used.sort_by_key(|body| body.start);
        used.dedup();
        let mut cursor = span.start;
        for body in used {
            if cursor > body.start {
                return Err(Error::ComponentOwnership);
            }
            if cursor < body.start {
                available.push(cursor..body.start);
            }
            cursor = body.end;
        }
        if cursor < span.end {
            available.push(cursor..span.end);
        }
    }
    let lengths = conversions::required_spills(&prepared, installed, Some(kernel))
        .map_err(Error::Conversions)?;
    let mut requests: Vec<_> = lengths
        .into_iter()
        .enumerate()
        .filter(|(_, length)| *length != 0)
        .collect();
    if requests.is_empty() && !growing_loader {
        return Err(Error::ComponentOwnership);
    }
    requests.sort_by_key(|(_, length)| core::cmp::Reverse(*length));
    let mut space = Space::default();
    for (index, length) in requests {
        let slot = available
            .iter()
            .enumerate()
            .filter(|(_, span)| span.len() >= length)
            .min_by_key(|(_, span)| span.len())
            .map(|(i, _)| i)
            .ok_or(Error::ComponentOwnership)?;
        let range = available[slot].start..available[slot].start + length;
        available[slot].start = range.end;
        prepared[range.clone()].fill(0xff);
        space.conversions[index] = Some(range);
    }
    let changed = transplant_with_waveforms(&prepared, installed, space, None, true, Some(kernel))?;
    verify_effective_result(target, installed, &changed, true, Some(kernel))?;
    Ok(changed)
}
