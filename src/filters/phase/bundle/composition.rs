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
    let protected: Vec<_> = core::iter::once(&resources.dispatch)
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
        if specialized && required.loader == super::Loader::AscendingNegated17 {
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
    }
    let before = super::bind(target).map_err(Error::Bundle)?;
    let required = super::bind(installed).map_err(Error::Bundle)?;
    let calibration_caller = calibration::callers::observe(target).map_err(Error::Calibration)?;
    let actual = super::bind(changed).map_err(Error::Bundle)?;
    let normalized = specialized && required.loader == super::Loader::AscendingNegated17;
    let original_loader = waveforms::loader::observe(target)
        .map_err(|error| Error::Waveforms(waveforms::Error::Loader(error)))?;
    let actual_loader = waveforms::loader::observe(changed)
        .map_err(|error| Error::Waveforms(waveforms::Error::Loader(error)))?;
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

/// Specialize without allocating an unowned gap. A shrinking whole OEM loader
/// may donate its now-unreachable suffix to a growing conversion. Its entry and
/// helper ABI are retained; complete Normal and exact supplied Kernel references
/// are checked before any retired byte is used. Arbitrary runtime synthesis of
/// instruction-interior addresses is outside this bounded ownership contract.
pub fn transplant_reusing_loader(
    target: &[u8],
    installed: &[u8],
    kernel: &[u8],
) -> Result<Vec<u8>, Error> {
    use crate::filters::phase::native::placement;
    let before = waveforms::loader::observe(target)
        .map_err(|e| Error::Waveforms(waveforms::Error::Loader(e)))?;
    let mut prepared = waveforms::transplant(target, installed, None).map_err(Error::Waveforms)?;
    let after = waveforms::loader::observe(&prepared)
        .map_err(|e| Error::Waveforms(waveforms::Error::Loader(e)))?;
    if before.spans.len() != 1
        || after.spans.len() != 1
        || before.program.start != after.program.start
        || after.program.end >= before.program.end
    {
        return Err(Error::ComponentOwnership);
    }
    let tail = after.program.end..before.program.end;
    placement::retirement_loader_references_clear(target, kernel, &before.program, &tail)
        .ok_or(Error::ComponentOwnership)?;
    // The bound loader transplant fills only its own retired suffix with NOPs.
    // Erasure is a local reservation marker, not a search for free flash bytes.
    if prepared[tail.clone()].chunks_exact(2).any(|bytes| {
        h8_asm::isa::decode_insn(bytes, h8_asm::Target::H8S2000, h8_asm::Mode::Advanced)
            .map_or(true, |d| d.insn.mnemonic != "NOP")
    }) {
        return Err(Error::ComponentOwnership);
    }
    let element = match conversions::rewrite_specialized_with_kernel(
        &prepared,
        installed,
        Default::default(),
        Some(kernel),
    ) {
        Err(conversions::Error::SpaceRequired(element)) => element,
        Err(error) => return Err(Error::Conversions(error)),
        Ok(_) => return Err(Error::ComponentOwnership),
    };
    let index = match element {
        super::Element::CalibrationBase => 0,
        super::Element::CalibrationOffset => 1,
        super::Element::CalibrationStep => 2,
        _ => return Err(Error::ComponentOwnership),
    };
    prepared[tail.clone()].fill(0xff);
    let mut space = Space::default();
    space.conversions[index] = Some(tail);
    let changed = transplant_with_waveforms(&prepared, installed, space, None, true, Some(kernel))?;
    verify_effective_result(target, installed, &changed, true, Some(kernel))?;
    Ok(changed)
}
