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
}

/// Compose actual OEM donor routines and tables, with target helper relocation.
/// The caller owns all executable reservations and live read prerequisites.
/// Indirect donor table loads use read-only pointer cells in loader_space.
/// Source routines, conversions and calibration readers reuse original space and spill overflow
/// only at instruction boundaries with no relative branches crossing the split.
/// Loader growth still requires a complete-body reservation.
pub fn transplant(
    target: &[u8],
    installed: &[u8],
    space: Space,
    loader_space: Option<Range<usize>>,
) -> Result<Vec<u8>, Error> {
    let before = super::bind(target).map_err(Error::Bundle)?;
    let required = super::bind(installed).map_err(Error::Bundle)?;
    let resources = waveforms::resources::observe(target)
        .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?;
    let loader = waveforms::loader::observe(target)
        .map_err(|e| Error::Waveforms(waveforms::Error::Loader(e)))?;
    let protected: Vec<_> = core::iter::once(&resources.dispatch)
        .chain(core::iter::once(&loader.program))
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
        conversions::rewrite_compact(target, installed, space.conversions)
            .map_err(Error::Conversions)?,
        conversions::rewrite_controls(target, installed).map_err(Error::Conversions)?,
        super::rewrite_step_offsets(
            target,
            required.step_minus_source ^ u8::from(before.coil != required.coil),
        )
        .map_err(Error::Bundle)?,
        sources::transplant(target, installed, space.sources).map_err(Error::Sources)?,
        calibration::transplant(target, installed, space.calibration)
            .map_err(Error::Calibration)?,
        waveforms::transplant(target, installed, loader_space).map_err(Error::Waveforms)?,
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
    let actual = super::bind(&changed).map_err(Error::Bundle)?;
    let after_resources = waveforms::resources::observe(&changed)
        .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?;
    let donor_resources = waveforms::resources::observe(installed)
        .map_err(|e| Error::Waveforms(waveforms::Error::Resources(e)))?;
    for tables in
        core::iter::once(&after_resources.selected).chain(&after_resources.erased_parameter)
    {
        for (to, from) in tables.motion.iter().chain(&tables.coefficients).zip(
            donor_resources
                .selected
                .motion
                .iter()
                .chain(&donor_resources.selected.coefficients),
        ) {
            if changed[to.clone()] != installed[from.clone()] {
                return Err(Error::VerificationFailed);
            }
        }
    }
    // The target retains its motion-pointer initializer. Its DSP loader now
    // uses explicit coefficient addresses; the read-only selection is external.
    let expected = Bundle {
        table_select_0x28f: before.table_select_0x28f,
        ..required
    };
    if actual != expected
        || calibration::observe(&changed).map_err(Error::Calibration)?
            != calibration::observe(installed).map_err(Error::Calibration)?
        || changed[..24] != target[..24]
    {
        return Err(Error::VerificationFailed);
    }
    Ok(changed)
}
