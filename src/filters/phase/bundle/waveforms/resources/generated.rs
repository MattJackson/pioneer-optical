//! Complete native generated-table convention and owned basis composition.
//! Native calibration and selector contracts are composed explicitly; resident
//! arithmetic calls stay target-owned. A shifted basis alone never makes
//! different calibration sources equivalent.
use super::{calibration_bridge, evaluators, software, Error};
use crate::filters::phase::{bundle, native};
use crate::filters::prerequisites::Word;
use crate::image::layout::Observation;
use alloc::vec::Vec;

/// Native programs participating in a generated software waveform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Complete table dispatcher and selector.
    pub consumer: software::Binding,
    /// Complete buffer producer and startup calls.
    pub producer: software::Producer,
    /// Complete evaluator graph and image basis.
    pub evaluator: evaluators::Binding,
    /// Complete calibration reader and its source contract.
    pub calibration: (core::ops::Range<usize>, evaluators::Calibration),
    /// Native paired output functions.
    pub coils: native::PairedPhase,
    /// Source word receiving the negative full-step offset.
    pub step_minus_source: u8,
}

/// Bind the complete generated path through its initialized buffers and coils.
pub fn observe(normal: &[u8]) -> Result<Binding, Error> {
    let consumer = software::observe(normal)?;
    let producer = software::observe_producer(normal)?;
    let evaluator = evaluators::observe(normal)?;
    let calibration = evaluators::calibration(normal, &evaluator)?;
    let Observation::Known(coils) = native::discover_pair(normal) else {
        return Err(Error::Unresolved);
    };
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let step_minus_source =
        bundle::step_source(normal, &regions.stored, &coils).map_err(|_| Error::Unresolved)?;
    // All producer/consumer buffers are native RAM resources. This operation
    // never allocates another buffer or changes their initialization schedule.
    for (_, source) in &consumer.choices {
        let software::Source::Runtime(address) = source else {
            return Err(Error::ResourceMismatch);
        };
        if !(0xa00000..=0xafff00).contains(address) {
            return Err(Error::ResourceMismatch);
        }
    }
    Ok(Binding {
        consumer,
        producer,
        evaluator,
        calibration,
        coils,
        step_minus_source,
    })
}

fn compatible(target: &[u8], a: &Binding, b: &Binding) -> bool {
    // Parameter contracts include both native service addresses: differing
    // context/getter implementations are not assumed interchangeable.
    a.calibration.1 == b.calibration.1
        && (a.evaluator.arithmetic == b.evaluator.arithmetic
            || native::arithmetic::observe(
                target,
                0x410000,
                a.evaluator.arithmetic[0],
                a.evaluator.arithmetic[1],
            )
            .is_some())
        && a.consumer
            .choices
            .iter()
            .map(|x| x.0)
            .eq(b.consumer.choices.iter().map(|x| x.0))
}

/// Find a unique cyclic permutation of the target's own paired coefficients.
/// This preserves every coefficient and amplitude; arbitrary donor tables are
/// not accepted as an equivalent native generation convention.
pub fn rotation(target: &[u8], installed: &[u8]) -> Result<usize, Error> {
    let a = observe(target)?;
    let b = observe(installed)?;
    if !compatible(target, &a, &b) {
        return Err(Error::ResourceMismatch);
    }
    let left = &target[a.evaluator.basis];
    let right = &installed[b.evaluator.basis];
    let mut rotations = (0..64).filter(|shift| {
        (0..64).all(|row| {
            left[((row + shift) % 64) * 4..((row + shift) % 64) * 4 + 4]
                == right[row * 4..row * 4 + 4]
        })
    });
    let shift = rotations.next().ok_or(Error::ResourceMismatch)?;
    if rotations.next().is_some() {
        return Err(Error::ResourceMismatch);
    }
    Ok(shift)
}

/// A complete generated operation and its enforced read-only source guards.
#[derive(Clone, Debug)]
pub struct Plan {
    /// Corrected Normal bytes, without shared checksum finalization.
    pub image: Vec<u8>,
    /// Exact persistent words read by preflight; never written.
    pub required_words: Vec<Word>,
}

/// Compose native mode predicates, calibration contract, cyclic basis and coil
/// convention. A parameter source may agree with image constants only under
/// the exact native read-only words returned by the calibration bridge.
pub fn plan(target: &[u8], installed: &[u8]) -> Result<Plan, Error> {
    plan_with_kernel(target, installed, None)
}

/// Include the exact resident component when instruction placement changes or
/// a noncyclic software/computed basis recipe needs exclusive-reference proof.
/// Cyclic software-only corrections require no Kernel.
pub fn plan_with_kernel(
    target: &[u8],
    installed: &[u8],
    kernel: Option<&[u8]>,
) -> Result<Plan, Error> {
    let computed_target = super::loader::computed::observe(target);
    let computed_donor = super::loader::computed::observe(installed);
    let staged = match (&computed_target, &computed_donor) {
        (Ok(a), Ok(b)) => {
            if a.calibration != b.calibration || a.arithmetic != b.arithmetic {
                return Err(Error::ResourceMismatch);
            }
            let mut staged = if a.loader.loader == b.loader.loader {
                target.to_vec()
            } else {
                super::loader::computed::specialize_direction(
                    target,
                    installed,
                    kernel.ok_or(Error::ResourceMismatch)?,
                )
                .map_err(|_| Error::ResourceMismatch)?
            };
            if target[a.basis.clone()] != installed[b.basis.clone()] {
                super::retirement::references_clear(
                    target,
                    kernel.ok_or(Error::ResourceMismatch)?,
                    core::slice::from_ref(&a.basis),
                    &[a.basis.clone(), a.loader.program.clone()],
                    core::slice::from_ref(&a.loader.program),
                )
                .ok_or(Error::ResourceMismatch)?;
                staged[a.basis.clone()].copy_from_slice(&installed[b.basis.clone()]);
            }
            staged
        }
        (Err(_), Err(_))
            if super::loader::observe(target).is_err()
                && super::loader::observe(installed).is_err() =>
        {
            target.to_vec()
        }
        _ => return Err(Error::ResourceMismatch),
    };
    let before = observe(target)?;
    let donor = observe(installed)?;
    let bridge = calibration_bridge::plan(&staged, installed)?;
    let mut changed = software::transplant_modes(&bridge.image, installed)?;
    // Both fully recognized evaluator grammars have the same symbolic helper
    // arguments/order. Retain target primitives; changing their addresses is
    // unnecessary. A locally bound native arithmetic implementation also
    // permits the source recipe to relocate onto those exact target services.
    let adapted = observe(&changed)?;
    if adapted.evaluator.arithmetic != donor.evaluator.arithmetic
        && native::arithmetic::observe(
            target,
            0x410000,
            before.evaluator.arithmetic[0],
            before.evaluator.arithmetic[1],
        )
        .is_none()
        && native::arithmetic::observe(
            installed,
            0x410000,
            donor.evaluator.arithmetic[0],
            donor.evaluator.arithmetic[1],
        )
        .is_none()
    {
        return Err(Error::ResourceMismatch);
    }
    let left = &target[before.evaluator.basis.clone()];
    let right = &installed[donor.evaluator.basis.clone()];
    let shifts: Vec<_> = (0..64)
        .filter(|shift| {
            (0..64).all(|row| {
                left[((row + shift) % 64) * 4..((row + shift) % 64) * 4 + 4]
                    == right[row * 4..row * 4 + 4]
            })
        })
        .collect();
    if shifts.len() != 1 {
        // Different amplitudes or repeated rows are legitimate donor recipes,
        // but require exclusive ownership of the target basis. The fully bound
        // evaluators are its permitted consumers; all other Normal/Kernel
        // references must remain outside the replaced table.
        let mut replaced = before.evaluator.programs.clone();
        replaced.push(before.evaluator.basis.clone());
        super::retirement::references_clear(
            target,
            kernel.ok_or(Error::ResourceMismatch)?,
            core::slice::from_ref(&before.evaluator.basis),
            &replaced,
            &before.evaluator.programs,
        )
        .ok_or(Error::ResourceMismatch)?;
    }
    changed = evaluators::rewrite_basis(&changed, installed)?;
    changed = native::correct_pair(&changed, donor.coils.assignment)
        .map_err(|_| Error::ResourceMismatch)?;
    changed = bundle::rewrite_step_offsets(&changed, donor.step_minus_source)
        .map_err(|_| Error::ResourceMismatch)?;
    let actual = observe(&changed)?;
    if actual.consumer != adapted.consumer
        || actual.producer != before.producer
        || actual.evaluator != before.evaluator
        || actual.calibration != adapted.calibration
        || actual.coils.assignment != donor.coils.assignment
        || actual.step_minus_source != donor.step_minus_source
        || calibration_bridge::verify_guarded(target, installed, &changed)? != bridge.required_words
    {
        return Err(Error::ResourceMismatch);
    }
    if let Ok(before_dsp) = computed_target {
        let after_dsp =
            super::loader::computed::observe(&changed).map_err(|_| Error::ResourceMismatch)?;
        let wanted_dsp =
            super::loader::computed::observe(&staged).map_err(|_| Error::ResourceMismatch)?;
        if after_dsp != wanted_dsp || after_dsp.calibration != before_dsp.calibration {
            return Err(Error::ResourceMismatch);
        }
    }
    Ok(Plan {
        image: changed,
        required_words: bridge.required_words,
    })
}

/// Unconditional form. A caller that cannot carry read prerequisites must not
/// silently apply a parameter-to-constant substitution.
pub fn transplant(target: &[u8], installed: &[u8]) -> Result<Vec<u8>, Error> {
    let plan = plan(target, installed)?;
    if !plan.required_words.is_empty() {
        return Err(Error::ResourceMismatch);
    }
    Ok(plan.image)
}

/// Rebind the whole graph after other owners compose their effects. Every
/// composed graph byte and retained resident-call operand must still match.
pub fn verify(target: &[u8], installed: &[u8], changed: &[u8]) -> Result<(), Error> {
    verify_with_kernel(target, installed, changed, None)
}

/// Recheck co-resident DSP ownership with the same exact Kernel evidence.
pub fn verify_with_kernel(
    target: &[u8],
    installed: &[u8],
    changed: &[u8],
    kernel: Option<&[u8]>,
) -> Result<(), Error> {
    let expected = plan_with_kernel(target, installed, kernel)?.image;
    let before = observe(target)?;
    let actual = observe(changed)?;
    let wanted = observe(&expected)?;
    if actual != wanted {
        return Err(Error::ResourceMismatch);
    }
    let protected = before.evaluator.programs.iter().chain([
        &before.consumer.dispatch,
        &before.consumer.selector,
        &before.producer.program,
        &before.producer.initializer,
        &before.calibration.0,
        &before.evaluator.basis,
    ]);
    for span in protected {
        if changed.get(span.clone()) != expected.get(span.clone()) {
            return Err(Error::ResourceMismatch);
        }
    }
    if let Ok(dsp) = super::loader::computed::observe(&expected) {
        let after =
            super::loader::computed::observe(changed).map_err(|_| Error::ResourceMismatch)?;
        if dsp != after {
            return Err(Error::ResourceMismatch);
        }
        for span in dsp.loader.spans.iter().chain([
            &dsp.basis,
            &dsp.calibration_program,
            &dsp.mode_context,
            &dsp.mode_reader,
        ]) {
            if changed.get(span.clone()) != expected.get(span.clone()) {
                return Err(Error::ResourceMismatch);
            }
        }
    }
    Ok(())
}
