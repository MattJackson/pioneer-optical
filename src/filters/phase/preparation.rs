//! Select firmware effects while retaining independent mechanism requirements.
use super::mechanism;
use crate::compatibility::{CorrectionPlan, Error, PreparedCorrection};
use crate::envelope::Envelope;

#[derive(Debug)]
pub(crate) enum PreparationError {
    Firmware(Error),
    Mechanism(mechanism::Error),
    Settings(crate::settings::update::Error),
}

// A family override belongs to requested firmware admission, not to a recipe's
// authority to mutate unrelated native facts. Check the recipe footprint before
// a replan can treat those changes as its new requested baseline.
fn verify_mechanism_footprint(
    before: &crate::filters::Context<'_>,
    after: &crate::filters::Context<'_>,
) -> Result<(), Error> {
    use crate::filters::{Comparison, Filter, Finding, Role};
    for owner in crate::filters::filters() {
        if owner.id() == super::FILTER.id() {
            continue;
        }
        let original = owner.inspect(before);
        let reviewed = owner.inspect(after);
        if original.id != owner.id() || reviewed.id != owner.id() || original.role != reviewed.role
        {
            return Err(Error::VerificationFailed);
        }
        let identical_unresolved_policy = original.role == Role::Operational
            && matches!(
                (&original.finding, &reviewed.finding),
                (Finding::Unresolved(_), Finding::Unresolved(_))
            )
            && original == reviewed;
        if !identical_unresolved_policy && owner.compare(&original, &reviewed) != Comparison::Match
        {
            return Err(Error::VerificationFailed);
        }
    }
    Ok(())
}

/// Firmware effect selection for one target. A guarded mechanism conversion
/// first establishes its reviewed complete image, then aligns that output's
/// native phase to the installed assignment. The original target's phase edit
/// is never layered over a changed mechanism grammar. Whole-image guards and
/// live prerequisites remain mandatory throughout composition. Every other
/// required native effect is replanned and verified on the reviewed output;
/// no correction from the original target is discarded or blindly replayed.
pub(crate) fn prepare(
    native: Option<&CorrectionPlan<'_>>,
    source: &mechanism::Contract,
    normal: &Envelope,
    kernel: &Envelope,
    original: Option<&str>,
    scope: Option<crate::settings::routing::ProductSelector<'static>>,
    #[cfg(test)] documents: Option<&[String]>,
) -> Result<Option<PreparedCorrection>, PreparationError> {
    let prepare_mechanism = || match (original, scope) {
        (Some(original), _) => {
            mechanism::prepare_hardware(source, &normal.image, &normal.info().model, original)
        }
        (None, Some(scope)) => {
            mechanism::prepare_scope(source, &normal.image, &normal.info().model, scope)
        }
        (None, None) => mechanism::prepare(source, &normal.image, &normal.info().model),
    };
    #[cfg(test)]
    let mechanism = if let Some(documents) = documents {
        mechanism::prepare_documents(documents, source, &normal.image, &normal.info().model)
    } else {
        prepare_mechanism()
    };
    #[cfg(not(test))]
    let mechanism = prepare_mechanism();

    let corrected = match mechanism.map_err(PreparationError::Mechanism)? {
        Some(mut corrected) => {
            // A reviewed mechanism recipe changes the original target grammar.
            // Rebind every native owner to its exact authenticated output, using
            // the immutable installed components and the original policy.
            let native = native.ok_or(PreparationError::Firmware(Error::UnresolvedIdentity))?;
            let bytes = crate::compatibility::rebuild_normal(
                normal,
                Some(kernel),
                &corrected.image,
                corrected.stock_return(),
            )
            .map_err(PreparationError::Firmware)?;
            let reviewed = Envelope::load_with_kernel(&bytes, kernel)
                .map_err(|_| PreparationError::Firmware(Error::Representation))?;
            if reviewed.image != corrected.image {
                return Err(PreparationError::Firmware(Error::VerificationFailed));
            }
            let requested_context = crate::filters::Context::new(crate::compatibility::Firmware {
                hardware: &normal.info().hardware_version,
                normal: &normal.image,
                kernel: Some(&kernel.image),
            });
            let reviewed_context = crate::filters::Context::new(crate::compatibility::Firmware {
                hardware: &reviewed.info().hardware_version,
                normal: &reviewed.image,
                kernel: Some(&kernel.image),
            });
            verify_mechanism_footprint(&requested_context, &reviewed_context)
                .map_err(|_| PreparationError::Mechanism(mechanism::Error::Guard))?;
            let replanned = native
                .replan(crate::compatibility::Firmware {
                    hardware: &reviewed.info().hardware_version,
                    normal: &reviewed.image,
                    kernel: Some(&kernel.image),
                })
                .map_err(PreparationError::Firmware)?;
            if let Some(image) = replanned
                .prepare_image(&reviewed, Some(kernel))
                .map_err(PreparationError::Firmware)?
            {
                if image != reviewed.image {
                    corrected.stock_return = false;
                }
                corrected.image = image;
            }
            corrected
                .corrections
                .extend(replanned.corrections().iter().cloned());
            corrected.verification =
                crate::compatibility::Verification::ReviewedMechanismAndRegisteredFilters;
            Some(corrected)
        }
        None => match native {
            Some(plan) => plan
                .prepare_image(normal, Some(kernel))
                .map_err(PreparationError::Firmware)?
                .map(|image| PreparedCorrection::native(image, plan.corrections())),
            None => None,
        },
    };
    match &corrected {
        Some(corrected) => source.check_resolving(
            &mechanism::Contract::discover(&corrected.image),
            Some(&corrected.resolves_issue),
        ),
        None => source.check(&mechanism::Contract::discover(&normal.image)),
    }
    .map_err(PreparationError::Settings)?;
    Ok(corrected)
}

#[cfg(test)]
mod tests;
