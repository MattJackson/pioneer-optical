//! Select firmware effects while retaining independent mechanism requirements.
use super::{mechanism, CorrectionPlan, Error, PreparedCorrection};
use crate::envelope::Envelope;

pub(crate) enum PreparationError {
    Firmware(Error),
    Mechanism(mechanism::Error),
    Settings(crate::settings::update::Error),
}

/// Firmware effect selection for one target. A guarded mechanism conversion
/// first establishes its reviewed complete image, then aligns that output's
/// native phase to the installed assignment. The original target's phase edit
/// is never layered over a changed mechanism grammar. Whole-image guards and
/// live prerequisites remain mandatory throughout composition.
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
        Some(corrected) => {
            // The reviewed recipe establishes a different mechanism program.
            // Only native output phase has a proved residual composition here;
            // never discard a separately required layout correction.
            if native.is_some_and(|plan| {
                plan.corrections()
                    .iter()
                    .any(|effect| !matches!(effect, super::Correction::Phase { .. }))
            }) {
                return Err(PreparationError::Firmware(Error::Unsupported));
            }
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
