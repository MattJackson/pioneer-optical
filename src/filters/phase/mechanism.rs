//! Full OEM mechanism effects owned by the phase filter.
use super::{bundle, Error, Preparation, Transition};
use crate::filters::prerequisites::Word;
use alloc::{vec, vec::Vec};

#[derive(Debug)]
pub(super) struct Mechanism {
    donor: Vec<u8>,
    image: Vec<u8>,
    selection_required: bool,
}
impl Mechanism {
    pub(super) fn plan(
        transition: &Transition<'_, '_>,
        selection_required: bool,
    ) -> Result<Self, Error> {
        let donor = transition.installed.firmware.normal.to_vec();
        // No unowned erased space or retired span is admitted by this owner.
        // Growing compositions remain refused until their placement is proved.
        let image = bundle::composition::transplant(
            transition.target.firmware.normal,
            &donor,
            bundle::composition::Space::default(),
            None,
        )
        .map_err(|_| Error::Unsupported)?;
        Ok(Self {
            donor,
            image,
            selection_required,
        })
    }
    pub(super) fn required_words(&self) -> Vec<Word> {
        if self.selection_required {
            vec![Word {
                parameter: 0x28f,
                value: 1,
            }]
        } else {
            Vec::new()
        }
    }
    pub(super) fn prepare(&self, context: &Preparation<'_>) -> Result<Vec<u8>, Error> {
        #[cfg(feature = "envelope")]
        if let Some(normal) = context.normal {
            use crate::envelope::Layout;
            if !matches!(normal.info().layout, Layout::Normal | Layout::NormalReverse) {
                return Err(Error::Unsupported);
            }
            normal
                .repair_image_checksum(&self.image)
                .ok_or(Error::Representation)?;
        }
        self.verify(context, &self.image)?;
        Ok(self.image.clone())
    }
    pub(super) fn verify(&self, context: &Preparation<'_>, normal: &[u8]) -> Result<(), Error> {
        if normal.len() != self.image.len() {
            return Err(Error::VerificationFailed);
        }
        // Other filter owners may add disjoint effects; every byte this owner
        // changes must survive, apart from the shared checksum field.
        for (at, ((before, expected), actual)) in context
            .target
            .normal
            .iter()
            .zip(&self.image)
            .zip(normal)
            .enumerate()
        {
            if !(16..20).contains(&at) && before != expected && actual != expected {
                return Err(Error::VerificationFailed);
            }
        }
        bundle::composition::verify_result(context.target.normal, &self.donor, normal)
            .map_err(|_| Error::VerificationFailed)
    }
}
