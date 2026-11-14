//! Generic owner decisions and atomic composition of verified decoded pairs.
use super::{
    Assessment, Comparison, Context, Filter, Finding, Integrity, Operation, Preparation,
    PreparedComponents, Role, Transition,
};
use crate::filters::{Error, Firmware};
use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};

/// Admission policy for the independent hardware-family gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Every required owner must establish a compatible native transition.
    Strict,
    /// Bypass only the broad domain gate. Every native owner decision,
    /// prerequisite and selected correction proof remains mandatory.
    FamilyOverride,
}

/// One immutable owner decision, also usable by reports without replanning.
#[derive(Debug)]
pub struct Decision {
    /// Stable owner identifier.
    pub id: &'static str,
    /// Original installed observation, including unresolved/conflicting facts.
    pub installed: Assessment,
    /// Original requested observation.
    pub target: Assessment,
    /// Actual native comparison; an override never converts this into Match.
    pub comparison: Comparison,
    /// Retained for compatibility. Evaluation never waives an owner failure
    /// and always sets this field to `false`.
    pub waived: bool,
    operation: Option<Box<dyn Operation>>,
    blocked: Option<Error>,
}
impl Decision {
    /// The immutable operation selected by this owner, if any.
    pub fn operation(&self) -> Option<&dyn Operation> {
        self.operation.as_deref()
    }
    /// Native refusal retained for reporting before admission is requested.
    pub fn blocked(&self) -> Option<Error> {
        self.blocked
    }
}

/// A complete registered decision list bound to exact requested components.
pub struct Plan<'a> {
    target: Firmware<'a>,
    decisions: Vec<Decision>,
    domain_comparison: Comparison,
    policy: Policy,
}
impl core::fmt::Debug for Plan<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Plan")
            .field("hardware", &self.target.hardware)
            .field("normal_len", &self.target.normal.len())
            .field("domain_comparison", &self.domain_comparison)
            .field("decisions", &self.decisions)
            .finish()
    }
}
impl Plan<'_> {
    /// Every owner decision, in registry/report order.
    pub fn decisions(&self) -> &[Decision] {
        &self.decisions
    }

    /// Selected operations in deterministic registry order.
    pub fn operations(&self) -> impl Iterator<Item = &dyn Operation> {
        self.decisions.iter().filter_map(Decision::operation)
    }

    /// Collect the read-only conditions from the same selected operations that
    /// prepare and verify image effects. Family override cannot waive them.
    pub fn required_words(&self) -> Result<Vec<super::prerequisites::OwnedWord>, Error> {
        self.admit()?;
        super::prerequisites::collect(self.operations())
    }

    /// Words the selected operations set before transfer. A word cannot be
    /// both a read-only condition and a write.
    pub fn word_writes(&self) -> Result<Vec<super::prerequisites::OwnedWord>, Error> {
        let reads = self.required_words()?;
        let writes = super::prerequisites::collect_writes(self.operations())?;
        if writes
            .iter()
            .any(|w| reads.iter().any(|r| r.word.parameter == w.word.parameter))
        {
            return Err(Error::VerificationFailed);
        }
        Ok(writes)
    }

    /// Refuse every owner failure before preparing files or device I/O.
    pub fn admit(&self) -> Result<(), Error> {
        if self.policy == Policy::Strict {
            match self.domain_comparison {
                Comparison::Match => {}
                Comparison::Different => return Err(Error::Incompatible),
                Comparison::Unresolved | Comparison::Conflicting => {
                    return Err(Error::UnresolvedIdentity)
                }
            }
        }
        let specific = self
            .decisions
            .iter()
            .filter_map(|decision| decision.blocked)
            .find(|error| !matches!(error, Error::Incompatible | Error::UnresolvedIdentity));
        match specific.or_else(|| self.decisions.iter().find_map(|decision| decision.blocked)) {
            Some(error) => Err(error),
            None => super::prerequisites::collect(self.operations()).map(|_| ()),
        }
    }

    /// Require the same complete decoded components used by owner planning.
    pub fn matches_components(&self, context: &Preparation<'_>) -> bool {
        context.target.hardware == self.target.hardware
            && context.target.normal == self.target.normal
            && context.target.kernel == self.target.kernel
            && self.matches_files(context)
    }

    #[cfg(feature = "envelope")]
    fn matches_files(&self, context: &Preparation<'_>) -> bool {
        context.normal.map_or(true, |normal| {
            normal.image == self.target.normal
                && normal.info().hardware_version == self.target.hardware
        }) && context.kernel.map_or(true, |kernel| {
            self.target.kernel == Some(kernel.image.as_slice())
                && kernel.info().hardware_version == self.target.hardware
        })
    }

    #[cfg(not(feature = "envelope"))]
    fn matches_files(&self, _context: &Preparation<'_>) -> bool {
        true
    }

    /// Prepare Normal bytes through complete-pair verification.
    /// A Kernel effect cannot be represented by this legacy return type.
    pub fn prepare(&self, context: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
        self.prepare_with(context, super::filters())
    }

    /// The checked Normal-only path for an explicitly supplied registry.
    pub fn prepare_with(
        &self,
        context: &Preparation<'_>,
        registry: &[&dyn Filter],
    ) -> Result<Option<Vec<u8>>, Error> {
        match self.prepare_components_with(context, registry)? {
            Some(pair) if pair.kernel.as_deref() != self.target.kernel => Err(Error::Unsupported),
            Some(pair) => Ok(Some(pair.normal)),
            None => Ok(None),
        }
    }

    /// Compose same-length effects and verify the complete final decoded pair.
    /// This does not authenticate envelopes or authorize device transfer.
    pub fn prepare_components(
        &self,
        context: &Preparation<'_>,
    ) -> Result<Option<PreparedComponents>, Error> {
        self.prepare_components_with(context, super::filters())
    }

    /// Complete-pair preparation for an explicitly supplied owner registry.
    pub fn prepare_components_with(
        &self,
        context: &Preparation<'_>,
        registry: &[&dyn Filter],
    ) -> Result<Option<PreparedComponents>, Error> {
        self.admit()?;
        if !self.matches_components(context) {
            return Err(Error::ComponentMismatch);
        }
        self.check_registry(registry)?;
        let mut normal_outputs = Vec::new();
        let mut kernel_outputs = Vec::new();
        for operation in self.operations() {
            let outputs = operation.prepare_components(context)?;
            if let Some(image) = outputs.normal {
                if image.len() != self.target.normal.len() {
                    return Err(Error::Representation);
                }
                normal_outputs.push((image, operation.component_integrity(crate::Role::Normal)));
            }
            if let Some(image) = outputs.kernel {
                let original = self.target.kernel.ok_or(Error::ComponentMismatch)?;
                if image.len() != original.len() {
                    return Err(Error::Representation);
                }
                kernel_outputs.push((image, operation.component_integrity(crate::Role::Kernel)));
            }
        }
        let normal = match normal_outputs.len() {
            0 => self.target.normal.to_vec(),
            1 if normal_outputs[0].1.is_none() => normal_outputs.pop().expect("one output").0,
            _ => compose(
                context,
                crate::Role::Normal,
                self.target.normal,
                normal_outputs,
            )?,
        };
        let kernel = match self.target.kernel {
            Some(original) if !kernel_outputs.is_empty() => Some(compose(
                context,
                crate::Role::Kernel,
                original,
                kernel_outputs,
            )?),
            original => original.map(<[u8]>::to_vec),
        };
        let prepared = PreparedComponents { normal, kernel };
        self.verify_components_with(
            context,
            Firmware {
                hardware: self.target.hardware,
                normal: &prepared.normal,
                kernel: prepared.kernel.as_deref(),
            },
            registry,
        )?;
        Ok((prepared.normal != self.target.normal
            || prepared.kernel.as_deref() != self.target.kernel)
            .then_some(prepared))
    }

    /// Verify every selected postcondition and every untouched native contract.
    /// A valid selected correction may change its own candidate contribution.
    pub fn verify(&self, context: &Preparation<'_>, normal: &[u8]) -> Result<(), Error> {
        self.verify_with(context, normal, super::filters())
    }

    /// Verify against the same explicitly supplied owner inventory.
    pub fn verify_with(
        &self,
        context: &Preparation<'_>,
        normal: &[u8],
        registry: &[&dyn Filter],
    ) -> Result<(), Error> {
        self.verify_components_with(
            context,
            Firmware {
                hardware: self.target.hardware,
                normal,
                kernel: self.target.kernel,
            },
            registry,
        )
    }

    /// Verify selected and untouched owners against the actual final pair.
    pub fn verify_components(
        &self,
        context: &Preparation<'_>,
        final_pair: Firmware<'_>,
    ) -> Result<(), Error> {
        self.verify_components_with(context, final_pair, super::filters())
    }

    /// Complete-pair verification against the same supplied owner inventory.
    pub fn verify_components_with(
        &self,
        context: &Preparation<'_>,
        final_pair: Firmware<'_>,
        registry: &[&dyn Filter],
    ) -> Result<(), Error> {
        self.admit()?;
        if !self.matches_components(context)
            || final_pair.hardware != self.target.hardware
            || final_pair.normal.len() != self.target.normal.len()
            || final_pair.kernel.map(<[u8]>::len) != self.target.kernel.map(<[u8]>::len)
        {
            return Err(Error::ComponentMismatch);
        }
        self.check_registry(registry)?;
        let after_context = Context::new(final_pair);
        for decision in &self.decisions {
            let index = registry
                .iter()
                .position(|owner| owner.id() == decision.id)
                .ok_or(Error::VerificationFailed)?;
            let owner = registry[index];
            let after = after_context.inspect_in(registry, index);
            if after.id != decision.id || after.role != decision.target.role {
                return Err(Error::VerificationFailed);
            }
            if let Some(operation) = &decision.operation {
                operation.verify_components(context, final_pair)?;
            } else if matches!(
                decision.target.finding,
                Finding::Known(_) | Finding::NotApplicable { .. }
            ) {
                // A waived mismatch may retain the requested fact; it must not
                // grant another owner's effect permission to change that fact.
                if owner.compare(&decision.target, &after) != Comparison::Match {
                    return Err(Error::VerificationFailed);
                }
            } else if !decision.waived && decision.target.role == Role::Hardware {
                return Err(Error::VerificationFailed);
            }
        }
        Ok(())
    }

    fn check_registry(&self, registry: &[&dyn Filter]) -> Result<(), Error> {
        let ids: BTreeSet<_> = registry.iter().map(|owner| owner.id()).collect();
        if ids.len() != registry.len()
            || registry.len() != self.decisions.len()
            || self
                .decisions
                .iter()
                .any(|decision| !ids.contains(decision.id))
        {
            return Err(Error::ComponentMismatch);
        }
        Ok(())
    }
}

/// Discover every owner and retain every decision, including refusal details.
pub fn evaluate<'a>(
    installed: &Context<'_>,
    target: &Context<'a>,
    policy: Policy,
) -> Result<Plan<'a>, Error> {
    evaluate_with(installed, target, policy, super::filters())
}

/// Evaluate a supplied owner registry without a platform-specific field list.
pub fn evaluate_with<'a>(
    installed: &Context<'_>,
    target: &Context<'a>,
    policy: Policy,
    registry: &[&dyn Filter],
) -> Result<Plan<'a>, Error> {
    let mut ids = BTreeSet::new();
    let mut decisions = Vec::new();
    let transition = Transition { installed, target };
    for (index, owner) in registry.iter().enumerate() {
        let id = owner.id();
        if id.is_empty() || !ids.insert(id) {
            return Err(Error::UnresolvedIdentity);
        }
        let installed = installed.inspect_in(registry, index);
        let target = target.inspect_in(registry, index);
        if installed.id != id || target.id != id {
            return Err(Error::UnresolvedIdentity);
        }
        let comparison = owner.compare(&installed, &target);
        let mut operation = None;
        let mut blocked = None;
        match owner.plan(&transition, &installed, &target) {
            Ok(selected) => {
                if selected
                    .as_ref()
                    .is_some_and(|operation| operation.filter_id() != id)
                {
                    return Err(Error::VerificationFailed);
                }
                operation = selected;
            }
            Err(error) => blocked = Some(error),
        }
        decisions.push(Decision {
            id,
            installed,
            target,
            comparison,
            waived: false,
            operation,
            blocked,
        });
    }
    let domain_comparison = match (
        super::identity::Domain::from_hardware(installed.firmware.hardware),
        super::identity::Domain::from_hardware(target.firmware.hardware),
    ) {
        (Some(a), Some(b)) if a == b => Comparison::Match,
        (Some(_), Some(_)) => Comparison::Different,
        _ => Comparison::Unresolved,
    };
    Ok(Plan {
        target: target.firmware,
        decisions,
        domain_comparison,
        policy,
    })
}

/// Build an admitted plan using the complete registered inventory.
pub fn plan<'a>(
    installed: &Context<'_>,
    target: &Context<'a>,
    policy: Policy,
) -> Result<Plan<'a>, Error> {
    let plan = evaluate(installed, target, policy)?;
    plan.admit()?;
    Ok(plan)
}

/// Build an admitted plan using an explicitly supplied registry.
pub fn plan_with<'a>(
    installed: &Context<'_>,
    target: &Context<'a>,
    policy: Policy,
    registry: &[&dyn Filter],
) -> Result<Plan<'a>, Error> {
    let plan = evaluate_with(installed, target, policy, registry)?;
    plan.admit()?;
    Ok(plan)
}

fn compose(
    context: &Preparation<'_>,
    component: crate::Role,
    original: &[u8],
    outputs: Vec<(Vec<u8>, Option<Integrity>)>,
) -> Result<Vec<u8>, Error> {
    let integrity = outputs[0].1.as_ref().ok_or(Error::Unsupported)?;
    if integrity.id.is_empty()
        || outputs.iter().any(|(_, contract)| {
            contract.as_ref().map_or(true, |contract| {
                contract.id != integrity.id || contract.fields != integrity.fields
            })
        })
    {
        return Err(Error::Unsupported);
    }
    let effects: Vec<_> = outputs
        .iter()
        .map(|(image, _)| super::composition::ComponentEffect {
            component,
            basis: original,
            image,
        })
        .collect();
    super::composition::compose_component(
        component,
        original,
        &effects,
        &integrity.fields,
        |image| (integrity.repair)(context, image),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::{be32_normal_integrity, Value};
    use alloc::vec;

    #[test]
    fn family_override_cannot_waive_conflicting_owner_read_conditions() {
        use crate::filters::prerequisites::Word;
        #[derive(Debug)]
        struct ReadOwner(&'static str, u16);
        impl Operation for ReadOwner {
            fn filter_id(&self) -> &'static str {
                self.0
            }
            fn required_words(&self) -> Vec<Word> {
                vec![Word {
                    parameter: 0x28f,
                    value: self.1,
                }]
            }
            fn prepare(&self, _: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
                Ok(None)
            }
            fn verify(&self, _: &Preparation<'_>, _: &[u8]) -> Result<(), Error> {
                Ok(())
            }
        }
        let decision = |id, value| {
            let assessment =
                Assessment::known(id, Role::Hardware, Value::U16(value), "native condition");
            Decision {
                id,
                installed: assessment.clone(),
                target: assessment,
                comparison: Comparison::Match,
                waived: false,
                operation: Some(Box::new(ReadOwner(id, value))),
                blocked: None,
            }
        };
        let mut plan = Plan {
            target: Firmware {
                hardware: "SAT 8600",
                normal: &[],
                kernel: None,
            },
            decisions: vec![decision("phase", 1), decision("startup", 0)],
            domain_comparison: Comparison::Different,
            policy: Policy::FamilyOverride,
        };
        assert_eq!(plan.admit(), Err(Error::VerificationFailed));
        assert_eq!(plan.required_words(), Err(Error::VerificationFailed));
        plan.decisions[1] = decision("startup", 1);
        assert_eq!(plan.admit(), Ok(()));
        let words = plan.required_words().unwrap();
        assert_eq!(
            words.iter().map(|w| w.filter).collect::<Vec<_>>(),
            ["phase", "startup"]
        );
        plan.decisions[1].blocked = Some(Error::Unsupported);
        assert_eq!(plan.required_words(), Err(Error::Unsupported));
    }

    #[derive(Clone, Copy)]
    enum Contract {
        Be32,
        DirtyOutput,
        Missing,
        OtherId,
        OtherFields,
        InvalidFields,
        OverlappingFields,
        EmptyFields,
        BadRepair,
    }
    struct Owner {
        id: &'static str,
        offset: usize,
        correctable: bool,
        contract: Contract,
        extra: Option<(usize, u8)>,
        role: Role,
        error: Option<Error>,
        finding: Option<Finding>,
        op_id: Option<&'static str>,
        truncate: bool,
    }
    impl Owner {
        fn field(id: &'static str, offset: usize) -> Self {
            Self {
                id,
                offset,
                correctable: true,
                contract: Contract::Be32,
                extra: None,
                role: Role::Hardware,
                error: None,
                finding: None,
                op_id: None,
                truncate: false,
            }
        }
    }
    impl Filter for Owner {
        fn id(&self) -> &'static str {
            self.id
        }
        fn name(&self) -> &'static str {
            "Native test field"
        }
        fn inspect(&self, context: &Context<'_>) -> Assessment {
            Assessment {
                id: self.id,
                role: self.role,
                finding: self.finding.clone().unwrap_or_else(|| {
                    Finding::Known(Value::U8(context.firmware.normal[self.offset]))
                }),
                evidence: "complete synthetic native field".into(),
            }
        }
        fn plan(
            &self,
            transition: &Transition<'_, '_>,
            installed: &Assessment,
            target: &Assessment,
        ) -> Result<Option<Box<dyn Operation>>, Error> {
            if let Some(error) = self.error {
                return Err(error);
            }
            match self.compare(installed, target) {
                Comparison::Match => Ok(None),
                Comparison::Different if self.correctable => Ok(Some(Box::new(Patch {
                    id: self.op_id.unwrap_or(self.id),
                    original: transition.target.firmware.normal.to_vec(),
                    offset: self.offset,
                    value: transition.installed.firmware.normal[self.offset],
                    contract: self.contract,
                    extra: self.extra,
                    truncate: self.truncate,
                }))),
                Comparison::Different => Err(Error::Incompatible),
                _ => Err(Error::UnresolvedIdentity),
            }
        }
    }
    #[derive(Debug)]
    struct Patch {
        id: &'static str,
        original: Vec<u8>,
        offset: usize,
        value: u8,
        contract: Contract,
        extra: Option<(usize, u8)>,
        truncate: bool,
    }
    impl core::fmt::Debug for Contract {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("native integrity fixture")
        }
    }
    impl Operation for Patch {
        fn filter_id(&self) -> &'static str {
            self.id
        }
        fn prepare(&self, context: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
            if context.target.normal != self.original {
                return Err(Error::ComponentMismatch);
            }
            let mut image = self.original.clone();
            image[self.offset] = self.value;
            if let Some((offset, value)) = self.extra {
                image[offset] = value;
            }
            if self.truncate {
                image.truncate(image.len() - 4);
                return Ok(Some(image));
            }
            if matches!(self.contract, Contract::DirtyOutput) {
                return Ok(Some(image));
            }
            Ok(Some((be32_normal_integrity().repair)(context, &image)?))
        }
        fn integrity(&self) -> Option<Integrity> {
            let mut integrity = be32_normal_integrity();
            match self.contract {
                Contract::Be32 | Contract::DirtyOutput => {}
                Contract::Missing => return None,
                Contract::OtherId => integrity.id = "different.native.contract",
                Contract::OtherFields => integrity.fields = std::iter::once(12..16).collect(),
                Contract::InvalidFields => {
                    integrity.fields = std::iter::once(16..usize::MAX).collect()
                }
                Contract::OverlappingFields => integrity.fields = vec![16..20, 18..22],
                Contract::EmptyFields => {
                    // A repair that accepts anything, so only the empty-field
                    // check can refuse this contract.
                    integrity.fields = std::iter::once(16..16).collect();
                    integrity.repair = |_context, image| Ok(image.to_vec());
                }
                Contract::BadRepair => {
                    integrity.repair = |_context, image| {
                        let mut image = image.to_vec();
                        image[0] ^= 1;
                        Ok(image)
                    }
                }
            }
            Some(integrity)
        }
        fn verify(&self, _context: &Preparation<'_>, normal: &[u8]) -> Result<(), Error> {
            if normal[self.offset] == self.value {
                Ok(())
            } else {
                Err(Error::VerificationFailed)
            }
        }
    }
    fn image() -> Vec<u8> {
        let mut image = vec![0; 32];
        image[..8].copy_from_slice(b"PIONEER ");
        image[24..28].fill(1);
        checksum(&mut image);
        image
    }
    fn checksum(image: &mut [u8]) {
        image[16..20].fill(0);
        let sum = image.chunks_exact(4).fold(0u32, |sum, word| {
            sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
        });
        image[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
    }
    fn context(normal: &[u8]) -> Context<'_> {
        Context::new(Firmware {
            hardware: "SAT 8000",
            normal,
            kernel: None,
        })
    }
    fn preparation<'a>(context: &Context<'a>) -> Preparation<'a> {
        Preparation {
            target: context.firmware,
            #[cfg(feature = "envelope")]
            normal: None,
            #[cfg(feature = "envelope")]
            kernel: None,
        }
    }

    #[test]
    fn disjoint_owners_compose_atomically_and_repair_one_shared_checksum() {
        let target = image();
        let mut source = target.clone();
        source[24] = 2;
        source[25] = 3;
        checksum(&mut source);
        let (source_context, target_context) = (context(&source), context(&target));
        let first = Owner::field("first", 24);
        let second = Owner::field("second", 25);
        let untouched = Owner::field("untouched", 26);
        let registry: &[&dyn Filter] = &[&first, &second, &untouched];
        let plan = plan_with(&source_context, &target_context, Policy::Strict, registry).unwrap();
        let before = target.clone();
        let output = plan
            .prepare_with(&preparation(&target_context), registry)
            .unwrap()
            .unwrap();
        assert_eq!(output, source);
        assert_eq!(target, before);
        assert_eq!(plan.operations().count(), 2);
        assert!(plan.decisions().iter().all(|decision| !decision.waived));
        plan.verify_with(&preparation(&target_context), &output, registry)
            .unwrap();
    }

    #[test]
    fn identical_overlapping_claims_refuse_instead_of_silently_collapsing() {
        let target = image();
        let mut source = target.clone();
        source[24] = 2;
        checksum(&mut source);
        let (a, b) = (context(&source), context(&target));
        let first = Owner::field("first", 24);
        let second = Owner::field("second", 24);
        let registry: &[&dyn Filter] = &[&first, &second];
        let plan = plan_with(&a, &b, Policy::Strict, registry).unwrap();
        assert_eq!(
            plan.prepare_with(&preparation(&b), registry),
            Err(Error::Unsupported)
        );
        assert_eq!(b.firmware.normal, target);
    }

    #[test]
    fn composition_requires_same_proved_integrity_and_repair_cannot_edit_code() {
        let target = image();
        let mut source = target.clone();
        source[24] = 2;
        source[25] = 3;
        checksum(&mut source);
        let (a, b) = (context(&source), context(&target));
        for contract in [Contract::Missing, Contract::OtherId, Contract::OtherFields] {
            let first = Owner::field("first", 24);
            let mut second = Owner::field("second", 25);
            second.contract = contract;
            let registry: &[&dyn Filter] = &[&first, &second];
            let plan = plan_with(&a, &b, Policy::Strict, registry).unwrap();
            assert_eq!(
                plan.prepare_with(&preparation(&b), registry),
                Err(Error::Unsupported)
            );
        }
        for (contract, expected) in [
            (Contract::InvalidFields, Error::Representation),
            (Contract::OverlappingFields, Error::Representation),
            (Contract::EmptyFields, Error::Representation),
            (Contract::BadRepair, Error::VerificationFailed),
        ] {
            let mut first = Owner::field("first", 24);
            let mut second = Owner::field("second", 25);
            first.contract = contract;
            second.contract = contract;
            let registry: &[&dyn Filter] = &[&first, &second];
            let plan = plan_with(&a, &b, Policy::Strict, registry).unwrap();
            assert_eq!(plan.prepare_with(&preparation(&b), registry), Err(expected));
        }
    }

    #[test]
    fn one_owner_with_integrity_repairs_operand_only_output_before_verification() {
        let target = image();
        let mut source = target.clone();
        source[24] = 2;
        checksum(&mut source);
        let (a, b) = (context(&source), context(&target));
        let mut owner = Owner::field("native", 24);
        owner.contract = Contract::DirtyOutput;
        let registry: &[&dyn Filter] = &[&owner];
        let plan = plan_with(&a, &b, Policy::Strict, registry).unwrap();
        let preparation = preparation(&b);
        let dirty = plan
            .operations()
            .next()
            .unwrap()
            .prepare(&preparation)
            .unwrap()
            .unwrap();
        assert_eq!(&dirty[16..20], &target[16..20]);
        assert_ne!(dirty, source);
        let output = plan.prepare_with(&preparation, registry).unwrap().unwrap();
        assert_eq!(output, source);
    }

    #[test]
    fn one_owner_needs_no_composition_contract_and_equal_input_preserves_bytes() {
        let target = image();
        let mut source = target.clone();
        source[24] = 2;
        checksum(&mut source);
        let (a, b) = (context(&source), context(&target));
        let mut owner = Owner::field("native", 24);
        owner.contract = Contract::Missing;
        let registry: &[&dyn Filter] = &[&owner];
        let plan = plan_with(&a, &b, Policy::Strict, registry).unwrap();
        assert_eq!(
            plan.prepare_with(&preparation(&b), registry).unwrap(),
            Some(source)
        );
        let same = plan_with(&b, &b, Policy::Strict, registry).unwrap();
        assert!(same
            .prepare_with(&preparation(&b), registry)
            .unwrap()
            .is_none());
    }

    #[test]
    fn family_override_refuses_uncorrectable_owner_and_preserves_postconditions() {
        let target = image();
        let mut source = target.clone();
        source[24] = 2;
        source[26] = 9;
        checksum(&mut source);
        let (a, b) = (context(&source), context(&target));
        let phase = Owner::field("phase", 24);
        let mut other = Owner::field("other", 26);
        other.correctable = false;
        let registry: &[&dyn Filter] = &[&phase, &other];
        for policy in [Policy::Strict, Policy::FamilyOverride] {
            let evaluated = evaluate_with(&a, &b, policy, registry).unwrap();
            let decision = &evaluated.decisions()[1];
            assert_eq!(decision.comparison, Comparison::Different);
            assert_eq!(decision.blocked(), Some(Error::Incompatible));
            assert!(!decision.waived);
            assert!(decision.operation().is_none());
            assert_eq!(evaluated.admit(), Err(Error::Incompatible));
            assert_eq!(
                evaluated.prepare_with(&preparation(&b), registry),
                Err(Error::Incompatible)
            );
            assert!(matches!(
                plan_with(&a, &b, policy, registry),
                Err(Error::Incompatible)
            ));
        }

        // Admit the supported correction with an actually matching untouched
        // owner, then retain the independent extra-write/postcondition guard.
        source[26] = target[26];
        checksum(&mut source);
        let a = context(&source);
        let plan = plan_with(&a, &b, Policy::FamilyOverride, registry).unwrap();
        assert!(plan.decisions().iter().all(|decision| !decision.waived));
        let output = plan
            .prepare_with(&preparation(&b), registry)
            .unwrap()
            .unwrap();
        assert_eq!((output[24], output[26]), (2, 1));
        let mut bad_phase = Owner::field("phase", 24);
        bad_phase.extra = Some((26, 9));
        let registry: &[&dyn Filter] = &[&bad_phase, &other];
        let plan = plan_with(&a, &b, Policy::FamilyOverride, registry).unwrap();
        assert_eq!(
            plan.prepare_with(&preparation(&b), registry),
            Err(Error::VerificationFailed)
        );
    }

    #[test]
    fn forcing_never_waives_operational_or_selected_proof_errors() {
        let target = image();
        let mut source = target.clone();
        source[24] = 2;
        checksum(&mut source);
        let (a, b) = (context(&source), context(&target));
        let mut owner = Owner::field("operational", 24);
        owner.role = Role::Operational;
        owner.correctable = false;
        assert!(matches!(
            plan_with(&a, &b, Policy::FamilyOverride, &[&owner]),
            Err(Error::Incompatible)
        ));
        owner.role = Role::Hardware;
        owner.error = Some(Error::Unsupported);
        assert!(matches!(
            plan_with(&a, &b, Policy::FamilyOverride, &[&owner]),
            Err(Error::Unsupported)
        ));
        owner.error = None;
        owner.finding = Some(Finding::Unresolved("no native reader".into()));
        for policy in [Policy::Strict, Policy::FamilyOverride] {
            let evaluated = evaluate_with(&a, &b, policy, &[&owner]).unwrap();
            let decision = &evaluated.decisions()[0];
            assert_eq!(decision.comparison, Comparison::Unresolved);
            assert_eq!(decision.blocked(), Some(Error::UnresolvedIdentity));
            assert!(!decision.waived);
            assert!(decision.operation().is_none());
            assert_eq!(evaluated.admit(), Err(Error::UnresolvedIdentity));
            assert_eq!(
                evaluated.prepare_with(&preparation(&b), &[&owner]),
                Err(Error::UnresolvedIdentity)
            );
        }
    }

    #[test]
    fn components_registry_and_nonselected_postconditions_are_bound() {
        let target = image();
        let mut source = target.clone();
        source[24] = 2;
        checksum(&mut source);
        let (a, b) = (context(&source), context(&target));
        let first = Owner::field("first", 24);
        let other = Owner::field("other", 25);
        let registry: &[&dyn Filter] = &[&first, &other];
        let plan = plan_with(&a, &b, Policy::Strict, registry).unwrap();
        let mut swapped = target.clone();
        swapped[27] ^= 1;
        checksum(&mut swapped);
        assert_eq!(
            plan.prepare_with(&preparation(&context(&swapped)), registry),
            Err(Error::ComponentMismatch)
        );
        assert_eq!(
            plan.prepare_with(&preparation(&b), &[&first]),
            Err(Error::ComponentMismatch)
        );
        assert!(matches!(
            plan_with(&a, &b, Policy::Strict, &[&first, &first]),
            Err(Error::UnresolvedIdentity)
        ));
        let mut output = plan
            .prepare_with(&preparation(&b), registry)
            .unwrap()
            .unwrap();
        output[25] ^= 1;
        checksum(&mut output);
        assert_eq!(
            plan.verify_with(&preparation(&b), &output, registry),
            Err(Error::VerificationFailed)
        );
    }

    #[test]
    fn no_operation_plan_binds_original_pair_before_noop_return() {
        let normal = image();
        let kernel = [1, 2, 3, 4];
        let target = Context::new(Firmware {
            hardware: "SAT 8600",
            normal: &normal,
            kernel: Some(&kernel),
        });
        let owner = Owner::field("unchanged", 24);
        let registry: &[&dyn Filter] = &[&owner];
        let mut changed_normal = normal.clone();
        changed_normal[27] ^= 1;
        for policy in [Policy::Strict, Policy::FamilyOverride] {
            let plan = plan_with(&target, &target, policy, registry).unwrap();
            assert_eq!(plan.operations().count(), 0);
            assert_eq!(
                plan.prepare_components_with(&preparation(&target), registry),
                Ok(None)
            );
            for substitute in [
                Firmware {
                    normal: &changed_normal,
                    ..target.firmware
                },
                Firmware {
                    kernel: Some(&[9, 2, 3, 4]),
                    ..target.firmware
                },
                Firmware {
                    kernel: None,
                    ..target.firmware
                },
                Firmware {
                    hardware: "SAT 9000",
                    ..target.firmware
                },
            ] {
                let substituted = Context::new(substitute);
                assert_eq!(
                    plan.prepare_components_with(&preparation(&substituted), registry),
                    Err(Error::ComponentMismatch)
                );
                assert_eq!(
                    plan.prepare_with(&preparation(&substituted), registry),
                    Err(Error::ComponentMismatch)
                );
            }
        }
    }

    #[test]
    fn h8_sat_platforms_share_a_partition_and_others_stay_separate() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Plan<'static>>();
        let image = image();
        let a = context(&image);
        let owner = Owner::field("constant", 24);
        let sat9 = Context::new(Firmware {
            hardware: "SAT 9000",
            normal: &image,
            kernel: None,
        });
        let plan = plan_with(&a, &sat9, Policy::Strict, &[&owner]).unwrap();
        assert!(
            plan.admit().is_ok(),
            "SAT8 and SAT9 share the H8 SAT platform"
        );
        for hardware in ["SAT 1046", "ATA 0004", "SCSI0001"] {
            let other = Context::new(Firmware {
                hardware,
                normal: &image,
                kernel: None,
            });
            assert!(
                matches!(
                    plan_with(&a, &other, Policy::Strict, &[&owner]).and_then(|p| p.admit()),
                    Err(Error::Incompatible)
                ),
                "{hardware} must stay on its own platform"
            );
            let plan = plan_with(&a, &other, Policy::FamilyOverride, &[&owner]).unwrap();
            assert_eq!(plan.decisions()[0].comparison, Comparison::Match);
            assert_eq!(plan.decisions()[0].blocked(), None);
            assert!(!plan.decisions()[0].waived);
            assert_eq!(plan.prepare_with(&preparation(&other), &[&owner]), Ok(None));
        }
    }

    #[test]
    fn specific_refusals_outrank_generic_ones_and_unknown_domains_refuse() {
        let target = image();
        let mut source = target.clone();
        source[24] = 2;
        checksum(&mut source);
        let (a, b) = (context(&source), context(&target));
        let mut first = Owner::field("first", 24);
        first.correctable = false;
        let mut second = Owner::field("second", 25);
        second.error = Some(Error::Unsupported);
        for registry in [[&first, &second], [&second, &first]] {
            let registry: Vec<&dyn Filter> =
                registry.into_iter().map(|o| o as &dyn Filter).collect();
            let plan = evaluate_with(&a, &b, Policy::Strict, &registry).unwrap();
            assert_eq!(plan.admit(), Err(Error::Unsupported));
        }
        let unknown = |normal| {
            Context::new(Firmware {
                hardware: "UNKNOWN",
                normal,
                kernel: None,
            })
        };
        let owner = Owner::field("constant", 24);
        let plan = evaluate_with(
            &unknown(&target),
            &unknown(&target),
            Policy::Strict,
            &[&owner],
        )
        .unwrap();
        assert_eq!(plan.admit(), Err(Error::UnresolvedIdentity));
    }

    #[test]
    fn foreign_operations_short_images_and_malformed_fields_refuse() {
        let target = image();
        let mut source = target.clone();
        source[24] = 2;
        source[25] = 3;
        checksum(&mut source);
        let (a, b) = (context(&source), context(&target));
        let mut foreign = Owner::field("first", 24);
        foreign.op_id = Some("other");
        assert!(matches!(
            plan_with(&a, &b, Policy::Strict, &[&foreign]),
            Err(Error::VerificationFailed)
        ));
        let mut short = Owner::field("first", 24);
        short.truncate = true;
        let registry: &[&dyn Filter] = &[&short];
        let plan = plan_with(&a, &b, Policy::Strict, registry).unwrap();
        assert_eq!(
            plan.prepare_with(&preparation(&b), registry),
            Err(Error::Representation)
        );
        for contract in [Contract::OverlappingFields, Contract::EmptyFields] {
            let mut first = Owner::field("first", 24);
            let mut second = Owner::field("second", 25);
            first.contract = contract;
            second.contract = contract;
            let registry: &[&dyn Filter] = &[&first, &second];
            let plan = plan_with(&a, &b, Policy::Strict, registry).unwrap();
            assert_eq!(
                plan.prepare_with(&preparation(&b), registry),
                Err(Error::Representation)
            );
        }
    }

    #[test]
    fn one_registration_automatically_changes_matching_and_report_inventory() {
        let target = image();
        let mut source = target.clone();
        source[25] = 9;
        checksum(&mut source);
        let (a, b) = (context(&source), context(&target));
        let existing = Owner::field("existing", 24);
        let mut newly_registered = Owner::field("new-native-contract", 25);
        newly_registered.correctable = false;
        let before = plan_with(&a, &b, Policy::Strict, &[&existing]).unwrap();
        assert_eq!(before.decisions().len(), 1);
        let after = evaluate_with(&a, &b, Policy::Strict, &[&existing, &newly_registered]).unwrap();
        assert_eq!(after.decisions().len(), 2);
        assert_eq!(after.decisions()[1].id, "new-native-contract");
        assert_eq!(after.decisions()[1].comparison, Comparison::Different);
        assert_eq!(after.admit(), Err(Error::Incompatible));
    }
}

#[cfg(test)]
#[path = "runner_pair_tests.rs"]
mod pair_tests;
