//! Generic owner decisions and atomic composition of verified Normal effects.
use super::{
    Assessment, Comparison, Context, Filter, Finding, Integrity, Operation, Preparation, Role,
    Transition,
};
use crate::compatibility::{Error, Firmware};
use alloc::{boxed::Box, collections::BTreeSet, vec, vec::Vec};

/// Admission policy for the independent hardware-family gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Every required owner must establish a compatible native transition.
    Strict,
    /// Record explicit hardware-family overrides while retaining operational
    /// requirements and every selected correction's application/verification.
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
    /// Explicit family waiver, independent of correction capability.
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

    /// Refuse any unwaived owner failure before preparing files or device I/O.
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
            None => Ok(()),
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

    /// Apply operations against their immutable original input, merge disjoint
    /// native edits, repair their common integrity contract once and verify all
    /// owners. Unknown integrity or overlapping effects refuse composition.
    pub fn prepare(&self, context: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
        self.prepare_with(context, super::filters())
    }

    /// The same atomic path for an explicitly supplied registry.
    pub fn prepare_with(
        &self,
        context: &Preparation<'_>,
        registry: &[&dyn Filter],
    ) -> Result<Option<Vec<u8>>, Error> {
        self.admit()?;
        if !self.matches_components(context) {
            return Err(Error::ComponentMismatch);
        }
        self.check_registry(registry)?;
        let mut outputs = Vec::new();
        for operation in self.operations() {
            if let Some(image) = operation.prepare(context)? {
                if image.len() != self.target.normal.len() {
                    return Err(Error::Representation);
                }
                outputs.push((image, operation.integrity()));
            }
        }
        let prepared = match outputs.len() {
            0 => None,
            1 if outputs[0].1.is_none() => Some(outputs.pop().expect("one output").0),
            _ => Some(compose(context, outputs)?),
        };
        self.verify_with(
            context,
            prepared.as_deref().unwrap_or(self.target.normal),
            registry,
        )?;
        Ok(prepared.filter(|image| image != self.target.normal))
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
        self.admit()?;
        if !self.matches_components(context) || normal.len() != self.target.normal.len() {
            return Err(Error::ComponentMismatch);
        }
        self.check_registry(registry)?;
        let after_context = Context::new(Firmware {
            hardware: self.target.hardware,
            normal,
            kernel: self.target.kernel,
        });
        for decision in &self.decisions {
            let owner = registry
                .iter()
                .find(|owner| owner.id() == decision.id)
                .ok_or(Error::VerificationFailed)?;
            let after = owner.inspect(&after_context);
            if after.id != decision.id || after.role != decision.target.role {
                return Err(Error::VerificationFailed);
            }
            if let Some(operation) = &decision.operation {
                operation.verify(context, normal)?;
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
    for owner in registry {
        let id = owner.id();
        if id.is_empty() || !ids.insert(id) {
            return Err(Error::UnresolvedIdentity);
        }
        let installed = owner.inspect(installed);
        let target = owner.inspect(target);
        if installed.id != id || target.id != id {
            return Err(Error::UnresolvedIdentity);
        }
        let comparison = owner.compare(&installed, &target);
        let mut operation = None;
        let mut blocked = None;
        let mut waived = false;
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
            Err(error)
                if policy == Policy::FamilyOverride
                    && target.role == Role::Hardware
                    && matches!(error, Error::Incompatible | Error::UnresolvedIdentity) =>
            {
                waived = true;
            }
            Err(error) => blocked = Some(error),
        }
        decisions.push(Decision {
            id,
            installed,
            target,
            comparison,
            waived,
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
    let original = context.target.normal;
    let mut checksum = vec![false; original.len()];
    for field in &integrity.fields {
        let bytes = checksum
            .get_mut(field.clone())
            .ok_or(Error::Representation)?;
        if bytes.is_empty() || bytes.iter().any(|&used| used) {
            return Err(Error::Representation);
        }
        bytes.fill(true);
    }
    let mut claimed = vec![false; original.len()];
    let mut prepared = original.to_vec();
    for (image, _) in &outputs {
        for (at, (&before, &after)) in original.iter().zip(image).enumerate() {
            if before == after || checksum[at] {
                continue;
            }
            if claimed[at] {
                return Err(Error::Unsupported);
            }
            claimed[at] = true;
            prepared[at] = after;
        }
    }
    let repaired = (integrity.repair)(context, &prepared)?;
    if repaired.len() != original.len()
        || repaired
            .iter()
            .zip(&prepared)
            .enumerate()
            .any(|(at, (a, b))| !checksum[at] && a != b)
    {
        return Err(Error::VerificationFailed);
    }
    Ok(repaired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::{be32_normal_integrity, Value};

    #[derive(Clone, Copy)]
    enum Contract {
        Be32,
        DirtyOutput,
        Missing,
        OtherId,
        OtherFields,
        InvalidFields,
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
                    id: self.id,
                    original: transition.target.firmware.normal.to_vec(),
                    offset: self.offset,
                    value: transition.installed.firmware.normal[self.offset],
                    contract: self.contract,
                    extra: self.extra,
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
    fn force_records_family_waiver_but_unrelated_requested_field_cannot_change() {
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
        assert!(matches!(
            plan_with(&a, &b, Policy::Strict, registry),
            Err(Error::Incompatible)
        ));
        let plan = plan_with(&a, &b, Policy::FamilyOverride, registry).unwrap();
        assert!(plan.decisions()[1].waived);
        assert_eq!(plan.decisions()[1].comparison, Comparison::Different);
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
        let evaluated = evaluate_with(&a, &b, Policy::Strict, &[&owner]).unwrap();
        assert_eq!(evaluated.decisions()[0].comparison, Comparison::Unresolved);
        assert_eq!(
            evaluated.decisions()[0].blocked(),
            Some(Error::UnresolvedIdentity)
        );
        assert_eq!(evaluated.admit(), Err(Error::UnresolvedIdentity));
        let waived = plan_with(&a, &b, Policy::FamilyOverride, &[&owner]).unwrap();
        assert!(waived.decisions()[0].waived);
        assert_eq!(waived.decisions()[0].comparison, Comparison::Unresolved);
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
    fn native_domains_remain_separate_and_plans_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Plan<'static>>();
        let image = image();
        let a = context(&image);
        let b = Context::new(Firmware {
            hardware: "SAT 9000",
            normal: &image,
            kernel: None,
        });
        let owner = Owner::field("constant", 24);
        assert!(matches!(
            plan_with(&a, &b, Policy::Strict, &[&owner]),
            Err(Error::Incompatible)
        ));
        assert!(plan_with(&a, &b, Policy::FamilyOverride, &[&owner]).is_ok());
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
