//! Original-hardware routing retained from dev 1.5. All independent native filters remain mandatory.
use super::{Contract, Contracts, Error, PreparedCorrection};
/// Reviewed original-hardware scopes and destination recipes. Catalogue
/// consumers must still prepare each firmware pair with the original hardware
/// evidence; these selectors alone do not grant a flash or an OEM return.
pub fn hardware_rules() -> Result<&'static [crate::settings::routing::Rule<'static>], Error> {
    static RULES: std::sync::OnceLock<Result<Vec<crate::settings::routing::Rule<'static>>, Error>> =
        std::sync::OnceLock::new();
    RULES
        .get_or_init(|| {
            Ok(super::registry()?
                .1
                .iter()
                .map(|r| crate::settings::routing::Rule {
                    hardware: r.hardware.borrowed(),
                    destination: r.destination.borrowed(),
                    profile: &r.profile,
                    restricted: r.restricted,
                })
                .collect())
        })
        .as_ref()
        .map(Vec::as_slice)
        .map_err(Clone::clone)
}

pub(super) fn hardware_route(
    original: &str,
    target_model: &str,
) -> Result<crate::settings::routing::Decision<'static>, Error> {
    let original =
        crate::production::ProductCode::parse(original).ok_or(Error::OriginalRequired)?;
    let rules = hardware_rules()?;
    if !rules.iter().any(|rule| rule.hardware.matches(original)) {
        return Ok(crate::settings::routing::Decision::Unscoped);
    }
    destination_route(
        target_model,
        rules
            .iter()
            .any(|r| r.restricted && r.hardware.matches(original)),
        |target| crate::settings::routing::Table::new(rules).resolve(original, target),
    )
}

// Live and symbolic preparation share destination parsing and refusal policy.
// OEM names outside the factory product grammar retain normal checks on an
// unrestricted scope, while a restricted scope still refuses them.
fn destination_route<'a>(
    target_model: &str,
    restricted: bool,
    resolve: impl FnOnce(crate::production::ProductCode<'_>) -> crate::settings::routing::Decision<'a>,
) -> Result<crate::settings::routing::Decision<'a>, Error> {
    let Some(target) = crate::production::ProductCode::parse(target_model) else {
        return if restricted {
            Err(Error::OriginalMismatch)
        } else {
            Ok(crate::settings::routing::Decision::Unscoped)
        };
    };
    match resolve(target) {
        crate::settings::routing::Decision::UnsupportedDestination => Err(Error::OriginalMismatch),
        crate::settings::routing::Decision::Ambiguous => Err(Error::Registry),
        route => Ok(route),
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HardwareGuard {
    model: String,
    normal_hash: String,
    phase_hash: Option<String>,
    profile: Option<String>,
    scope: Option<crate::settings::routing::ProductSelector<'static>>,
}

impl HardwareGuard {
    pub(crate) fn new(model: &str, normal: &[u8], profile: Option<&str>) -> Self {
        Self {
            model: model.into(),
            normal_hash: super::digest(normal),
            phase_hash: super::phase_variant(normal).map(|b| super::digest(&b)),
            profile: profile.map(Into::into),
            scope: None,
        }
    }

    pub(crate) fn with_scope(
        mut self,
        scope: Option<crate::settings::routing::ProductSelector<'static>>,
    ) -> Self {
        self.scope = scope;
        self
    }

    pub(crate) fn scope(&self) -> Option<crate::settings::routing::ProductSelector<'static>> {
        self.scope
    }

    pub(crate) fn check(&self, parameters: &[u8]) -> Result<(), Error> {
        use crate::settings::routing::Decision;
        let original = crate::production::parse(parameters).ok_or(Error::OriginalRequired)?;
        if self.scope.is_some_and(|scope| {
            !original
                .product_code_parts()
                .is_some_and(|code| scope.matches(code))
        }) {
            return Err(Error::OriginalMismatch);
        }
        let route = hardware_route(original.product_code, &self.model)?;
        match route {
            Decision::Unscoped if self.profile.is_none() => Ok(()),
            Decision::Profile(policy) => {
                if super::registry()?.0.iter().any(|p| {
                    (self.profile.as_deref() == Some(p.id.as_str())
                        || (self.profile.is_none() && p.mode == super::Mode::StockReturn))
                        && p.policy() == policy
                        && (p.output_sha256 == self.normal_hash
                            || self.phase_hash.as_deref() == Some(p.output_sha256.as_str()))
                }) {
                    Ok(())
                } else {
                    Err(Error::Guard)
                }
            }
            Decision::OriginalPlatform => {
                if super::registry()?.0.iter().any(|p| {
                    p.mode == super::Mode::StockReturn
                        && p.target_model == self.model
                        && (p.target_normal_sha256 == self.normal_hash
                            || self.phase_hash.as_deref() == Some(p.target_normal_sha256.as_str()))
                }) {
                    Ok(())
                } else {
                    Err(Error::Guard)
                }
            }
            _ => Err(Error::OriginalMismatch),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[cfg_attr(test, serde(deny_unknown_fields))]
pub(super) struct Selector {
    pub(super) platform: String,
    pub(super) prefix: Option<String>,
    pub(super) suffix: Option<String>,
}
impl Selector {
    fn borrowed(&self) -> crate::settings::routing::ProductSelector<'_> {
        crate::settings::routing::ProductSelector {
            platform: &self.platform,
            prefix: self.prefix.as_deref(),
            suffix: self.suffix.as_deref(),
        }
    }
    fn valid(&self) -> bool {
        let witness = format!(
            "{}-{}{}",
            self.prefix.as_deref().unwrap_or("BDR"),
            self.platform,
            self.suffix.as_deref().unwrap_or("")
        );
        crate::production::ProductCode::parse(&witness).is_some_and(|p| self.borrowed().matches(p))
    }
    fn overlaps(&self, other: &Self) -> bool {
        let compatible = |a: &Option<String>, b: &Option<String>| match (a, b) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            _ => true,
        };
        self.platform.eq_ignore_ascii_case(&other.platform)
            && compatible(&self.prefix, &other.prefix)
            && compatible(&self.suffix, &other.suffix)
    }
}
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[cfg_attr(test, serde(deny_unknown_fields))]
pub(super) struct HardwareRule {
    pub(super) hardware: Selector,
    pub(super) destination: Selector,
    pub(super) profile: String,
    #[cfg_attr(test, serde(default = "restricted_by_default"))]
    pub(super) restricted: bool,
}
#[cfg(test)]
fn restricted_by_default() -> bool {
    true
}

impl Contracts {
    pub(super) fn validate_rules(&self) -> Result<(), Error> {
        for (index, rule) in self.1.iter().enumerate() {
            if !rule.hardware.valid()
                || !rule.destination.valid()
                || self.1[..index].iter().any(|r: &HardwareRule| {
                    r.hardware.overlaps(&rule.hardware)
                        && (r.hardware != rule.hardware
                            || r.destination.overlaps(&rule.destination))
                })
                || !self.0.iter().any(|p| {
                    p.policy() == rule.profile
                        && crate::production::ProductCode::parse(&p.target_model)
                            .is_some_and(|model| rule.destination.borrowed().matches(model))
                })
            {
                return Err(Error::Registry);
            }
        }
        Ok(())
    }
    pub(super) fn prepare_hardware(
        &self,
        source: &Contract,
        target: &[u8],
        model: &str,
        original: &str,
    ) -> Result<Option<PreparedCorrection>, Error> {
        let route = hardware_route(original, model)?;
        self.prepare_route(source, target, model, route)
    }

    pub(super) fn prepare_scope(
        &self,
        source: &Contract,
        target: &[u8],
        model: &str,
        scope: crate::settings::routing::ProductSelector<'static>,
    ) -> Result<Option<PreparedCorrection>, Error> {
        let rules = hardware_rules()?;
        let route = destination_route(
            model,
            rules.iter().any(|r| r.restricted && r.hardware.same(scope)),
            |target| crate::settings::routing::Table::new(rules).resolve_scope(scope, target),
        )?;
        self.prepare_route(source, target, model, route)
    }

    fn prepare_route(
        &self,
        source: &Contract,
        target: &[u8],
        model: &str,
        route: crate::settings::routing::Decision<'_>,
    ) -> Result<Option<PreparedCorrection>, Error> {
        use crate::settings::routing::Decision;
        if route == Decision::Unscoped {
            return Ok(None);
        }
        let target_hash = super::digest(target);
        let variant = super::phase_variant(target);
        let variant_hash = variant.as_ref().map(|b| super::digest(b));
        let mut selected = Vec::new();
        for p in &self.0 {
            if source.hardware_family.as_deref() != Some(p.hardware_family.as_str())
                || p.target_model != model
                || p.source_calibration
                    .is_some_and(|format| source.calibration != Some(format))
                || !match route {
                    Decision::Profile(id) => p.policy() == id,
                    Decision::OriginalPlatform => p.mode == super::Mode::StockReturn,
                    _ => false,
                }
            {
                continue;
            }
            let matches = |hash: &str| p.target_normal_sha256 == hash || p.output_sha256 == hash;
            let reviewed = if matches(&target_hash) {
                Some(target)
            } else if variant_hash.as_deref().is_some_and(matches) {
                variant.as_deref()
            } else {
                None
            };
            if let Some(reviewed) = reviewed {
                selected.push((p, reviewed));
            }
        }
        match selected.as_slice() {
            [] => Err(Error::Guard),
            [(profile, reviewed)] => {
                let mut corrected = self.apply(profile, source, target, reviewed)?;
                if route == Decision::OriginalPlatform {
                    if let Some(corrected) = &mut corrected {
                        corrected.requirements.clear();
                    }
                }
                Ok(corrected)
            }
            _ => Err(Error::Registry),
        }
    }
}
pub(crate) fn prepare_hardware(
    source: &Contract,
    target: &[u8],
    model: &str,
    original: &str,
) -> Result<Option<PreparedCorrection>, Error> {
    super::registry()?.prepare_hardware(source, target, model, original)
}

pub(crate) fn prepare_scope(
    source: &Contract,
    target: &[u8],
    model: &str,
    scope: crate::settings::routing::ProductSelector<'static>,
) -> Result<Option<PreparedCorrection>, Error> {
    super::registry()?.prepare_scope(source, target, model, scope)
}
