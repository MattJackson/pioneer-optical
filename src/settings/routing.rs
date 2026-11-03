//! Original hardware remains the routing source through every firmware hop.
//! This read-only table never substitutes for family, image or live checks.

use crate::production::ProductCode;

/// A platform/product scope; unspecified product fields cover its variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductSelector<'a> {
    /// Complete platform token, compared without ASCII case distinctions.
    pub platform: &'a str,
    /// Optional exact product prefix; `None` covers recognized prefixes.
    pub prefix: Option<&'a str>,
    /// Optional exact product suffix; `None` covers product variants.
    pub suffix: Option<&'a str>,
}

impl ProductSelector<'_> {
    /// The same selector, compared like `matches` without ASCII case distinctions.
    pub(crate) fn same(&self, other: ProductSelector<'_>) -> bool {
        let same = |a: Option<&str>, b: Option<&str>| match (a, b) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            (None, None) => true,
            _ => false,
        };
        self.platform.eq_ignore_ascii_case(other.platform)
            && same(self.prefix, other.prefix)
            && same(self.suffix, other.suffix)
    }

    fn overlaps(&self, other: Self) -> bool {
        let compatible = |a: Option<&str>, b: Option<&str>| match (a, b) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            _ => true,
        };
        self.platform.eq_ignore_ascii_case(other.platform)
            && compatible(self.prefix, other.prefix)
            && compatible(self.suffix, other.suffix)
    }

    /// Syntactic match only. An adaptation must validate mechanism prerequisites.
    pub fn matches(&self, product: ProductCode<'_>) -> bool {
        product.platform_is(self.platform)
            && self
                .prefix
                .map_or(true, |v| v.eq_ignore_ascii_case(product.prefix))
            && self
                .suffix
                .map_or(true, |v| v.eq_ignore_ascii_case(product.suffix))
    }
}

/// One reviewed destination for an original platform/product cohort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule<'a> {
    /// Original factory hardware, never the currently reported firmware model.
    pub hardware: ProductSelector<'a>,
    /// Destination firmware platform/product.
    pub destination: ProductSelector<'a>,
    /// Identifier of the separate reviewed settings adaptation/restore profile.
    pub profile: &'a str,
    /// Refuse destinations without a rule for this original hardware. An
    /// additive exception can retain existing family/settings checks instead.
    pub restricted: bool,
}

/// Result of the scoped table; none of these results bypass other flash gates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision<'a> {
    /// No special-settings scope for this original hardware; retain defaults.
    Unscoped,
    /// Destination names the original hardware platform. No adaptation is
    /// selected; OEM identity, bytes and all normal flash checks still apply.
    OriginalPlatform,
    /// The original hardware has exactly one explicit destination rule.
    Profile(&'a str),
    /// Special-settings hardware has no rule for this destination: refuse.
    UnsupportedDestination,
    /// More than one rule applies: refuse rather than selecting by table order.
    Ambiguous,
}

/// A borrowed table of special-settings exceptions, not an all-drive catalogue.
#[derive(Clone, Copy, Debug)]
pub struct Table<'a> {
    rules: &'a [Rule<'a>],
}

impl<'a> Table<'a> {
    /// Construct a read-only routing view. This does not register byte patches.
    pub const fn new(rules: &'a [Rule<'a>]) -> Self {
        Self { rules }
    }

    /// Resolve a compiled original-hardware predicate without inventing a
    /// factory product or treating it as evidence read from a drive.
    pub fn resolve_scope(
        &self,
        original: ProductSelector<'_>,
        destination: ProductCode<'_>,
    ) -> Decision<'a> {
        // A single exported predicate must resolve uniformly for every product
        // it covers. Reject overlapping, unequal scopes until they can be
        // represented as disjoint predicates; never guess a representative SKU.
        if self
            .rules
            .iter()
            .any(|r| !r.hardware.same(original) && r.hardware.overlaps(original))
        {
            return Decision::Ambiguous;
        }
        let mut scoped = false;
        let mut restricted = false;
        let mut selected = None;
        for rule in self.rules {
            if !rule.hardware.same(original) {
                continue;
            }
            scoped = true;
            restricted |= rule.restricted;
            if rule.destination.matches(destination) {
                if selected.is_some() {
                    return Decision::Ambiguous;
                }
                selected = Some(rule.profile);
            }
        }
        if scoped && destination.platform_is(original.platform) {
            return Decision::OriginalPlatform;
        }
        match (scoped, selected) {
            (_, Some(profile)) => Decision::Profile(profile),
            (true, None) if restricted => Decision::UnsupportedDestination,
            _ => Decision::Unscoped,
        }
    }

    /// Resolve original A to destination X. Current firmware B is deliberately
    /// not an argument: it can never replace A as the hardware routing source.
    pub fn resolve(&self, original: ProductCode<'_>, destination: ProductCode<'_>) -> Decision<'a> {
        let mut scoped = false;
        let mut restricted = false;
        let mut selected = None;
        for rule in self.rules {
            if !rule.hardware.matches(original) {
                continue;
            }
            scoped = true;
            restricted |= rule.restricted;
            if rule.destination.matches(destination) {
                if selected.is_some() {
                    return Decision::Ambiguous;
                }
                selected = Some(rule.profile);
            }
        }
        if scoped && destination.platform_is(original.platform) {
            return Decision::OriginalPlatform;
        }
        match (scoped, selected) {
            (_, Some(profile)) => Decision::Profile(profile),
            (true, None) if restricted => Decision::UnsupportedDestination,
            (true, None) => Decision::Unscoped,
            (false, None) => Decision::Unscoped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn platform(value: &str) -> ProductSelector<'_> {
        ProductSelector {
            platform: value,
            prefix: None,
            suffix: None,
        }
    }
    const RULES: &[Rule<'_>] = &[
        Rule {
            hardware: platform("UD02"),
            destination: platform("UD04"),
            profile: "a-to-b",
            restricted: true,
        },
        Rule {
            hardware: platform("UD04"),
            destination: platform("UD03"),
            profile: "b-to-c",
            restricted: true,
        },
    ];
    fn code(value: &str) -> ProductCode<'_> {
        ProductCode::parse(value).unwrap()
    }

    #[test]
    fn firmware_b_never_grants_b_to_c_to_original_hardware_a() {
        let table = Table::new(RULES);
        let original = code("BDR-UD02TBD");
        assert_eq!(
            table.resolve(original, code("BDR-UD04")),
            Decision::Profile("a-to-b")
        );
        assert_eq!(
            table.resolve(original, code("BDR-UD03")),
            Decision::UnsupportedDestination
        );
        assert_eq!(
            table.resolve(original, code("BDR-UD02D")),
            Decision::OriginalPlatform
        );
        assert_eq!(
            table.resolve(code("BDR-UD04ABC"), code("BDR-UD03")),
            Decision::Profile("b-to-c")
        );
    }

    #[test]
    fn native_return_requires_no_settings_row_and_does_not_change_scope() {
        let rules = [RULES[0]];
        let table = Table::new(&rules);
        assert_eq!(
            table.resolve(code("BDR-UD02TBD"), code("BDR-UD02D")),
            Decision::OriginalPlatform
        );
        assert_eq!(
            table.resolve(code("BDR-UD02TBD"), code("BDR-UD03")),
            Decision::UnsupportedDestination
        );
    }

    #[test]
    fn unrelated_hardware_needs_no_table_entry() {
        assert_eq!(
            Table::new(RULES).resolve(code("BDR-209XJB"), code("BDR-S09")),
            Decision::Unscoped
        );
        assert_eq!(
            Table::new(&[]).resolve(code("BDR-UD02TBD"), code("BDR-UD04")),
            Decision::Unscoped
        );
    }

    #[test]
    fn additive_exception_retains_existing_checks_without_inheriting_other_hardware_rules() {
        let rules = [
            RULES[0],
            Rule {
                restricted: false,
                ..RULES[1]
            },
        ];
        let table = Table::new(&rules);
        assert_eq!(
            table.resolve(code("BDR-UD04ABC"), code("BDR-UD03")),
            Decision::Profile("b-to-c")
        );
        assert_eq!(
            table.resolve(code("BDR-UD04ABC"), code("BDR-209")),
            Decision::Unscoped
        );
        assert_eq!(
            table.resolve(code("BDR-UD02TBD"), code("BDR-209")),
            Decision::UnsupportedDestination
        );
        assert_eq!(
            table.resolve(code("BDR-UD02TBD"), code("BDR-UD03")),
            Decision::UnsupportedDestination
        );
    }

    #[test]
    fn suffixes_and_prefixes_are_scoped_only_when_requested() {
        let specific = Rule {
            hardware: ProductSelector {
                platform: "UD02",
                prefix: Some("BDR"),
                suffix: Some("TBD"),
            },
            destination: platform("UD04"),
            profile: "specific",
            restricted: true,
        };
        let rules = [specific];
        let table = Table::new(&rules);
        assert_eq!(
            table.resolve(code("bdr ud02tbd"), code("BDR-UD04")),
            Decision::Profile("specific")
        );
        assert_eq!(
            table.resolve(code("BDU-UD02TBD"), code("BDR-UD04")),
            Decision::Unscoped
        );
        assert_eq!(
            table.resolve(code("BDR-UD02ABC"), code("BDR-UD04")),
            Decision::Unscoped
        );
        assert_eq!(
            Table::new(RULES).resolve(code("BDU-UD02ABC"), code("BDR-UD04")),
            Decision::Profile("a-to-b")
        );
    }

    #[test]
    fn symbolic_scopes_match_live_routing_without_fabricated_factory_parameters() {
        for original in ["BDR-UD02TBD", "BDU-UD04ABC"] {
            let product = code(original);
            let scope = RULES
                .iter()
                .find(|r| r.hardware.matches(product))
                .unwrap()
                .hardware;
            for destination in ["BDR-UD02D", "BDR-UD03", "BDR-UD04", "BDR-209"] {
                assert_eq!(
                    Table::new(RULES).resolve_scope(scope, code(destination)),
                    Table::new(RULES).resolve(product, code(destination))
                );
            }
        }
    }

    #[test]
    fn symbolic_scopes_ignore_ascii_case_like_live_routing() {
        let specific = Rule {
            hardware: ProductSelector {
                prefix: Some("BDR"),
                suffix: Some("TBD"),
                ..platform("UD02")
            },
            ..RULES[0]
        };
        let lower = ProductSelector {
            platform: "ud02",
            prefix: Some("bdr"),
            suffix: Some("tbd"),
        };
        for destination in ["BDR-UD02D", "BDR-UD03", "BDR-UD04"] {
            assert_eq!(
                Table::new(RULES).resolve_scope(platform("ud02"), code(destination)),
                Table::new(RULES).resolve_scope(platform("UD02"), code(destination)),
            );
            assert_eq!(
                Table::new(&[specific]).resolve_scope(lower, code(destination)),
                Table::new(&[specific]).resolve_scope(specific.hardware, code(destination)),
            );
        }
        assert_eq!(
            Table::new(RULES).resolve_scope(platform("ud02"), code("BDR-UD04")),
            Decision::Profile("a-to-b")
        );
        // A specified field never equals an unspecified one.
        assert!(!platform("UD02").same(specific.hardware));
        assert!(!specific.hardware.same(platform("UD02")));
    }

    #[test]
    fn symbolic_scopes_reject_nonuniform_prefix_or_suffix_overlaps() {
        for specific in [
            ProductSelector {
                prefix: Some("BDR"),
                ..platform("UD02")
            },
            ProductSelector {
                suffix: Some("TBD"),
                ..platform("UD02")
            },
        ] {
            let rules = [
                RULES[0],
                Rule {
                    hardware: specific,
                    destination: platform("UD03"),
                    profile: "specific",
                    restricted: true,
                },
            ];
            for scope in [platform("UD02"), specific] {
                assert_eq!(
                    Table::new(&rules).resolve_scope(scope, code("BDR-UD04")),
                    Decision::Ambiguous
                );
            }
        }
    }

    #[test]
    fn overlapping_rules_are_not_resolved_by_row_order() {
        let rules = [
            RULES[0],
            Rule {
                profile: "different",
                ..RULES[0]
            },
        ];
        for rules in [rules, [rules[1], rules[0]]] {
            assert_eq!(
                Table::new(&rules).resolve(code("BDR-UD02TBD"), code("BDR-UD04")),
                Decision::Ambiguous
            );
        }
    }
}
