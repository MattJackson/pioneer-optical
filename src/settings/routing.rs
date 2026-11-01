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

    /// Resolve original A to destination X. Current firmware B is deliberately
    /// not an argument: it can never replace A as the hardware routing source.
    pub fn resolve(&self, original: ProductCode<'_>, destination: ProductCode<'_>) -> Decision<'a> {
        let mut scoped = false;
        let mut selected = None;
        for rule in self.rules {
            if !rule.hardware.matches(original) {
                continue;
            }
            scoped = true;
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
            (true, None) => Decision::UnsupportedDestination,
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
        },
        Rule {
            hardware: platform("UD04"),
            destination: platform("UD03"),
            profile: "b-to-c",
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
    fn suffixes_and_prefixes_are_scoped_only_when_requested() {
        let specific = Rule {
            hardware: ProductSelector {
                platform: "UD02",
                prefix: Some("BDR"),
                suffix: Some("TBD"),
            },
            destination: platform("UD04"),
            profile: "specific",
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
