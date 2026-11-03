//! Borrowed factory product-code components; no SKU-to-hardware guesses.

/// Syntactic factory product components, not a crossflash authorization.
/// Case and variant bytes remain available; platform matching ignores ASCII case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductCode<'a> {
    /// Complete input, retained without rewriting the factory record.
    pub raw: &'a str,
    /// Canonical Pioneer product prefix, such as `BDR`, `BDC` or `BDU`.
    pub prefix: &'static str,
    /// Platform token through its first digit run, such as `UD02` or `209`.
    pub platform: &'a str,
    /// Remaining product variant, such as `TBD`, `ABC` or `MIO`.
    pub suffix: &'a str,
}

impl<'a> ProductCode<'a> {
    /// Parse known Pioneer prefix grammars without a firmware/model allowlist.
    /// OEM aliases, incomplete tokens and unsupported names remain unclassified.
    pub fn parse(raw: &'a str) -> Option<Self> {
        let text = raw.trim_matches(' ');
        if !text.is_ascii() || text.len() < 4 {
            return None;
        }
        let prefix = [
            "BDR", "BDC", "BDU", "BDE", "BDW", "BDX", "DVR", "DVD", "CDR",
        ]
        .into_iter()
        .find(|p| text[..3].eq_ignore_ascii_case(p))?;
        let rest = text[3..].trim_start_matches([' ', '-', '_']);
        let letters = rest.bytes().take_while(u8::is_ascii_alphabetic).count();
        // Held Pioneer platform tokens have at most two leading letters.
        // Do not turn arbitrary descriptive strings into hardware identities.
        if letters > 2 {
            return None;
        }
        let digits = rest[letters..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        if digits == 0 {
            return None;
        }
        let split = letters + digits;
        let suffix = &rest[split..];
        if !suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+' | b'/'))
        {
            return None;
        }
        Some(Self {
            raw,
            prefix,
            platform: &rest[..split],
            suffix,
        })
    }

    /// Compare the complete platform token, not a substring or fuzzy prefix.
    /// Matching syntax alone never proves that product variants share settings.
    pub fn platform_is(&self, platform: &str) -> bool {
        self.platform.eq_ignore_ascii_case(platform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_variants_share_a_token_without_losing_product_details() {
        for (raw, prefix, suffix) in [
            ("BDR-UD02TBD", "BDR", "TBD"),
            ("BDR UD02TBD", "BDR", "TBD"),
            ("BDU-UD02ABC", "BDU", "ABC"),
            ("  bdr_ud02tbd  ", "BDR", "tbd"),
        ] {
            let parts = ProductCode::parse(raw).unwrap();
            assert_eq!(parts.raw, raw);
            assert_eq!(parts.prefix, prefix);
            assert!(parts.platform_is("UD02"));
            assert_eq!(parts.suffix, suffix);
        }
    }

    #[test]
    fn platform_and_oem_variant_digits_remain_separate() {
        for (raw, platform, suffix) in [
            ("BDR-UD03FAL", "UD03", "FAL"),
            ("BDR-UD04", "UD04", ""),
            ("BDR-209MIO", "209", "MIO"),
            ("BDR-S12JX", "S12", "JX"),
            ("BDR-PR1EPDVPP100", "PR1", "EPDVPP100"),
            ("BDCTD01RS", "TD01", "RS"),
            ("DVR-106D", "106", "D"),
            ("BDR-UD020TBD", "UD020", "TBD"),
        ] {
            let parts = ProductCode::parse(raw).unwrap();
            assert_eq!(parts.platform, platform);
            assert_eq!(parts.suffix, suffix);
            assert_eq!(parts.platform_is("UD02"), platform == "UD02");
        }
    }

    #[test]
    fn malformed_or_foreign_names_are_not_forced_into_pioneer_platforms() {
        for raw in [
            "",
            "BDR-",
            "BDR-UD",
            "BDR-UD 02",
            "BDR-UD02 TBD",
            "BDR-UD02\0TBD",
            "BDR-UD02\n",
            "BDR-ÜD02",
            "XYZ-UD02ABC",
            "DVR-MCC",
            "BDR-ABC123",
            "BDR-ABCD1",
            "SlimtypeEB1",
            "SBC-06D2X-U",
            "BDR-UD02🚗",
        ] {
            assert_eq!(ProductCode::parse(raw), None, "{raw:?}");
        }
    }
}
