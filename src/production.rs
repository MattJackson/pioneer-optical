//! Factory production data from the read-only A0 parameters response.
//!
//! The record layout was observed identically on BDR-UD04, BDR-S11, BDR-S12
//! and BDR-XD06 hardware. Anything outside that layout parses as `None`.

/// Buffer id of the parameters read.
pub const PARAMETERS_ID: u8 = 0xA0;
/// Length of the parameters response.
pub const PARAMETERS_LEN: usize = 0x800;

/// Production record tag (`kw0` + digit) and its offset.
const TAG: usize = 0x84;
/// Original product code: 15 ASCII bytes, space padded.
const PRODUCT: usize = 0x90;
const PRODUCT_LEN: usize = 15;
/// Factory test string: 90 characters with the test date (YYMMDD) at 76.
const FACTORY: usize = 0xC0;
const FACTORY_LEN: usize = 90;
const FACTORY_DATE: usize = 76;

/// READ BUFFER of the whole parameters response.
pub fn parameters() -> [u8; 10] {
    crate::cdb::read_diagnostic(PARAMETERS_ID, 0, PARAMETERS_LEN as u32)
}

/// A calendar date recorded at the factory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Date {
    /// Four-digit year.
    pub year: u16,
    /// Month, 1..=12.
    pub month: u8,
    /// Day, 1..=31.
    pub day: u8,
}

/// Production facts stored when the drive was built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Production<'a> {
    /// The product code the hardware was built as, which survives crossflashing.
    pub product_code: &'a str,
    /// Factory test date, if the test string is present and well formed.
    pub manufactured: Option<Date>,
}

/// Decode the parameters response; `None` when the production record is absent.
pub fn parse(b: &[u8]) -> Option<Production<'_>> {
    let tag = b.get(TAG..TAG + 4)?;
    if &tag[..3] != b"kw0" || !tag[3].is_ascii_digit() {
        return None;
    }
    let code = b.get(PRODUCT..PRODUCT + PRODUCT_LEN)?;
    if !code.iter().all(|c| (0x20..0x7f).contains(c)) {
        return None;
    }
    let product_code = core::str::from_utf8(code).ok()?.trim_end();
    if product_code.is_empty() {
        return None;
    }
    Some(Production {
        product_code,
        manufactured: b.get(FACTORY..FACTORY + FACTORY_LEN).and_then(factory_date),
    })
}

fn factory_date(s: &[u8]) -> Option<Date> {
    if !s
        .iter()
        .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase() || matches!(c, b'+' | b'-'))
    {
        return None;
    }
    let two = |at: usize| {
        let d = s.get(at..at + 2)?;
        (d[0].is_ascii_digit() && d[1].is_ascii_digit()).then(|| (d[0] - b'0') * 10 + d[1] - b'0')
    };
    let (year, month, day) = (
        two(FACTORY_DATE)?,
        two(FACTORY_DATE + 2)?,
        two(FACTORY_DATE + 4)?,
    );
    ((1..=12).contains(&month) && (1..=31).contains(&day)).then_some(Date {
        year: 2000 + u16::from(year),
        month,
        day,
    })
}

/// Country of manufacture from the serial number's two-letter suffix.
pub fn origin(serial: &str) -> Option<&'static str> {
    let serial = serial.trim_end();
    match serial.get(serial.len().checked_sub(2)?..)? {
        "JP" => Some("Japan"),
        "WL" => Some("China"),
        _ => None,
    }
}

#[cfg(test)]
#[path = "production_tests.rs"]
mod tests;
