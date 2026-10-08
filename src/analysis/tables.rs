//! Structural table views. Recognition does not assign undocumented semantics.
use serde::Serialize;
use std::ops::Range;

const MIN_RECORDS: usize = 4;
const MIN_WIDTH: usize = 4;
const MAX_WIDTH: usize = 64;
const MAX_RECORDS: usize = 4096;

/// A fixed-width, zero-padded ASCII record.
#[derive(Clone, Debug, Serialize)]
pub struct Record {
    /// Original ordinal, preserved even if a client sorts the display.
    pub index: usize,
    /// Byte range relative to the containing logical region.
    pub range: Range<usize>,
    /// Printable value, excluding only terminating zero bytes.
    pub value: String,
}
/// A structurally recognized table, without guessed field meanings.
#[derive(Clone, Debug, Serialize)]
pub struct Table {
    /// Parser format identifier.
    pub format: &'static str,
    /// Table byte range relative to its logical region.
    pub range: Range<usize>,
    /// Fixed record width, including zero padding.
    pub record_width: usize,
    /// All validated records in source order.
    pub records: Vec<Record>,
}

// Recognize only an anchored leading run. Do not scan arbitrary instructions
// for strings and then label their surroundings as strategy records.
pub(super) fn inspect(bytes: &[u8]) -> Vec<Table> {
    let mut candidates = Vec::new();
    for width in MIN_WIDTH..=MAX_WIDTH {
        let mut records = Vec::new();
        for (index, record) in bytes.chunks_exact(width).take(MAX_RECORDS).enumerate() {
            let Some(end) = record.iter().position(|&b| b == 0) else {
                break;
            };
            if end < 3
                || !record[..end].iter().all(|&b| (b' '..=b'~').contains(&b))
                || !record[end..].iter().all(|&b| b == 0)
                || !record[..end].iter().any(u8::is_ascii_alphanumeric)
            {
                break;
            }
            records.push(Record {
                index,
                range: index * width..(index + 1) * width,
                value: String::from_utf8_lossy(&record[..end]).into_owned(),
            });
        }
        if records.len() >= MIN_RECORDS {
            candidates.push(Table {
                format: "ascii.fixed_width.zero_padded.v1",
                range: 0..records.len() * width,
                record_width: width,
                records,
            });
        }
    }
    if candidates.len() == 1 {
        candidates
    } else {
        Vec::new()
    }
}
