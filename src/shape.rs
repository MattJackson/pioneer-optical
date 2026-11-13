//! Native code shapes: exact instruction bytes with relocatable operand holes.

/// Whether `body` holds `shape` at `at`, ignoring relocatable operand ranges.
pub(crate) fn matches(body: &[u8], at: usize, shape: &[u8], operands: &[(usize, usize)]) -> bool {
    let Some(bytes) = at
        .checked_add(shape.len())
        .and_then(|end| body.get(at..end))
    else {
        return false;
    };
    bytes.iter().zip(shape).enumerate().all(|(i, (a, b))| {
        a == b
            || operands
                .iter()
                .any(|&(start, len)| (start..start + len).contains(&i))
    })
}
