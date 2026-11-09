use super::*;

/// Which native template set the synthetic mechanism uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Convention {
    /// XD08/UD02D-type code: ascending loader, plain conversions.
    Direct,
    /// XS08U/UD04-type code: descending loader, mirrored conversions.
    Mirrored,
}

fn emit(template: Template) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(template.len() + 1);
    for (i, byte) in template.iter().enumerate() {
        let after_call = |n: usize| i >= n && template[i - n] == Some(0x5e);
        bytes.push(match byte {
            Some(b) => *b,
            // Call-target holes name 0x410000; other holes are registers.
            None if after_call(1) => 0x41,
            None if after_call(2) || after_call(3) => 0x00,
            None => 0xc8,
        });
    }
    if bytes.len() % 2 == 1 {
        bytes.push(0);
    }
    bytes
}

fn call(target: usize) -> [u8; 4] {
    let address = u32::try_from(target + BASE_ADDRESS).unwrap().to_be_bytes();
    [0x5e, address[1], address[2], address[3]]
}

/// Install a complete synthetic mechanism bundle so that native discovery and
/// the registered identity recognize the image. `functions` are the decoded
/// offsets of the source-word-zero and source-word-one coil functions; the
/// rest of the bundle needs 320 bytes at `rest` and the step block 48 at `step`.
pub(crate) fn install(
    body: &mut [u8],
    rest: usize,
    step: usize,
    functions: [usize; 2],
    convention: Convention,
) {
    let index = usize::from(convention == Convention::Mirrored);
    // Direct code gives the negative offset to source word zero (XD08 and
    // XS08U alike); the mirrored synthetic set moves it to word one.
    let (minus, plus) = (functions[index], functions[1 - index]);
    let mut at = step;
    for (template, callee) in [(STEP_MINUS, minus), (STEP_PLUS, plus)] {
        let mut block = emit(template);
        block.extend_from_slice(&[0x01, 0x00, 0x69, 0x51]);
        block.extend_from_slice(&call(callee));
        body[at..at + block.len()].copy_from_slice(&block);
        at += block.len();
    }
    assert!(at <= step + 48);
    let loader = if index == 0 {
        LOADER_ASCENDING
    } else {
        LOADER_DESCENDING
    };
    let mut at = rest;
    let mut place = |template: Template| {
        let bytes = emit(template);
        body[at..at + bytes.len()].copy_from_slice(&bytes);
        at += bytes.len();
    };
    place(loader);
    place(BASE[index]);
    place(OFFSET[index]);
    place(STEP[index]);
    place(MODE[index]);
    place(CONTROLLER[index]);
    assert!(at <= rest + 320, "{}", at - rest);
}
