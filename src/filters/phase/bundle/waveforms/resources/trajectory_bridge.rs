//! PR1 accelerated-controller adaptation onto the UD04 native output/timer ABI.
//! OEM basic blocks retain direction/count, events, timer teardown and target
//! hardware services. The profile owns no caller object: a 36-byte stack object
//! remains live until target timer teardown clears the registered callback.
use super::{retirement, trajectory_profile};
use alloc::vec::Vec;
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, encode_insn, Ea, Operand},
    Mode, Target,
};
use sha2::{Digest, Sha256};
mod software_roles;
mod target_roles;
/// Complete native software controller/profile source roles.
pub use software_roles::SoftwareRoles;
/// Native target code/data locations bound by complete coherent graphs.
pub use target_roles::TargetRoles;
const BASE: u32 = 0x410000;
const ENTRY: u32 = 0x5398a6;
const CONTROLLER: u32 = ENTRY + 104;
const CALLBACK: u32 = CONTROLLER + 272;
const REPORT: u32 = CALLBACK + 160;
const VTABLE: u32 = REPORT + 6;
const PRIVATE: u32 = 0xa05ddd;
const SOURCE: &[(u32, u32, [u8; 32])] = &[
    (
        0x5d011e,
        0x5d0126,
        [
            42, 243, 95, 4, 206, 226, 105, 172, 178, 152, 127, 235, 187, 67, 238, 156, 143, 82,
            103, 249, 212, 84, 26, 131, 11, 44, 253, 32, 53, 136, 140, 134,
        ],
    ),
    (
        0x5d003e,
        0x5d0046,
        [
            39, 157, 22, 234, 218, 216, 114, 186, 42, 24, 238, 156, 37, 57, 45, 49, 1, 199, 133,
            207, 89, 98, 156, 247, 230, 67, 75, 49, 64, 249, 141, 126,
        ],
    ),
    (
        0x5d6bce,
        0x5d6c28,
        [
            199, 201, 221, 59, 13, 118, 90, 47, 217, 193, 106, 102, 83, 203, 163, 78, 5, 160, 223,
            60, 15, 14, 212, 200, 194, 58, 10, 84, 5, 205, 252, 161,
        ],
    ),
    (
        0x5d64bc,
        0x5d6508,
        [
            58, 232, 1, 229, 82, 207, 183, 179, 241, 77, 93, 243, 165, 104, 214, 137, 148, 236,
            187, 194, 80, 225, 50, 243, 158, 121, 149, 41, 250, 191, 124, 6,
        ],
    ),
    (
        0x5d796c,
        0x5d7b1c,
        [
            230, 96, 227, 163, 135, 58, 149, 161, 253, 20, 62, 98, 145, 116, 254, 190, 193, 196,
            138, 34, 133, 176, 255, 222, 199, 77, 197, 157, 203, 122, 216, 81,
        ],
    ),
    (
        0x6934b6,
        0x6934ca,
        [
            165, 122, 30, 220, 94, 196, 24, 117, 184, 182, 21, 217, 201, 65, 3, 174, 202, 179, 240,
            110, 240, 119, 91, 57, 249, 86, 247, 146, 193, 75, 90, 199,
        ],
    ),
    (
        0x5f0102,
        0x5f0164,
        [
            62, 42, 3, 85, 82, 7, 107, 243, 25, 120, 149, 113, 109, 197, 8, 93, 191, 164, 32, 181,
            13, 83, 32, 51, 155, 179, 64, 200, 59, 99, 58, 196,
        ],
    ),
    (
        0x5eb350,
        0x5eb3c2,
        [
            254, 222, 12, 40, 189, 74, 94, 233, 131, 133, 156, 86, 40, 57, 176, 16, 81, 250, 138,
            251, 50, 244, 187, 64, 251, 229, 248, 248, 230, 182, 9, 158,
        ],
    ),
];
const TARGET: &[(u32, u32, [u8; 32])] = &[
    (
        0x5398a6,
        0x539b2c,
        [
            43, 229, 89, 181, 13, 196, 39, 121, 88, 250, 53, 47, 34, 174, 162, 30, 235, 88, 11, 10,
            106, 232, 88, 4, 139, 241, 120, 141, 198, 112, 254, 167,
        ],
    ),
    (
        0x53956c,
        0x53962e,
        [
            178, 226, 58, 110, 97, 22, 106, 162, 52, 251, 158, 44, 139, 182, 24, 155, 194, 40, 223,
            9, 125, 219, 39, 9, 163, 146, 177, 139, 37, 104, 237, 246,
        ],
    ),
    (
        0x53966e,
        0x539766,
        [
            200, 55, 25, 84, 237, 246, 45, 56, 40, 8, 226, 223, 5, 165, 238, 159, 170, 157, 53, 23,
            246, 46, 230, 78, 14, 99, 178, 208, 36, 247, 100, 209,
        ],
    ),
    (
        0x538364,
        0x53836e,
        [
            136, 23, 99, 233, 176, 212, 237, 52, 185, 173, 92, 236, 163, 17, 204, 142, 148, 250,
            94, 61, 246, 59, 234, 95, 134, 202, 191, 156, 240, 176, 78, 206,
        ],
    ),
    (
        0x5388ba,
        0x5388c4,
        [
            136, 23, 99, 233, 176, 212, 237, 52, 185, 173, 92, 236, 163, 17, 204, 142, 148, 250,
            94, 61, 246, 59, 234, 95, 134, 202, 191, 156, 240, 176, 78, 206,
        ],
    ),
    (
        0x539406,
        0x539554,
        [
            42, 178, 245, 58, 243, 220, 175, 170, 27, 4, 47, 103, 227, 193, 29, 159, 237, 197, 21,
            202, 248, 95, 86, 74, 214, 18, 141, 33, 234, 194, 197, 7,
        ],
    ),
    (
        0x538a88,
        0x538f82,
        [
            50, 246, 231, 33, 108, 255, 141, 203, 115, 140, 93, 84, 45, 252, 218, 193, 42, 46, 166,
            93, 23, 143, 10, 74, 78, 75, 3, 77, 54, 67, 150, 160,
        ],
    ),
    (
        0x539d58,
        0x539da6,
        [
            119, 101, 89, 35, 158, 144, 173, 208, 218, 3, 232, 172, 102, 24, 204, 98, 194, 55, 138,
            37, 162, 139, 113, 205, 11, 27, 215, 80, 248, 93, 148, 74,
        ],
    ),
    (
        0x530bae,
        0x530be2,
        [
            60, 179, 52, 70, 209, 164, 28, 150, 201, 115, 9, 94, 21, 1, 245, 236, 208, 141, 102,
            163, 111, 5, 129, 90, 135, 177, 209, 42, 7, 44, 237, 217,
        ],
    ),
    (
        0x551f0e,
        0x551f18,
        [
            106, 23, 4, 89, 190, 174, 132, 91, 196, 55, 180, 159, 129, 123, 58, 87, 28, 17, 44,
            210, 247, 9, 190, 239, 102, 134, 161, 204, 228, 66, 51, 67,
        ],
    ),
    (
        0x551f60,
        0x551fb4,
        [
            210, 90, 112, 15, 105, 149, 142, 15, 230, 93, 209, 243, 138, 214, 20, 36, 211, 10, 204,
            64, 120, 96, 142, 213, 167, 245, 240, 97, 74, 84, 48, 121,
        ],
    ),
    (
        0x54bf4e,
        0x54c104,
        [
            167, 75, 246, 55, 155, 217, 206, 26, 37, 126, 134, 95, 24, 197, 78, 213, 93, 132, 45,
            87, 199, 168, 148, 159, 132, 247, 248, 6, 25, 133, 56, 215,
        ],
    ),
    (
        0x54c17c,
        0x54c1f4,
        [
            220, 20, 3, 61, 195, 161, 102, 179, 131, 34, 95, 228, 133, 29, 185, 173, 1, 107, 53,
            35, 235, 12, 132, 125, 55, 8, 166, 96, 213, 19, 38, 235,
        ],
    ),
    (
        0x54c4c4,
        0x54c504,
        [
            230, 2, 243, 240, 124, 74, 32, 181, 157, 4, 49, 220, 111, 159, 136, 92, 216, 36, 13,
            75, 144, 66, 149, 100, 7, 189, 29, 135, 171, 131, 132, 54,
        ],
    ),
    (
        0x4f52fc,
        0x4f539e,
        [
            234, 117, 36, 28, 157, 108, 62, 22, 218, 91, 168, 107, 126, 222, 239, 13, 140, 239, 10,
            181, 250, 227, 200, 163, 8, 250, 207, 27, 193, 175, 16, 150,
        ],
    ),
];
const DIRECTION: &[(u32, u32, [u8; 32])] = &[
    (
        0x538350,
        0x53836e,
        [
            176, 228, 31, 23, 109, 243, 199, 134, 208, 207, 213, 203, 69, 41, 166, 7, 95, 141, 78,
            48, 74, 227, 1, 102, 142, 191, 136, 226, 165, 102, 127, 190,
        ],
    ),
    (
        0x5388a4,
        0x5388c4,
        [
            90, 178, 85, 81, 145, 52, 83, 211, 145, 36, 144, 39, 15, 69, 63, 252, 41, 199, 200,
            202, 45, 198, 146, 38, 112, 116, 175, 57, 14, 10, 248, 94,
        ],
    ),
    (
        0x57cf34,
        0x57cf3c,
        [
            205, 193, 248, 173, 136, 193, 48, 26, 35, 32, 75, 251, 19, 11, 75, 22, 118, 61, 102,
            97, 167, 129, 178, 237, 156, 184, 63, 174, 57, 100, 101, 107,
        ],
    ),
];
const RETAINED: &[(u32, u32, [u8; 32])] = &[
    (
        0x538a88,
        0x538b0c,
        [
            30, 157, 109, 154, 144, 110, 48, 251, 89, 181, 83, 98, 221, 104, 63, 62, 177, 4, 247,
            255, 177, 86, 240, 108, 132, 132, 35, 198, 97, 22, 2, 49,
        ],
    ),
    (
        0x538b24,
        0x538b34,
        [
            62, 185, 62, 24, 212, 172, 167, 8, 127, 48, 158, 77, 174, 202, 98, 152, 161, 49, 26,
            105, 170, 156, 116, 126, 212, 169, 3, 224, 205, 76, 226, 92,
        ],
    ),
    (
        0x538b74,
        0x538b7a,
        [
            188, 19, 17, 114, 211, 152, 224, 204, 18, 130, 147, 108, 24, 67, 166, 80, 170, 41, 236,
            30, 151, 194, 64, 39, 72, 120, 158, 0, 229, 40, 40, 179,
        ],
    ),
    (
        0x538c7a,
        0x538ca2,
        [
            208, 18, 46, 53, 167, 99, 70, 63, 175, 10, 107, 202, 228, 90, 10, 77, 250, 154, 172,
            69, 119, 90, 172, 39, 67, 220, 1, 25, 155, 92, 125, 88,
        ],
    ),
    (
        0x538f56,
        0x538f82,
        [
            59, 106, 251, 70, 33, 83, 47, 20, 34, 211, 234, 33, 179, 46, 216, 173, 242, 2, 92, 24,
            82, 234, 125, 237, 21, 218, 247, 35, 222, 187, 63, 103,
        ],
    ),
    (
        0x539d58,
        0x539da6,
        [
            119, 101, 89, 35, 158, 144, 173, 208, 218, 3, 232, 172, 102, 24, 204, 98, 194, 55, 138,
            37, 162, 139, 113, 205, 11, 27, 215, 80, 248, 93, 148, 74,
        ],
    ),
    (
        0x530bae,
        0x530be2,
        [
            60, 179, 52, 70, 209, 164, 28, 150, 201, 115, 9, 94, 21, 1, 245, 236, 208, 141, 102,
            163, 111, 5, 129, 90, 135, 177, 209, 42, 7, 44, 237, 217,
        ],
    ),
    (
        0x551f0e,
        0x551f18,
        [
            106, 23, 4, 89, 190, 174, 132, 91, 196, 55, 180, 159, 129, 123, 58, 87, 28, 17, 44,
            210, 247, 9, 190, 239, 102, 134, 161, 204, 228, 66, 51, 67,
        ],
    ),
    (
        0x551f60,
        0x551fb4,
        [
            210, 90, 112, 15, 105, 149, 142, 15, 230, 93, 209, 243, 138, 214, 20, 36, 211, 10, 204,
            64, 120, 96, 142, 213, 167, 245, 240, 97, 74, 84, 48, 121,
        ],
    ),
    (
        0x54bf4e,
        0x54c104,
        [
            167, 75, 246, 55, 155, 217, 206, 26, 37, 126, 134, 95, 24, 197, 78, 213, 93, 132, 45,
            87, 199, 168, 148, 159, 132, 247, 248, 6, 25, 133, 56, 215,
        ],
    ),
    (
        0x54c17c,
        0x54c1f4,
        [
            220, 20, 3, 61, 195, 161, 102, 179, 131, 34, 95, 228, 133, 29, 185, 173, 1, 107, 53,
            35, 235, 12, 132, 125, 55, 8, 166, 96, 213, 19, 38, 235,
        ],
    ),
    (
        0x54c4c4,
        0x54c504,
        [
            230, 2, 243, 240, 124, 74, 32, 181, 157, 4, 49, 220, 111, 159, 136, 92, 216, 36, 13,
            75, 144, 66, 149, 100, 7, 189, 29, 135, 171, 131, 132, 54,
        ],
    ),
    (
        0x4f52fc,
        0x4f539e,
        [
            234, 117, 36, 28, 157, 108, 62, 22, 218, 91, 168, 107, 126, 222, 239, 13, 140, 239, 10,
            181, 250, 227, 200, 163, 8, 250, 207, 27, 193, 175, 16, 150,
        ],
    ),
    (
        0x53956c,
        0x53957e,
        [
            112, 237, 109, 60, 246, 217, 213, 86, 159, 90, 68, 32, 89, 88, 173, 36, 179, 181, 204,
            118, 5, 180, 38, 131, 38, 68, 14, 222, 244, 160, 1, 20,
        ],
    ),
    (
        0x5395e8,
        0x53962e,
        [
            97, 26, 72, 8, 254, 134, 207, 95, 105, 192, 250, 162, 51, 18, 147, 12, 244, 213, 200,
            47, 200, 68, 191, 202, 255, 180, 25, 217, 127, 204, 5, 213,
        ],
    ),
    (
        0x531a86,
        0x531a8e,
        [
            11, 56, 91, 232, 47, 232, 114, 113, 185, 8, 44, 37, 100, 239, 222, 254, 10, 60, 71,
            178, 253, 221, 48, 219, 182, 128, 36, 72, 244, 125, 118, 165,
        ],
    ),
    (
        0x531bf6,
        0x531bfe,
        [
            141, 199, 255, 84, 112, 81, 180, 165, 34, 96, 142, 206, 161, 80, 1, 37, 110, 239, 69,
            107, 20, 20, 25, 129, 16, 208, 115, 245, 142, 77, 111, 185,
        ],
    ),
    (
        0x539550,
        0x539554,
        [
            182, 25, 64, 208, 60, 117, 237, 212, 116, 207, 11, 146, 144, 40, 143, 127, 147, 176,
            26, 204, 214, 5, 106, 64, 133, 106, 126, 209, 149, 13, 8, 245,
        ],
    ),
];
/// All writes are staged; the caller owns the two supplied profile slots and
/// commits this plan atomically with its software-table/encoder composition.
#[derive(Clone, Debug)]
pub struct Plan {
    /// Complete disjoint writes, including the profile plan.
    pub writes: Vec<(Range<usize>, Vec<u8>)>,
    /// Relocated source controller CPU entry.
    pub controller: u32,
    /// Relocated source timer callback CPU entry.
    pub callback: u32,
    /// Profile entries and preparation used by the stack wrapper.
    pub profile: trajectory_profile::Plan,
}
fn span(a: u32, z: u32) -> Range<usize> {
    (a - BASE) as usize..(z - BASE) as usize
}
fn bytes(n: &[u8], a: u32, z: u32) -> Option<&[u8]> {
    n.get(span(a, z))
}
fn bind(n: &[u8], proofs: &[(u32, u32, [u8; 32])]) -> Option<()> {
    let regions = crate::image::regions(n)?;
    for &(a, z, digest) in proofs {
        let r = span(a, z);
        if !regions.stored.iter().any(|b| {
            let at = b.as_ptr() as usize - n.as_ptr() as usize;
            at <= r.start && r.end <= at + b.len()
        }) || Sha256::digest(n.get(r)?).as_slice() != digest
        {
            return None;
        }
    }
    Some(())
}
/// Bind relocated source controller/profile nodes as one coherent native graph.
/// The returned canonical view is read only: its role-address copies are never
/// written to the target image or offered as allocatable storage.
fn canonical_source(source: &[u8]) -> Option<Vec<u8>> {
    SoftwareRoles::discover(source)?.canonical_view(source)
}

fn overlap(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}
// Every emitted instruction passes the same H8 decoder/encoder, including
// operand-adjusted OEM stack blocks. No byte-level replacement opcode is used.
fn emit(out: &mut Vec<u8>, native: &[u8], mapping: &[(u32, u32)]) -> Option<()> {
    let mut at = 0;
    while at < native.len() {
        let d = decode_insn(&native[at..], Target::H8S2000, Mode::Advanced).ok()?;
        if encode_insn(d.insn, Target::H8S2000, Mode::Advanced).ok()? != native[at..at + d.len] {
            return None;
        }
        let mut insn = d.insn;
        for op in &mut insn.operands {
            let old = match *op {
                Operand::Address(Ea::Absolute { value, .. }) | Operand::Immediate { value, .. } => {
                    value
                }
                _ => continue,
            };
            if let Some(&(_, value)) = mapping.iter().find(|(a, _)| *a == old) {
                *op = match *op {
                    Operand::Address(Ea::Absolute { bits, .. }) => {
                        Operand::Address(Ea::Absolute { bits, value })
                    }
                    Operand::Immediate { bits, .. } => Operand::Immediate { bits, value },
                    _ => return None,
                };
            }
        }
        let b = encode_insn(insn, Target::H8S2000, Mode::Advanced).ok()?;
        if b.len() != d.len {
            return None;
        }
        out.extend(b);
        at += d.len;
    }
    Some(())
}
fn call(out: &mut Vec<u8>, to: u32) -> Option<()> {
    emit(out, &[0x5e, 0, 0, 0], &[(0, to)])
}
fn nops(out: &mut Vec<u8>, len: usize) -> Option<()> {
    for _ in 0..len / 2 {
        emit(out, &[0, 0], &[])?;
    }
    Some(())
}
fn copied(n: &[u8], a: u32, z: u32, mapping: &[(u32, u32)]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    emit(&mut out, bytes(n, a, z)?, mapping)?;
    Some(out)
}
/// Positively bind the sole mode-zero router callers, complete wrappers and
/// old controller. No outside Normal/Kernel edge may bypass their mode store.
fn entries_clear(n: &[u8], k: &[u8]) -> Option<()> {
    let graph = [
        span(0x538350, 0x53836e),
        span(0x5388a4, 0x5388c4),
        span(0x53956c, 0x53957e),
        span(0x5395e8, 0x539620),
        span(0x539620, 0x53962e),
        span(ENTRY, 0x539b2c),
        span(0x53966e, 0x539766),
    ];
    let mut retired = graph.to_vec();
    // Caller preparation begins at a legitimate existing native entry; every
    // following byte must be reached through the explicit SUB.B R1L,R1L.
    retired[0].start += 1;
    retired[1].start += 1;
    retirement::references_clear(
        n,
        k,
        &retired,
        &graph,
        &[
            graph[0].clone(),
            graph[1].clone(),
            graph[2].clone(),
            graph[3].clone(),
            graph[4].clone(),
            graph[5].clone(),
            span(0x53966e, 0x5396a8),
            span(0x5396a8, 0x539766),
        ],
    )
}
/// The old DSP state is reused only after every visible reference is positively
/// accounted for. Base-pointer immediates are included as well as byte accesses;
/// stored and expanded Normal and the associated Kernel are scanned.
fn private_clear(n: &[u8], k: &[u8]) -> Option<()> {
    let allowed = [
        span(ENTRY, 0x539b2c),
        span(0x53957e, 0x53959e),
        span(0x5395d6, 0x5395e2),
        span(0x53966e, 0x539766),
    ];
    private_refs_clear(n, k, &allowed)
}
fn private_refs_clear(n: &[u8], k: &[u8], allowed: &[Range<usize>]) -> Option<()> {
    for (image, is_normal) in [(n, true), (k, false)] {
        let regions = crate::image::regions(image)?;
        for (b, offset) in regions
            .stored
            .iter()
            .map(|b| (*b, Some(b.as_ptr() as usize - image.as_ptr() as usize)))
            .chain(regions.expanded.iter().map(|b| (b.as_slice(), None)))
        {
            for at in 0..b.len().saturating_sub(3) {
                let value = u32::from_be_bytes(b[at..at + 4].try_into().ok()?);
                if (PRIVATE - 1..PRIVATE + 3).contains(&value)
                    && !(is_normal
                        && offset.is_some_and(|o| {
                            allowed
                                .iter()
                                .any(|r| r.start <= o + at && o + at + 4 <= r.end)
                        }))
                {
                    return None;
                }
            }
        }
    }
    Some(())
}
/// Build an exact UD04/PR1 adapter. The caller must independently own `code` and
/// `data`; zero/erased contents do not establish allocation. Existing target
/// timer calibration, peripheral hooks and level-four diagnostic gating remain
/// native. Source diagnostic format/arguments are retained for both masks.
/// Target default speed index is converted through its native row-frequency
/// coordinate before the source selector; source and target indices are never
/// copied between domains. No persistent writes are emitted.
pub fn plan(
    target: &[u8],
    source: &[u8],
    kernel: &[u8],
    code: Range<usize>,
    data: Range<usize>,
) -> Option<Plan> {
    let canonical = canonical_source(source)?;
    let source = canonical.as_slice();
    validate(target, source, kernel)?;
    for &(a, z, _) in TARGET {
        if overlap(&code, &span(a, z)) || overlap(&data, &span(a, z)) {
            return None;
        }
    }
    let profile = trajectory_profile::plan(target, source, code, data, PRIVATE, services())?;
    assemble(target, source, profile)
}
fn validate(target: &[u8], source: &[u8], kernel: &[u8]) -> Option<()> {
    bind(target, TARGET)?;
    bind(target, DIRECTION)?;
    bind(target, RETAINED)?;
    bind(source, SOURCE)?;
    if kernel.len() != crate::image::KERNEL_LEN {
        return None;
    }
    // Kernel code is retained verbatim; no transplanted source call is rebound
    // to a new resident service. Its relevant obligations are the native
    // reference, default-index and private-RAM closures below, not package
    // identity. The outer immutable operation pins the exact supplied Kernel.
    trajectory_profile::validate_default(target, kernel)?;
    entries_clear(target, kernel)?;
    private_clear(target, kernel)?;
    Some(())
}
/// Target-native hardware and diagnostic adapters for profile planners.
pub const fn services() -> trajectory_profile::Services {
    trajectory_profile::Services {
        report: [REPORT, REPORT],
        state_getter: 0x538f56,
        hardware_mode: 0x538f7e,
    }
}
/// Three private volatile bytes proved owned by this controller composition.
pub const fn private_ram() -> u32 {
    PRIVATE
}
/// Conditional profile slots inside this plan's retired helper bodies and
/// unused controller tail. They become owned only when `plan_with_profile`
/// validates the complete source/target graph and commits the same composition.
pub fn auxiliary_slots() -> [Range<usize>; 2] {
    [span(0x53966e, 0x539766), span(VTABLE + 20, 0x539b2c)]
}
/// Combine a profile stage with the complete outer controller. `profile` must
/// come from the profile module's native planner with `services()` and
/// `private_ram()`. Its external allocations require the caller's ownership
/// proof. Writes within `auxiliary_slots()` are coalesced atomically with this
/// plan's retirement fill; writes into the live controller prefix are refused.
pub fn plan_with_profile(
    target: &[u8],
    source: &[u8],
    kernel: &[u8],
    profile: trajectory_profile::Plan,
) -> Option<Plan> {
    let canonical = canonical_source(source)?;
    let source = canonical.as_slice();
    validate(target, source, kernel)?;
    assemble(target, source, profile)
}
fn assemble(target: &[u8], source: &[u8], profile: trajectory_profile::Plan) -> Option<Plan> {
    let entry = |old| {
        profile
            .entries
            .iter()
            .find(|(a, _)| *a == old)
            .map(|(_, b)| *b)
    };
    let mut mapping = profile.entries.clone();
    mapping.extend([
        (0x5d6d62, 0x538c7a),
        (0x5d6c72, 0x538b74),
        (0x5d6c40, 0x538b24),
        (0x5d6c48, 0x538b2c),
        (0x5d6bce, 0x538a88),
        (0x5d7d6c, 0x539d58),
        (0x5d7d7e, 0x539d6a),
        (0x5d7d8a, 0x539d76),
        (0x5d7da0, 0x539d8c),
        (0x5d7dac, 0x539d98),
        (0x5cedae, 0x530bae),
        (0x5f0c26, 0x551f0e),
        (0x5f0cb6, 0x551f60),
        (0x5f0ce0, 0x551f8a),
    ]);
    let mut replacement = Vec::new();
    // Save caller registers and allocate an aligned local complete35-byte object.
    emit(
        &mut replacement,
        bytes(source, 0x5d7a0c, 0x5d7a18)?,
        &[(16, 36)],
    )?;
    // OEM MOV.L ER1,ER4.
    emit(&mut replacement, &[0x0f, 0x94], &[])?;
    // Source init's exact unsigned count normalization and zero branch, moved
    // before object construction. 0xffff rounds to zero; skipping the controller
    // prevents its zero-count initializer from exposing an uninitialized table.
    // Native caller wrappers still execute their existing completion/status path.
    emit(&mut replacement, bytes(source, 0x5d5aae, 0x5d5ab0)?, &[])?;
    let guard_at = replacement.len();
    emit(&mut replacement, bytes(source, 0x5d5b3e, 0x5d5b4c)?, &[])?;
    call(&mut replacement, profile.prepare)?;
    emit(&mut replacement, &[0x0f, 0xf0, 0x0f, 0x85], &[])?;
    emit(
        &mut replacement,
        &[0x7a, 1, 0, 0, 0, 0, 1, 0, 0x69, 0x81, 0x0b, 0x90],
        &[(0, VTABLE)],
    )?;
    call(&mut replacement, entry(0x5d5fe6)?)?;
    emit(
        &mut replacement,
        &[
            0xf0, 1, 0x6a, 0xa0, 0, 0xa0, 0x5d, 0xdc, 0x0f, 0xc1, 0x0f, 0xd0,
        ],
        &[],
    )?;
    call(&mut replacement, CONTROLLER)?;
    emit(
        &mut replacement,
        &[0x18, 0, 0x6a, 0xa0, 0, 0xa0, 0x5d, 0xdc],
        &[],
    )?;
    let epilogue = replacement.len();
    // Re-encode only the native BEQ displacement; its condition/register flow
    // and the short branch skipping INC remain the original source block.
    let branch = guard_at + 10;
    let d = decode_insn(&replacement[branch..], Target::H8S2000, Mode::Advanced).ok()?;
    let mut i = d.insn;
    let Operand::Address(Ea::PcRelative { bits, .. }) = i.operands[0] else {
        return None;
    };
    i.operands[0] = Operand::Address(Ea::PcRelative {
        bits,
        value: (epilogue - branch - d.len) as i32,
    });
    let encoded = encode_insn(i, Target::H8S2000, Mode::Advanced).ok()?;
    replacement[branch..branch + d.len].copy_from_slice(&encoded);
    emit(
        &mut replacement,
        bytes(source, 0x5d7b0e, 0x5d7b1c)?,
        &[(16, 36)],
    )?;
    if replacement.len() > 104 {
        return None;
    }
    let pad = 104 - replacement.len();
    nops(&mut replacement, pad)?;
    let mut controller = copied(source, 0x5d7a0c, 0x5d7b1c, &mapping)?;
    // These two complete source blocks are native mode-nine peripheral hooks.
    // Keep target hardware-specific mode-nine implementations and their ABI.
    for (old, to) in [(0x5d7aa4, 0x4f52fc), (0x5d7afe, 0x4f5366)] {
        let mut block = Vec::new();
        emit(&mut block, &[0xf8, 9], &[])?;
        call(&mut block, to)?;
        nops(&mut block, 4)?;
        controller[(old - 0x5d7a0c) as usize..(old - 0x5d7a0c) as usize + 10]
            .copy_from_slice(&block);
    }
    replacement.extend(controller);
    replacement.extend(copied(source, 0x5d796c, 0x5d7a0c, &mapping)?);
    // Tail-jump preserves the original variadic stack frame for both source masks.
    emit(&mut replacement, &[0xf8, 4, 0x5a, 0x54, 0xc4, 0xc4], &[])?;
    let mut vtable = bytes(source, 0x6934b6, 0x6934ca)?.to_vec();
    if vtable[..16].iter().any(|b| *b != 0) || vtable[16..] != 0x5d796cu32.to_be_bytes() {
        return None;
    }
    vtable[16..].copy_from_slice(&CALLBACK.to_be_bytes());
    replacement.extend(vtable);
    let pad = (0x539b2c - ENTRY) as usize - replacement.len();
    nops(&mut replacement, pad)?;
    let mut stop = bytes(target, 0x53957e, 0x53959e)?.to_vec();
    let mut empty = Vec::new();
    nops(&mut empty, 10)?;
    stop[8..18].copy_from_slice(&empty);
    let mut dead = Vec::new();
    nops(&mut dead, (0x539766 - 0x53966e) as usize)?;
    let mut initializers = Vec::new();
    nops(&mut initializers, 12)?;
    let mut writes = Vec::new();
    let [helpers, tail] = auxiliary_slots();
    for (i, (r, b)) in profile.writes.iter().enumerate() {
        if r.len() != b.len()
            || profile.writes[..i]
                .iter()
                .any(|(other, _)| overlap(r, other))
        {
            return None;
        }
        if helpers.start <= r.start && r.end <= helpers.end {
            dead[r.start - helpers.start..r.end - helpers.start].copy_from_slice(b);
        } else if tail.start <= r.start && r.end <= tail.end {
            replacement[r.start - (ENTRY - BASE) as usize..r.end - (ENTRY - BASE) as usize]
                .copy_from_slice(b);
        } else {
            if [
                helpers.clone(),
                span(ENTRY, 0x539b2c),
                span(0x53957e, 0x53959e),
                span(0x5395d6, 0x5395e2),
            ]
            .iter()
            .any(|own| overlap(r, own))
            {
                return None;
            }
            writes.push((r.clone(), b.clone()));
        }
    }
    writes.extend([
        (span(ENTRY, 0x539b2c), replacement),
        (span(0x53957e, 0x53959e), stop),
        (span(0x53966e, 0x539766), dead),
        (span(0x5395d6, 0x5395e2), initializers),
    ]);
    Some(Plan {
        writes,
        controller: CONTROLLER,
        callback: CALLBACK,
        profile,
    })
}

/// Positively recognized software trajectory, independent of a donor image,
/// old DSP loader signature, marker, or saved patch plan.
#[derive(Clone, Debug)]
pub struct Observed {
    entry: u32,
    profile: trajectory_profile::ObservedShared,
    code: Vec<Range<usize>>,
    protected: Vec<Range<usize>>,
    fingerprint: [u8; 32],
}
impl Observed {
    /// Recognized source profile and native target special-mode placements.
    pub fn profile(&self) -> &trajectory_profile::ObservedShared {
        &self.profile
    }
    /// Complete positively decoded native code bodies, excluding scalar data.
    pub fn code_ranges(&self) -> &[Range<usize>] {
        &self.code
    }
    /// Complete code/data/client authority whose bytes define this observation.
    pub fn protected(&self) -> &[Range<usize>] {
        &self.protected
    }
    /// Controller entry accepts native E1 count and canonical R1H direction;
    /// source count normalization and target status completion are explicit.
    pub const fn entry(&self) -> u32 {
        self.entry
    }
    /// Re-recognize complete bytes and inbound references, without interpreting
    /// firmware or assuming disjoint writes cannot introduce a new caller.
    pub fn verify(&self, normal: &[u8], kernel: &[u8]) -> bool {
        observe(normal, kernel)
            .is_some_and(|b| b.fingerprint == self.fingerprint && b.protected == self.protected)
    }
}
fn observed_call(n: &[u8], at: u32) -> Option<u32> {
    let b = bytes(n, at, at + 4)?;
    let d = decode_insn(b, Target::H8S2000, Mode::Advanced).ok()?;
    if d.len != 4
        || d.insn.mnemonic != "JSR"
        || encode_insn(d.insn, Target::H8S2000, Mode::Advanced).ok()? != b
    {
        return None;
    }
    let Operand::Address(Ea::Absolute { value, bits: 24 }) = d.insn.operands[0] else {
        return None;
    };
    Some(value)
}
/// Recognize the complete emitted UD04/PR1 software graph and retained native
/// target timer, output, event, position-counter and diagnostic contracts.
/// One signed output delta advances both the64-phase row and native word
/// position by the same amount; no new command-coordinate scaling is inferred.
/// The old DSP loader is neither required nor used as an equivalence proxy.
pub fn observe(normal: &[u8], kernel: &[u8]) -> Option<Observed> {
    observe_detailed(normal, kernel).ok()
}
/// Exact positive-proof stage that refused an emitted graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservationFailure {
    /// Static stage label; absence is not interpreted as hardware incompatibility.
    pub stage: &'static str,
}
/// Diagnostic form of `observe`, with identical acceptance conditions.
pub fn observe_detailed(normal: &[u8], kernel: &[u8]) -> Result<Observed, ObservationFailure> {
    let mut stage = "retained-services";
    observe_inner(normal, kernel, &mut stage)
        .or_else(|| {
            stage = "retained-role-discovery";
            let roles = TargetRoles::locate_emitted(normal)?;
            observe_inner_with_roles(normal, kernel, &mut stage, &roles)
        })
        .ok_or(ObservationFailure { stage })
}
fn observe_inner(normal: &[u8], kernel: &[u8], stage: &mut &'static str) -> Option<Observed> {
    let service_witness = observe_services(normal)?;
    *stage = "native-input-preparation";
    bind(normal, DIRECTION)?;
    *stage = "resident-component";
    if kernel.len() != crate::image::KERNEL_LEN {
        return None;
    }
    *stage = "profile-entries";
    let roots = trajectory_profile::SharedEntries {
        init: observed_call(normal, CONTROLLER + (0x5d7a6a - 0x5d7a0c))?,
        update: observed_call(normal, CALLBACK + (0x5d79f8 - 0x5d796c))?,
        ctor: observed_call(normal, ENTRY + 50)?,
        prepare: observed_call(normal, ENTRY + 30)?,
    };
    *stage = "profile";
    let profile = trajectory_profile::observe_shared(normal, kernel, roots, services(), PRIVATE)?;
    *stage = "private-ram";
    let mut private_owners = profile.placements.code.to_vec();
    private_owners.extend([
        span(ENTRY, VTABLE),
        span(0x537e26, 0x537e30),
        span(0x53957e, 0x53959e),
    ]);
    private_refs_clear(normal, kernel, &private_owners)?;
    *stage = "stack-wrapper";
    let mut expected = Vec::new();
    // Complete OEM register/stack wrapper, including the lifted source unsigned
    // normalization block. Only prepare/ctor entries are relocated here.
    emit(
        &mut expected,
        &[
            0x01, 0, 0x6d, 0xf3, 0x01, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0, 0x24, 0x0f, 0x94, 0x0d,
            0x9a, 0x0d, 0xa1, 0x73, 0x09, 0x47, 0x02, 0x0b, 0x5a, 0x0d, 0xaa, 0x58, 0x70, 0, 0x30,
        ],
        &[],
    )?;
    call(&mut expected, roots.prepare)?;
    emit(
        &mut expected,
        &[
            0x0f, 0xf0, 0x0f, 0x85, 0x7a, 1, 0, 0, 0, 0, 1, 0, 0x69, 0x81, 0x0b, 0x90,
        ],
        &[(0, VTABLE)],
    )?;
    call(&mut expected, roots.ctor)?;
    emit(
        &mut expected,
        &[
            0xf0, 1, 0x6a, 0xa0, 0, 0xa0, 0x5d, 0xdc, 0x0f, 0xc1, 0x0f, 0xd0,
        ],
        &[],
    )?;
    call(&mut expected, CONTROLLER)?;
    emit(
        &mut expected,
        &[
            0x18, 0, 0x6a, 0xa0, 0, 0xa0, 0x5d, 0xdc, 0x79, 0x17, 0, 0x24, 1, 0x20, 0x6d, 0x76, 1,
            0, 0x6d, 0x73, 0x54, 0x70,
        ],
        &[],
    )?;
    nops(&mut expected, 12)?;
    if bytes(normal, ENTRY, CONTROLLER)? != expected {
        return None;
    }
    *stage = "controller-callback";
    let mut reverse = alloc::vec![
        (roots.init, 0x5d5aa6),
        (roots.update, 0x5d5d60),
        (BASE + profile.placements.code[3].start as u32, 0x5d6018),
        (0x538c7a, 0x5d6d62),
        (0x538b74, 0x5d6c72),
        (0x538b24, 0x5d6c40),
        (0x538b2c, 0x5d6c48),
        (0x538a88, 0x5d6bce),
        (0x539d58, 0x5d7d6c),
        (0x539d6a, 0x5d7d7e),
        (0x539d76, 0x5d7d8a),
        (0x539d8c, 0x5d7da0),
        (0x539d98, 0x5d7dac),
        (0x530bae, 0x5cedae),
        (0x551f0e, 0x5f0c26),
        (0x551f60, 0x5f0cb6),
        (0x551f8a, 0x5f0ce0),
    ];
    reverse.sort_unstable();
    if reverse.windows(2).any(|w| w[0].0 == w[1].0) {
        return None;
    }
    let mut controller = copied(normal, CONTROLLER, CONTROLLER + 272, &reverse)?;
    for (old, target, source) in [
        (0x5d7aa4, 0x4f52fc, 0x5b8cc8),
        (0x5d7afe, 0x4f5366, 0x5b8df6),
    ] {
        let off = (old - 0x5d7a0c) as usize;
        let mut hook = Vec::new();
        emit(&mut hook, &[0xf8, 9], &[])?;
        call(&mut hook, target)?;
        nops(&mut hook, 4)?;
        if controller.get(off..off + 10)? != hook {
            return None;
        }
        let mut original = Vec::new();
        call(&mut original, 0x5b8a5e)?;
        emit(&mut original, &[0xf9, 9], &[])?;
        call(&mut original, source)?;
        controller[off..off + 10].copy_from_slice(&original);
    }
    let mut canonical = copied(normal, CALLBACK, CALLBACK + 160, &reverse)?;
    canonical.extend(controller);
    let (_, _, digest) = SOURCE
        .iter()
        .find(|(a, z, _)| *a == 0x5d796c && *z == 0x5d7b1c)?;
    if Sha256::digest(&canonical).as_slice() != digest {
        return None;
    }
    *stage = "vtable-reporter";
    if bytes(normal, REPORT, VTABLE)? != [0xf8, 4, 0x5a, 0x54, 0xc4, 0xc4] {
        return None;
    }
    let vtable = bytes(normal, VTABLE, VTABLE + 20)?;
    if vtable[..16].iter().any(|b| *b != 0) || vtable[16..] != CALLBACK.to_be_bytes() {
        return None;
    }
    *stage = "stop";
    let mut stop = alloc::vec![0x6a, 0x28, 0, 0xa0, 0x5d, 0xdc, 0x47, 0x14];
    nops(&mut stop, 10)?;
    emit(
        &mut stop,
        &[
            0xf8, 1, 0x6a, 0xa8, 0, 0xa0, 0x5d, 0xdd, 0x40, 2, 0x55, 0xb4, 0x54, 0x70,
        ],
        &[],
    )?;
    if bytes(normal, 0x53957e, 0x53959e)? != stop
        || bytes(normal, 0x5395d6, 0x5395e2)?.iter().any(|b| *b != 0)
    {
        return None;
    }
    *stage = "inbound-closure";
    let mut retired = profile.placements.code.to_vec();
    retired.extend(profile.placements.data.iter().cloned());
    retired.push(span(ENTRY, VTABLE + 20));
    // Close the wrapper's mode/direction specialization and the legacy guard:
    // unknown calls cannot bypass the native preparation/zero-count boundary.
    retired.extend([
        span(0x53956c, 0x53957e),
        span(0x5395e8, 0x539620),
        span(0x539620, 0x53962e),
        span(0x538351, 0x53836e),
        span(0x5388a5, 0x5388c4),
        span(0x539406, 0x539407),
    ]);
    let mut replaced = retired.clone();
    replaced.extend(profile.ranges.iter().cloned());
    replaced.extend([span(0x538350, 0x53836e), span(0x5388a4, 0x5388c4)]);
    replaced.extend([
        span(ENTRY, 0x539b2c),
        span(0x5392d2, 0x539406),
        span(0x539406, 0x539550),
    ]);
    let mut bodies = profile.placements.code.to_vec();
    bodies.extend([
        span(ENTRY, CONTROLLER),
        span(CONTROLLER, CALLBACK),
        span(CALLBACK, REPORT),
        span(REPORT, VTABLE),
        span(0x5392d2, 0x539406),
        span(0x539406, 0x539550),
    ]);
    // A materialized software graph must establish exclusive scalar ownership;
    // passing the generic reference scan alone does not establish that claim.
    let dispatch = super::dispatch_bridge::observe(normal).ok()?;
    let authority = match dispatch.kind {
        super::dispatch_bridge::Kind::Software => {
            super::profile_ownership::prove_with_software_tables(
                normal,
                kernel,
                &retired,
                &replaced,
                &bodies,
                &profile.data_authority,
            )
        }
        super::dispatch_bridge::Kind::Literal => {
            super::profile_ownership::prove(normal, kernel, &retired, &replaced, &bodies)
        }
        super::dispatch_bridge::Kind::Pointer => None,
    }?;
    let mut protected = profile.ranges.clone();
    protected.extend(profile.invariants.iter().cloned());
    protected.extend(authority);
    protected.extend(service_witness);
    protected.extend(
        RETAINED
            .iter()
            .chain(DIRECTION)
            .map(|(a, z, _)| span(*a, *z)),
    );
    protected.extend([
        span(ENTRY, VTABLE + 20),
        span(0x53957e, 0x53959e),
        span(0x5395d6, 0x5395e2),
    ]);
    protected.sort_unstable_by_key(|r| (r.start, r.end));
    protected.dedup();
    let mut fingerprint = Sha256::new();
    for r in &protected {
        fingerprint.update((r.start as u32).to_be_bytes());
        fingerprint.update((r.end as u32).to_be_bytes());
        fingerprint.update(normal.get(r.clone())?);
    }
    Some(Observed {
        entry: ENTRY,
        profile,
        code: bodies,
        protected,
        fingerprint: fingerprint.finalize().into(),
    })
}

fn observe_services(normal: &[u8]) -> Option<Vec<Range<usize>>> {
    let selected = observed_call(normal, 0x538ad6)?;
    if observed_call(normal, 0x538b26)? != selected {
        return None;
    }
    let mut witnesses = Vec::new();
    if selected != 0x538de4 {
        let graph = super::dispatch_bridge::observe(normal).ok()?;
        if graph.kind != super::dispatch_bridge::Kind::Software
            || BASE + graph.selector.start as u32 != selected
        {
            return None;
        }
        witnesses.extend([graph.dispatch, graph.selector]);
        witnesses.extend(graph.callers.into_iter().flatten());
    }
    for &(a, z, digest) in RETAINED {
        if matches!(a, 0x538a88 | 0x538b24) {
            let canonical = copied(normal, a, z, &[(selected, 0x538de4)])?;
            if Sha256::digest(canonical).as_slice() != digest {
                return None;
            }
        } else {
            bind(normal, &[(a, z, digest)])?;
        }
        witnesses.push(span(a, z));
    }
    Some(witnesses)
}

/// Compose a profile against independently discovered target native roles.
pub fn plan_with_profile_with_roles(
    target: &[u8],
    source: &[u8],
    kernel: &[u8],
    profile: trajectory_profile::Plan,
    roles: &TargetRoles,
) -> Option<Plan> {
    if !roles.verify(target) || kernel.len() != crate::image::KERNEL_LEN {
        return None;
    }
    let canonical = canonical_source(source)?;
    let source = canonical.as_slice();
    trajectory_profile::validate_default_with_roles(target, kernel, roles)?;
    entries_clear_with_roles(target, kernel, roles)?;
    let allowed = [
        span(ENTRY, 0x539b2c),
        span(0x53957e, 0x53959e),
        span(0x5395d6, 0x5395e2),
        span(0x53966e, 0x539766),
    ]
    .into_iter()
    .map(|r| roles.span(r))
    .collect::<Option<Vec<_>>>()?;
    private_refs_clear(target, kernel, &allowed)?;
    assemble_with_roles(target, source, profile, roles)
}

fn assemble_with_roles(
    target: &[u8],
    source: &[u8],
    profile: trajectory_profile::Plan,
    roles: &TargetRoles,
) -> Option<Plan> {
    let entry = |old| {
        profile
            .entries
            .iter()
            .find(|(a, _)| *a == old)
            .map(|(_, b)| *b)
    };
    let mut mapping = profile.entries.clone();
    mapping.extend(
        [
            (0x5d6d62, 0x538c7a),
            (0x5d6c72, 0x538b74),
            (0x5d6c40, 0x538b24),
            (0x5d6c48, 0x538b2c),
            (0x5d6bce, 0x538a88),
            (0x5d7d6c, 0x539d58),
            (0x5d7d7e, 0x539d6a),
            (0x5d7d8a, 0x539d76),
            (0x5d7da0, 0x539d8c),
            (0x5d7dac, 0x539d98),
            (0x5cedae, 0x530bae),
            (0x5f0c26, 0x551f0e),
            (0x5f0cb6, 0x551f60),
            (0x5f0ce0, 0x551f8a),
        ]
        .into_iter()
        .map(|(a, b)| Some((a, roles.address(b)?)))
        .collect::<Option<Vec<_>>>()?,
    );
    let mut replacement = Vec::new();
    // Save caller registers and allocate an aligned local complete35-byte object.
    emit(
        &mut replacement,
        bytes(source, 0x5d7a0c, 0x5d7a18)?,
        &[(16, 36)],
    )?;
    // OEM MOV.L ER1,ER4.
    emit(&mut replacement, &[0x0f, 0x94], &[])?;
    // Source init's exact unsigned count normalization and zero branch, moved
    // before object construction. 0xffff rounds to zero; skipping the controller
    // prevents its zero-count initializer from exposing an uninitialized table.
    // Native caller wrappers still execute their existing completion/status path.
    emit(&mut replacement, bytes(source, 0x5d5aae, 0x5d5ab0)?, &[])?;
    let guard_at = replacement.len();
    emit(&mut replacement, bytes(source, 0x5d5b3e, 0x5d5b4c)?, &[])?;
    call(&mut replacement, profile.prepare)?;
    emit(&mut replacement, &[0x0f, 0xf0, 0x0f, 0x85], &[])?;
    emit(
        &mut replacement,
        &[0x7a, 1, 0, 0, 0, 0, 1, 0, 0x69, 0x81, 0x0b, 0x90],
        &[(0, roles.address(VTABLE)?)],
    )?;
    call(&mut replacement, entry(0x5d5fe6)?)?;
    emit(
        &mut replacement,
        &[
            0xf0, 1, 0x6a, 0xa0, 0, 0xa0, 0x5d, 0xdc, 0x0f, 0xc1, 0x0f, 0xd0,
        ],
        &[],
    )?;
    call(&mut replacement, roles.address(CONTROLLER)?)?;
    emit(
        &mut replacement,
        &[0x18, 0, 0x6a, 0xa0, 0, 0xa0, 0x5d, 0xdc],
        &[],
    )?;
    let epilogue = replacement.len();
    // Re-encode only the native BEQ displacement; its condition/register flow
    // and the short branch skipping INC remain the original source block.
    let branch = guard_at + 10;
    let d = decode_insn(&replacement[branch..], Target::H8S2000, Mode::Advanced).ok()?;
    let mut i = d.insn;
    let Operand::Address(Ea::PcRelative { bits, .. }) = i.operands[0] else {
        return None;
    };
    i.operands[0] = Operand::Address(Ea::PcRelative {
        bits,
        value: (epilogue - branch - d.len) as i32,
    });
    let encoded = encode_insn(i, Target::H8S2000, Mode::Advanced).ok()?;
    replacement[branch..branch + d.len].copy_from_slice(&encoded);
    emit(
        &mut replacement,
        bytes(source, 0x5d7b0e, 0x5d7b1c)?,
        &[(16, 36)],
    )?;
    if replacement.len() > 104 {
        return None;
    }
    let pad = 104 - replacement.len();
    nops(&mut replacement, pad)?;
    let mut controller = copied(source, 0x5d7a0c, 0x5d7b1c, &mapping)?;
    // These two complete source blocks are native mode-nine peripheral hooks.
    // Keep target hardware-specific mode-nine implementations and their ABI.
    for (old, to) in [(0x5d7aa4, 0x4f52fc), (0x5d7afe, 0x4f5366)] {
        let mut block = Vec::new();
        emit(&mut block, &[0xf8, 9], &[])?;
        call(&mut block, roles.address(to)?)?;
        nops(&mut block, 4)?;
        controller[(old - 0x5d7a0c) as usize..(old - 0x5d7a0c) as usize + 10]
            .copy_from_slice(&block);
    }
    replacement.extend(controller);
    replacement.extend(copied(source, 0x5d796c, 0x5d7a0c, &mapping)?);
    // Tail-jump preserves the original variadic stack frame for both source masks.
    emit(
        &mut replacement,
        &[0xf8, 4, 0x5a, 0x54, 0xc4, 0xc4],
        &[(0x54c4c4, roles.address(0x54c4c4)?)],
    )?;
    let mut vtable = bytes(source, 0x6934b6, 0x6934ca)?.to_vec();
    if vtable[..16].iter().any(|b| *b != 0) || vtable[16..] != 0x5d796cu32.to_be_bytes() {
        return None;
    }
    vtable[16..].copy_from_slice(&roles.address(CALLBACK)?.to_be_bytes());
    replacement.extend(vtable);
    let pad = (0x539b2c - ENTRY) as usize - replacement.len();
    nops(&mut replacement, pad)?;
    let mut stop = target.get(roles.span(span(0x53957e, 0x53959e))?)?.to_vec();
    let mut empty = Vec::new();
    nops(&mut empty, 10)?;
    stop[8..18].copy_from_slice(&empty);
    let mut dead = Vec::new();
    nops(&mut dead, (0x539766 - 0x53966e) as usize)?;
    let mut initializers = Vec::new();
    nops(&mut initializers, 12)?;
    let mut writes = Vec::new();
    let [helpers, tail] = roles.auxiliary_slots()?;
    for (i, (r, b)) in profile.writes.iter().enumerate() {
        if r.len() != b.len()
            || profile.writes[..i]
                .iter()
                .any(|(other, _)| overlap(r, other))
        {
            return None;
        }
        if helpers.start <= r.start && r.end <= helpers.end {
            dead[r.start - helpers.start..r.end - helpers.start].copy_from_slice(b);
        } else if tail.start <= r.start && r.end <= tail.end {
            replacement[r.start - (roles.address(ENTRY)? - BASE) as usize
                ..r.end - (roles.address(ENTRY)? - BASE) as usize]
                .copy_from_slice(b);
        } else {
            if [
                helpers.clone(),
                roles.span(span(ENTRY, 0x539b2c))?,
                roles.span(span(0x53957e, 0x53959e))?,
                roles.span(span(0x5395d6, 0x5395e2))?,
            ]
            .iter()
            .any(|own| overlap(r, own))
            {
                return None;
            }
            writes.push((r.clone(), b.clone()));
        }
    }
    writes.extend([
        (roles.span(span(ENTRY, 0x539b2c))?, replacement),
        (roles.span(span(0x53957e, 0x53959e))?, stop),
        (roles.span(span(0x53966e, 0x539766))?, dead),
        (roles.span(span(0x5395d6, 0x5395e2))?, initializers),
    ]);
    Some(Plan {
        writes,
        controller: roles.address(CONTROLLER)?,
        callback: roles.address(CALLBACK)?,
        profile,
    })
}

fn entries_clear_with_roles(n: &[u8], k: &[u8], roles: &TargetRoles) -> Option<()> {
    let graph = [
        roles.span(span(0x538350, 0x53836e))?,
        roles.span(span(0x5388a4, 0x5388c4))?,
        roles.span(span(0x53956c, 0x53957e))?,
        roles.span(span(0x5395e8, 0x539620))?,
        roles.span(span(0x539620, 0x53962e))?,
        roles.span(span(ENTRY, 0x539b2c))?,
        roles.span(span(0x53966e, 0x539766))?,
    ];
    let mut retired = graph.to_vec();
    // Caller preparation begins at a legitimate existing native entry; every
    // following byte must be reached through the explicit SUB.B R1L,R1L.
    retired[0].start += 1;
    retired[1].start += 1;
    retirement::references_clear(
        n,
        k,
        &retired,
        &graph,
        &[
            graph[0].clone(),
            graph[1].clone(),
            graph[2].clone(),
            graph[3].clone(),
            graph[4].clone(),
            graph[5].clone(),
            roles.span(span(0x53966e, 0x5396a8))?,
            roles.span(span(0x5396a8, 0x539766))?,
        ],
    )
}

fn observe_inner_with_roles(
    normal: &[u8],
    kernel: &[u8],
    stage: &mut &'static str,
    roles: &TargetRoles,
) -> Option<Observed> {
    let service_witness = roles.protected().to_vec();
    *stage = "native-input-preparation";

    *stage = "resident-component";
    if kernel.len() != crate::image::KERNEL_LEN {
        return None;
    }
    *stage = "profile-entries";
    let roots = trajectory_profile::SharedEntries {
        init: observed_call(normal, roles.address(CONTROLLER + (0x5d7a6a - 0x5d7a0c))?)?,
        update: observed_call(normal, roles.address(CALLBACK + (0x5d79f8 - 0x5d796c))?)?,
        ctor: observed_call(normal, roles.address(ENTRY + 50)?)?,
        prepare: observed_call(normal, roles.address(ENTRY + 30)?)?,
    };
    *stage = "profile";
    let profile = trajectory_profile::observe_shared_with_roles(
        normal,
        kernel,
        roots,
        roles.services()?,
        PRIVATE,
        roles,
    )?;
    *stage = "private-ram";
    let mut private_owners = profile.placements.code.to_vec();
    private_owners.extend([
        roles.span(span(ENTRY, VTABLE))?,
        roles.span(span(0x537e26, 0x537e30))?,
        roles.span(span(0x53957e, 0x53959e))?,
    ]);
    private_refs_clear(normal, kernel, &private_owners)?;
    *stage = "stack-wrapper";
    let mut expected = Vec::new();
    // Complete OEM register/stack wrapper, including the lifted source unsigned
    // normalization block. Only prepare/ctor entries are relocated here.
    emit(
        &mut expected,
        &[
            0x01, 0, 0x6d, 0xf3, 0x01, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0, 0x24, 0x0f, 0x94, 0x0d,
            0x9a, 0x0d, 0xa1, 0x73, 0x09, 0x47, 0x02, 0x0b, 0x5a, 0x0d, 0xaa, 0x58, 0x70, 0, 0x30,
        ],
        &[],
    )?;
    call(&mut expected, roots.prepare)?;
    emit(
        &mut expected,
        &[
            0x0f, 0xf0, 0x0f, 0x85, 0x7a, 1, 0, 0, 0, 0, 1, 0, 0x69, 0x81, 0x0b, 0x90,
        ],
        &[(0, roles.address(VTABLE)?)],
    )?;
    call(&mut expected, roots.ctor)?;
    emit(
        &mut expected,
        &[
            0xf0, 1, 0x6a, 0xa0, 0, 0xa0, 0x5d, 0xdc, 0x0f, 0xc1, 0x0f, 0xd0,
        ],
        &[],
    )?;
    call(&mut expected, roles.address(CONTROLLER)?)?;
    emit(
        &mut expected,
        &[
            0x18, 0, 0x6a, 0xa0, 0, 0xa0, 0x5d, 0xdc, 0x79, 0x17, 0, 0x24, 1, 0x20, 0x6d, 0x76, 1,
            0, 0x6d, 0x73, 0x54, 0x70,
        ],
        &[],
    )?;
    nops(&mut expected, 12)?;
    if normal.get(roles.span(span(ENTRY, CONTROLLER))?)? != expected {
        return None;
    }
    *stage = "controller-callback";
    let mut reverse = alloc::vec![
        (roots.init, 0x5d5aa6),
        (roots.update, 0x5d5d60),
        (BASE + profile.placements.code[3].start as u32, 0x5d6018),
        (roles.address(0x538c7a)?, 0x5d6d62),
        (roles.address(0x538b74)?, 0x5d6c72),
        (roles.address(0x538b24)?, 0x5d6c40),
        (roles.address(0x538b2c)?, 0x5d6c48),
        (roles.address(0x538a88)?, 0x5d6bce),
        (roles.address(0x539d58)?, 0x5d7d6c),
        (roles.address(0x539d6a)?, 0x5d7d7e),
        (roles.address(0x539d76)?, 0x5d7d8a),
        (roles.address(0x539d8c)?, 0x5d7da0),
        (roles.address(0x539d98)?, 0x5d7dac),
        (roles.address(0x530bae)?, 0x5cedae),
        (roles.address(0x551f0e)?, 0x5f0c26),
        (roles.address(0x551f60)?, 0x5f0cb6),
        (roles.address(0x551f8a)?, 0x5f0ce0),
    ];
    reverse.sort_unstable();
    if reverse.windows(2).any(|w| w[0].0 == w[1].0) {
        return None;
    }
    let mut controller = copied(
        normal,
        roles.address(CONTROLLER)?,
        roles.address(CONTROLLER + 272)?,
        &reverse,
    )?;
    for (old, target, source) in [
        (0x5d7aa4, 0x4f52fc, 0x5b8cc8),
        (0x5d7afe, 0x4f5366, 0x5b8df6),
    ] {
        let off = (old - 0x5d7a0c) as usize;
        let mut hook = Vec::new();
        emit(&mut hook, &[0xf8, 9], &[])?;
        call(&mut hook, roles.address(target)?)?;
        nops(&mut hook, 4)?;
        if controller.get(off..off + 10)? != hook {
            return None;
        }
        let mut original = Vec::new();
        call(&mut original, 0x5b8a5e)?;
        emit(&mut original, &[0xf9, 9], &[])?;
        call(&mut original, source)?;
        controller[off..off + 10].copy_from_slice(&original);
    }
    let mut canonical = copied(
        normal,
        roles.address(CALLBACK)?,
        roles.address(CALLBACK + 160)?,
        &reverse,
    )?;
    canonical.extend(controller);
    let (_, _, digest) = SOURCE
        .iter()
        .find(|(a, z, _)| *a == 0x5d796c && *z == 0x5d7b1c)?;
    if Sha256::digest(&canonical).as_slice() != digest {
        return None;
    }
    *stage = "vtable-reporter";
    let mut reporter = Vec::new();
    emit(
        &mut reporter,
        &[0xf8, 4, 0x5a, 0x54, 0xc4, 0xc4],
        &[(0x54c4c4, roles.address(0x54c4c4)?)],
    )?;
    if normal.get(roles.span(span(REPORT, VTABLE))?)? != reporter {
        return None;
    }
    let vtable = normal.get(roles.span(span(VTABLE, VTABLE + 20))?)?;
    if vtable[..16].iter().any(|b| *b != 0)
        || vtable[16..] != roles.address(CALLBACK)?.to_be_bytes()
    {
        return None;
    }
    *stage = "stop";
    let mut stop = alloc::vec![0x6a, 0x28, 0, 0xa0, 0x5d, 0xdc, 0x47, 0x14];
    nops(&mut stop, 10)?;
    emit(
        &mut stop,
        &[
            0xf8, 1, 0x6a, 0xa8, 0, 0xa0, 0x5d, 0xdd, 0x40, 2, 0x55, 0xb4, 0x54, 0x70,
        ],
        &[],
    )?;
    let stop = super::native_graph::relocate(
        &stop,
        0x53957e,
        roles.address(0x53957e)?,
        &[(0x539550, 0x539554, roles.address(0x539550)?)],
    )?;
    if normal.get(roles.span(span(0x53957e, 0x53959e))?)? != stop
        || normal
            .get(roles.span(span(0x5395d6, 0x5395e2))?)?
            .iter()
            .any(|b| *b != 0)
    {
        return None;
    }
    *stage = "inbound-closure";
    let mut retired = profile.placements.code.to_vec();
    retired.extend(profile.placements.data.iter().cloned());
    retired.push(roles.span(span(ENTRY, VTABLE + 20))?);
    // Close the wrapper's mode/direction specialization and the legacy guard:
    // unknown calls cannot bypass the native preparation/zero-count boundary.
    retired.extend([
        roles.span(span(0x53956c, 0x53957e))?,
        roles.span(span(0x5395e8, 0x539620))?,
        roles.span(span(0x539620, 0x53962e))?,
        roles.span(span(0x538351, 0x53836e))?,
        roles.span(span(0x5388a5, 0x5388c4))?,
        roles.span(span(0x539406, 0x539407))?,
    ]);
    let mut replaced = retired.clone();
    replaced.extend(profile.ranges.iter().cloned());
    replaced.extend([
        roles.span(span(0x538350, 0x53836e))?,
        roles.span(span(0x5388a4, 0x5388c4))?,
    ]);
    replaced.extend([
        roles.span(span(ENTRY, 0x539b2c))?,
        roles.span(span(0x5392d2, 0x539406))?,
        roles.span(span(0x539406, 0x539550))?,
    ]);
    let mut bodies = profile.placements.code.to_vec();
    bodies.extend([
        roles.span(span(ENTRY, CONTROLLER))?,
        roles.span(span(CONTROLLER, CALLBACK))?,
        roles.span(span(CALLBACK, REPORT))?,
        roles.span(span(REPORT, VTABLE))?,
        roles.span(span(0x5392d2, 0x539406))?,
        roles.span(span(0x539406, 0x539550))?,
    ]);
    // A materialized software graph must establish exclusive scalar ownership;
    // passing the generic reference scan alone does not establish that claim.
    let dispatch = super::dispatch_bridge::observe(normal).ok()?;
    let authority = match dispatch.kind {
        super::dispatch_bridge::Kind::Software => {
            super::profile_ownership::prove_with_software_tables(
                normal,
                kernel,
                &retired,
                &replaced,
                &bodies,
                &profile.data_authority,
            )
        }
        super::dispatch_bridge::Kind::Literal => {
            super::profile_ownership::prove(normal, kernel, &retired, &replaced, &bodies)
        }
        super::dispatch_bridge::Kind::Pointer => None,
    }?;
    let mut protected = profile.ranges.clone();
    protected.extend(profile.invariants.iter().cloned());
    protected.extend(authority);
    protected.extend(service_witness);
    protected.extend(
        RETAINED
            .iter()
            .chain(DIRECTION)
            .map(|(a, z, _)| roles.span(span(*a, *z)))
            .collect::<Option<Vec<_>>>()?,
    );
    protected.extend([
        roles.span(span(ENTRY, VTABLE + 20))?,
        roles.span(span(0x53957e, 0x53959e))?,
        roles.span(span(0x5395d6, 0x5395e2))?,
    ]);
    protected.sort_unstable_by_key(|r| (r.start, r.end));
    protected.dedup();
    let mut fingerprint = Sha256::new();
    for r in &protected {
        fingerprint.update((r.start as u32).to_be_bytes());
        fingerprint.update((r.end as u32).to_be_bytes());
        fingerprint.update(normal.get(r.clone())?);
    }
    Some(Observed {
        entry: roles.address(ENTRY)?,
        profile,
        code: bodies,
        protected,
        fingerprint: fingerprint.finalize().into(),
    })
}

/// Rediscover emitted controller and retained target roles without an original
/// image, saved operation, or fixed controller location.
pub fn observe_native_roles(normal: &[u8], kernel: &[u8]) -> Result<Observed, ObservationFailure> {
    let roles = TargetRoles::locate_emitted(normal).ok_or(ObservationFailure {
        stage: "retained-role-discovery",
    })?;
    let mut stage = "retained-roles";
    observe_inner_with_roles(normal, kernel, &mut stage, &roles).ok_or(ObservationFailure { stage })
}
