//! Shared H8S instruction framing used by ABI discovery and analysis.
/// Instruction length in bytes at `i` (H8S/2000 big-endian).
pub(crate) fn ilen(c: &[u8], i: usize) -> usize {
    let g = |k: usize| c.get(i + k).copied().unwrap_or(0);
    let (b0, b1) = (g(0), g(1));
    match b0 {
        0x01 => match b1 & 0xF0 {
            0x00 | 0x40 => match g(2) {
                0x6B => {
                    if g(3) & 0x70 == 0 {
                        6
                    } else {
                        8
                    }
                }
                0x6F => 6,
                0x78 => 10,
                _ => 4,
            },
            0x10 | 0x20 | 0x30 | 0xC0 | 0xD0 | 0xF0 => 4,
            _ => 2,
        },
        0x58 | 0x5A | 0x5C | 0x5E => 4,
        0x6A => match b1 & 0xF0 {
            0x10 | 0x20 | 0x90 | 0xA0 => 6,
            0x30 | 0xB0 => 8,
            _ => 4,
        },
        0x6B => match b1 & 0xF0 {
            0x00 | 0x80 => 4,
            _ => 6,
        },
        0x6E | 0x6F | 0x79 | 0x7B | 0x7C | 0x7D | 0x7E | 0x7F => 4,
        0x78 => 8,
        0x7A => 6,
        _ => 2,
    }
}

/// Is the instruction at `i` a defined H8S/2000 encoding (coarse check)?
pub(crate) fn valid(c: &[u8], i: usize) -> bool {
    if i + 2 > c.len() {
        return false;
    }
    let g = |k: usize| c.get(i + k).copied().unwrap_or(0);
    let (b0, b1) = (g(0), g(1));
    match b0 {
        0x01 => match b1 & 0xF0 {
            h @ (0x00 | 0x40) => {
                if h == 0x00 && b1 != 0x00 {
                    return false;
                }
                match g(2) {
                    0x69 | 0x6D | 0x6F => true,
                    0x6B => matches!(g(3) & 0x70, 0x00 | 0x20),
                    0x78 => matches!(g(4), 0x6A | 0x6B),
                    _ => false,
                }
            }
            0x10 | 0x20 | 0x30 => b1 & 0x0F == 0 && g(2) == 0x6D && g(3) >= 0x70,
            0x80 => b1 == 0x80,
            0xC0 => g(2) == 0x50,
            0xD0 => g(2) == 0x51,
            0xF0 => matches!(g(2), 0x64..=0x66),
            _ => false,
        },
        0x54 | 0x56 => b1 == 0x70,
        0x58 => b1 & 0x0F == 0,
        0x59 | 0x5D => b1 & 0x8F == 0,
        0x5A | 0x5E => b1 <= 0x7F,
        0x5C => b1 == 0,
        0x7C | 0x7D => b1 & 0x8F == 0 && matches!(g(2), 0x60..=0x77),
        0x7E | 0x7F => matches!(g(2), 0x60..=0x77),
        0x7B => b1 == 0x5C && g(2) == 0x59,
        0x78 => b1 & 0x8F == 0 && matches!(g(2), 0x6A | 0x6B),
        0x79 | 0x7A => b1 & 0xF0 <= 0x60,
        0x6A => matches!(
            b1 & 0xF0,
            0x00 | 0x10 | 0x20 | 0x30 | 0x80 | 0x90 | 0xA0 | 0xB0
        ),
        0x6B => matches!(b1 & 0xF0, 0x00 | 0x20 | 0x80 | 0xA0),
        _ => true,
    }
}
