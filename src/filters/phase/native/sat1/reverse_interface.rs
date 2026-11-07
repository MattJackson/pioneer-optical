//! Native split-word physical output with the target byte command's original
//! caller-visible state updates. Placement is limited to bound retired code/data.
use super::*;
const BYTE_ZERO: &[u8] = &[
    0x18, 0x88, 0x6a, 0x88, 0xf9, 8, 0x6a, 0x88, 0xf9, 9, 0x54, 0x70,
];

fn driver(
    origin: u32,
    tail: u32,
    previous: u32,
    direction: u32,
    packed: u32,
    lookup: u32,
    assignment: Assignment,
) -> Result<Vec<u8>, Error> {
    let mut a = h8_asm::Asm::new(Target::H8S2000, Mode::Advanced).map_err(|_| Error::Unresolved)?;
    macro_rules! i {($($b:expr),+)=>{a.instruction(&[$($b),+]).map_err(|_|Error::Unresolved)?};}
    macro_rules! b {
        ($c:expr,$l:expr) => {
            a.branch($c, $l).map_err(|_| Error::Unresolved)?
        };
    }
    macro_rules! l {
        ($l:expr) => {
            a.label($l).map_err(|_| Error::Unresolved)?
        };
    }
    let p = previous.to_be_bytes();
    let q = direction.to_be_bytes();
    let t = packed.to_be_bytes();
    let c = lookup.to_be_bytes();
    let e = tail.to_be_bytes();
    i!(0xea, 0x3f); // Retained target masked phase.
    i!(0x01, 0x20, 0x6d, 0xf4);
    i!(0x0d, 0x2e); // Save callee registers and target mode/phase in E6.
    i!(0x1a, 0xc4);
    i!(0x0c, 0x20);
    i!(0x14, 0x90);
    b!(6, "mode");
    i!(0xf2, 4);
    l!("mode");
    i!(0xa2, 5);
    b!(2, "done");
    i!(0xfc, 32);
    i!(0xa2, 2);
    b!(4, "ge2");
    i!(0x18, 0xcc);
    i!(0x0c, 0x22);
    b!(7, "selected");
    i!(0xfc, 24);
    b!(0, "selected");
    l!("ge2");
    i!(0xa2, 4);
    b!(5, "selected");
    i!(0xfc, 8);
    if assignment == Assignment::Swapped {
        i!(0xa2, 5);
        b!(6, "direction");
        i!(0x18, 0xcc);
    }
    l!("direction");
    i!(0x19, 0x00);
    i!(0x6a, 0x28, p[0], p[1], p[2], p[3]);
    i!(0x19, 0x33);
    i!(0x0c, 0xab);
    i!(0x19, 0x30);
    b!(7, "retained_direction");
    i!(0x79, 0x20, 0, 16);
    b!(14, "negative");
    i!(0x0d, 0x00);
    b!(12, "positive_direction");
    i!(0x79, 0x20, 0xff, 0xf0);
    b!(13, "positive_direction");
    l!("negative");
    i!(0xf8, 1);
    b!(0, "write_direction");
    l!("positive_direction");
    i!(0x18, 0x88);
    l!("write_direction");
    i!(0x6a, 0xa8, q[0], q[1], q[2], q[3]);
    l!("retained_direction");
    i!(0x6a, 0x28, q[0], q[1], q[2], q[3]);
    b!(7, "selected");
    i!(0xfc, 16);
    l!("selected");
    i!(0x17, 0x54);
    i!(0x17, 0x74);
    i!(0x7a, 0x14, t[0], t[1], t[2], t[3]);
    i!(0x0c, 0xa6);
    i!(0x0c, 0xae);
    i!(0xa9, 2);
    b!(6, "phases");
    i!(0x86, 8);
    i!(0xe6, 32);
    i!(0x8e, 0xf8);
    i!(0xee, 32);
    i!(0xce, 16);
    l!("phases");
    if assignment == Assignment::Swapped {
        i!(0x0b, 0x94);
    }
    i!(0x0f, 0xc1);
    i!(
        0x0c,
        if assignment == Assignment::Direct {
            0x68
        } else {
            0xe8
        }
    );
    i!(0x5e, c[1], c[2], c[3]);
    i!(0x0d, 0x05);
    i!(0x12, 0xc8);
    i!(0xe8, 3);
    i!(0x6a, 0x88, 0xf9, 0x12);
    i!(
        if assignment == Assignment::Direct {
            0x0b
        } else {
            0x1b
        },
        0x94
    );
    i!(0x0f, 0xc1);
    i!(
        0x0c,
        if assignment == Assignment::Direct {
            0xe8
        } else {
            0x68
        }
    );
    i!(0x5e, c[1], c[2], c[3]);
    i!(0x12, 0xc8);
    i!(0xe8, 3);
    i!(0x6a, 0x88, 0xf9, 0x13);
    i!(0x6a, 0x85, 0xf9, 0x10);
    i!(0x6a, 0x80, 0xf9, 0x11);
    l!("done");
    i!(0x0d, 0xe2);
    i!(0x01, 0x20, 0x6d, 0x76);
    i!(0x5a, e[1], e[2], e[3]);
    a.finish(origin).map_err(|_| Error::ResourceMismatch)
}

fn exclusive(
    normal: &[u8],
    kernel: &[u8],
    body: &Range<usize>,
    tables: &[Range<usize>],
    zero: &Range<usize>,
) -> Result<(), Error> {
    if kernel.len() != crate::image::KERNEL_LEN {
        return Err(Error::Ownership);
    }
    let protected = |address: usize| {
        address.checked_sub(0x410000).is_some_and(|at| {
            (body.start + 66..body.start + 260).contains(&at)
                || tables.iter().any(|r| r.contains(&at))
                || (zero.contains(&at) && at != zero.start)
        })
    };
    for (bytes, base) in [(normal, 0x410000usize), (kernel, 0x400000)] {
        let regions = crate::image::regions(bytes).ok_or(Error::Ownership)?;
        for region in regions.stored {
            let start = region.as_ptr() as usize - bytes.as_ptr() as usize;
            for local in 0..region.len() {
                let at = start + local;
                if base == 0x410000
                    && (body.contains(&at)
                        || zero.contains(&at)
                        || tables.iter().any(|r| r.contains(&at)))
                {
                    continue;
                }
                if local + 4 <= region.len()
                    && protected(integer(&region[local..local + 4]) as usize)
                {
                    return Err(Error::Ownership);
                }
                if at & 1 != 0 {
                    continue;
                }
                if let Ok(d) = decode_insn(&region[local..], Target::H8S2000, Mode::Advanced) {
                    for operand in d.insn.operands {
                        let address = match operand {
                            O::Immediate {
                                value,
                                bits: 24 | 32,
                            }
                            | O::Address(Ea::Absolute {
                                value,
                                bits: 24 | 32,
                            }) => Some(value as usize),
                            O::Address(Ea::PcRelative { value, .. }) => {
                                (base + at + d.len).checked_add_signed(value as isize)
                            }
                            O::Address(Ea::Displacement {
                                value, bits: 32, ..
                            }) => Some(value as usize),
                            _ => None,
                        };
                        if address.is_some_and(protected) {
                            return Err(Error::Ownership);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Transplant exact split-word output while retaining target phase accumulation,
/// previous-phase storage and public entries. Both Kernels are authoritative;
/// the donor Kernel must prove the original identity/high-byte leaves.
/// Insufficient positively-owned storage remains a refusal.
pub fn transplant(
    target: &[u8],
    target_kernel: &[u8],
    donor: &[u8],
    donor_kernel: &[u8],
) -> Result<Vec<u8>, Error> {
    let a = byte_pair::observe_normal(target)?;
    let d = super::observe(donor, donor_kernel)?;
    if a.shape != 0 || a.body.len() != 272 {
        return Err(Error::Unresolved);
    }
    let tables: Vec<_> = a
        .coefficients
        .iter()
        .map(|t| match t {
            byte_pair::Coefficients::Rom(r) => Ok(r.clone()),
            _ => Err(Error::Unresolved),
        })
        .collect::<Result<_, _>>()?;
    if tables.len() != 3 || tables.windows(2).any(|p| p[0].end != p[1].start) {
        return Err(Error::ResourceMismatch);
    }
    let zero = a.body.end..a.body.end + 12;
    if target.get(zero.clone()) != Some(BYTE_ZERO) {
        return Err(Error::Unresolved);
    }
    exclusive(target, target_kernel, &a.body, &tables, &zero)?;
    let direction = persistent_direction(target, target_kernel, &a)?;
    let mut words = [[0u8; 256]; 5];
    for (to, from) in words.iter_mut().zip(&d.tables) {
        to.copy_from_slice(&donor[from.clone()]);
    }
    let packed = packed::pack(&words)?;
    let lookup = packed.lookup_leaf()?;
    let storage = tables[0].start..tables[2].end;
    let lookup_at = storage.start;
    let packed_at = lookup_at + lookup.len();
    let zero_at = packed_at + packed.bytes.len();
    if zero_at + ZERO.len() > storage.end {
        return Err(Error::ResourceMismatch);
    }
    let physical = driver(
        (0x410000 + a.body.start + 66) as u32,
        (0x410000 + a.body.start + 260) as u32,
        a.state[1],
        direction,
        (0x410000 + packed_at) as u32,
        (0x410000 + lookup_at) as u32,
        d.assignment,
    )?;
    if physical.len() > 194 {
        return Err(Error::ResourceMismatch);
    }
    let mut changed = target.to_vec();
    encoding::nops(&mut changed[a.body.start + 66..a.body.start + 260]).ok_or(Error::Unresolved)?;
    encoding::nops(&mut changed[storage.clone()]).ok_or(Error::Unresolved)?;
    encoding::nops(&mut changed[zero.clone()]).ok_or(Error::Unresolved)?;
    changed[a.body.start + 66..a.body.start + 66 + physical.len()].copy_from_slice(&physical);
    changed[lookup_at..packed_at].copy_from_slice(&lookup);
    changed[packed_at..zero_at].copy_from_slice(&packed.bytes);
    changed[zero_at..zero_at + ZERO.len()].copy_from_slice(ZERO);
    changed[zero.start..zero.start + 4]
        .copy_from_slice(&encoding::jump((0x410000 + zero_at) as u32).ok_or(Error::Unresolved)?);
    Ok(changed)
}

// The source retains its direction on equal consecutive phases. Byte shape zero
// exposes only previous phase and accumulator state, neither of which can encode
// that independent bit. A future binding must prove a private RAM byte AND its
// initialization/reset lifecycle; an unused address is not sufficient evidence.
fn persistent_direction(
    _normal: &[u8],
    _kernel: &[u8],
    _binding: &byte_pair::Binding,
) -> Result<u32, Error> {
    Err(Error::Unresolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sat1_reverse_driver_assembles_with_bound_entries() {
        for assignment in [Assignment::Direct, Assignment::Swapped] {
            let code = driver(0x500000, 0x500100, 0x2000, 0x2001,
                0x600000, 0x600100, assignment).unwrap();
            let mut at = 0;
            while at < code.len() {
                let ins = decode_insn(&code[at..], Target::H8S2000, Mode::Advanced).unwrap();
                at += ins.len;
            }
            assert_eq!(at, code.len());
            eprintln!("reverse {assignment:?} driver {} bytes", code.len());
        }
    }
}
