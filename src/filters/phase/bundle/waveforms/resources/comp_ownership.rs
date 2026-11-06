//! Ownership of complete native COMP representations and their reclaimed tails.
//! Original validated compressed bytes are data, not candidate instructions.
//! All other stored/expanded Normal and paired-Kernel references are checked.
use super::{comp_code, comp_tables, native_comp};
use alloc::{collections::BTreeMap, vec::Vec};
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, Ea, Operand},
    Mode, Target,
};
const BASE: usize = 0x410000;

/// Stream storage ownership plus every unchanged Normal classification witness.
#[derive(Clone, Debug)]
pub struct Proof {
    /// Exact reclaimed byte tails; callers apply their required alignment.
    pub tails: Vec<Range<usize>>,
    /// Original native instruction/data witnesses that must survive composition.
    /// The separately proved inflater JSR retargets are explicit exceptions;
    /// all other overlapping edits require an independent equivalent grammar.
    pub protected_normal: Vec<Range<usize>>,
}
/// Prove unchanged expansion and exclusive original stream ownership.
/// This does not replace native execution certification of the new encoding.
pub fn prove(original: &[u8], kernel: &[u8], repacked: &[u8]) -> Option<Proof> {
    if original.len() != repacked.len() {
        return None;
    }
    let native = native_comp::observe_with_kernel(original, kernel)?;
    if native_comp::observe(repacked)? != native {
        return None;
    }
    let (base, before) =
        crate::comp_streams::read(original, crate::comp::MAX_TOTAL_EXPANDED, &mut || true)
            .ok()??;
    let (after_base, after) =
        crate::comp_streams::read(repacked, crate::comp::MAX_TOTAL_EXPANDED, &mut || true)
            .ok()??;
    // Exact bound loader admits selectors 0..=5, and the directory is six pairs.
    if base as usize != BASE || after_base != base || before.len() != 6 || after.len() != 6 {
        return None;
    }
    let directory = crate::comp::COMP_OFFSET..crate::comp::COMP_OFFSET + 4 + before.len() * 8 + 4;
    let mut owned = Vec::new();
    let mut editable = Vec::new();
    let mut tails = Vec::new();
    for (i, (a, b)) in before.iter().zip(&after).enumerate() {
        if a.image_offset != b.image_offset
            || a.expanded != b.expanded
            || a.compressed_size < b.compressed_size
            || original.get(a.image_offset..a.image_offset + 4)?
                != repacked.get(b.image_offset..b.image_offset + 4)?
        {
            return None;
        }
        let start = a.image_offset + 4;
        let end = start.checked_add(a.compressed_size)?;
        let new_end = start.checked_add(b.compressed_size)?;
        if a.compressed_size != b.compressed_size
            || original.get(start..end)? != repacked.get(start..end)?
        {
            owned.push(a.image_offset..end);
            // The selected record supplies this exact original stream. Other
            // unchanged records are not claimed to have an exclusive reader.
            owned.push(crate::comp::COMP_OFFSET + 4 + i * 8..crate::comp::COMP_OFFSET + 12 + i * 8);
        }
        editable.push(start..end);
        editable.push(crate::comp::COMP_OFFSET + 8 + i * 8..crate::comp::COMP_OFFSET + 12 + i * 8);
        if new_end < end {
            tails.push(new_end..end);
        }
    }
    if original
        .iter()
        .zip(repacked)
        .enumerate()
        .any(|(at, (a, b))| a != b && !editable.iter().any(|r| r.contains(&at)))
    {
        return None;
    }
    // Check the native directory base anchor as well as each changed record.
    // As with retirement proofs, arbitrary runtime address synthesis from an
    // unrelated unchanged record is outside this bounded-reference contract.
    owned.push(crate::comp::COMP_OFFSET..crate::comp::COMP_OFFSET + 4);
    let loader = native.loader.clone();
    let mut bodies = native.programs;
    bodies.push(native.boundary_program);
    bodies.push(native.loader);
    let code = comp_code::observe(original, kernel, &before[5].expanded);
    let tables = comp_tables::observe(original);
    if let Some(t) = &tables {
        bodies.extend(t.complete_code_bodies.iter().cloned());
    }
    let evidence = Evidence {
        owned: &owned,
        directory: &directory,
        bodies: &bodies,
        native_data: &native.data,
        loader: &loader,
        code: code.as_ref(),
        tables: tables.as_ref(),
    };
    references_clear(original, kernel, &evidence)?;
    let mut protected_normal = bodies.clone();
    protected_normal.push(native.data);
    if let Some(code) = code {
        protected_normal.extend(
            code.functions
                .iter()
                .filter(|f| f.base == BASE as u32)
                .map(|f| f.span.start as usize - BASE..f.span.end as usize - BASE),
        );
        protected_normal.push(0x594c68 - BASE..0x594c7e - BASE);
    }
    if let Some(tables) = tables {
        protected_normal.extend(tables.ranges);
        protected_normal.extend(tables.directory_ranges);
        protected_normal.extend(tables.map_writer_sites);
        protected_normal.push(0x5936b2 - BASE..0x5936c1 - BASE);
    }
    protected_normal.sort_by_key(|r| r.start);
    protected_normal.dedup();
    Some(Proof {
        tails,
        protected_normal,
    })
}

struct Evidence<'a> {
    owned: &'a [Range<usize>],
    directory: &'a Range<usize>,
    bodies: &'a [Range<usize>],
    native_data: &'a Range<usize>,
    loader: &'a Range<usize>,
    code: Option<&'a comp_code::Authority>,
    tables: Option<&'a comp_tables::TableAuthority>,
}
fn covers(r: &Range<usize>, at: usize, len: usize) -> bool {
    r.start <= at && at + len <= r.end
}
fn references_clear(normal: &[u8], kernel: &[u8], e: &Evidence<'_>) -> Option<()> {
    let mut instructions = BTreeMap::new();
    for body in e.bodies {
        let mut at = body.start;
        while at < body.end {
            let d = decode_insn(normal.get(at..body.end)?, Target::H8S2000, Mode::Advanced).ok()?;
            instructions.insert((BASE + at) as u32, (BASE + at + d.len) as u32);
            at += d.len;
        }
    }
    if let Some(code) = e.code {
        for f in &code.functions {
            for r in &f.instructions {
                instructions.insert(r.start, r.end);
            }
        }
    }
    let interior = |at: u32| {
        instructions
            .range(..=at)
            .next_back()
            .is_some_and(|(&start, &end)| start < at && at < end)
    };
    let code_bytes = |at: u32, len: usize| {
        (0..len).all(|i| {
            instructions
                .range(..=at + i as u32)
                .next_back()
                .is_some_and(|(_, &end)| at + (i as u32) < end)
        })
    };
    let owned = |a: usize| {
        a.checked_sub(BASE)
            .is_some_and(|a| e.owned.iter().any(|r| r.contains(&a)))
    };
    let table_target = |a: usize| {
        e.tables.and_then(|t| {
            a.checked_sub(BASE)
                .and_then(|a| t.ranges.iter().position(|r| r.contains(&a)))
        })
    };
    let table_directory = |a: usize| {
        e.tables.is_some_and(|t| {
            a.checked_sub(BASE)
                .is_some_and(|a| t.directory_ranges.iter().any(|r| r.contains(&a)))
        })
    };
    let map_cell = |a: usize| {
        e.tables.is_some_and(|t| {
            t.map_pointer_cells
                .iter()
                .any(|c| (*c..*c + 4).contains(&a))
        })
    };
    let mut clear = true;
    for (component, base) in [(normal, BASE), (kernel, crate::image::KERNEL_BASE as usize)] {
        let regions = crate::image::regions(component)?;
        for (bytes, offset, expanded_index) in regions
            .stored
            .iter()
            .map(|b| {
                (
                    *b,
                    Some(b.as_ptr() as usize - component.as_ptr() as usize),
                    None,
                )
            })
            .chain(
                regions
                    .expanded
                    .iter()
                    .enumerate()
                    .map(|(i, b)| (b.as_slice(), None, Some(i))),
            )
        {
            let cpu_base = offset
                .map(|o| (base + o) as u32)
                .or_else(|| (base == BASE && expanded_index == Some(5)).then_some(0xdac000));
            let normal_at = |at: usize| (base == BASE).then_some(offset).flatten().map(|o| o + at);
            let native_data = |at: usize, len: usize| {
                normal_at(at).is_some_and(|a| covers(e.native_data, a, len))
            };
            let directory_data =
                |at: usize, len: usize| normal_at(at).is_some_and(|a| covers(e.directory, a, len));
            let scalar_data = |at: usize, len: usize| {
                normal_at(at).is_some_and(|a| {
                    e.tables
                        .is_some_and(|t| t.ranges.iter().any(|r| covers(r, a, len)))
                })
            };
            let scalar_directory = |at: usize, len: usize| {
                normal_at(at).is_some_and(|a| {
                    e.tables
                        .is_some_and(|t| t.directory_ranges.iter().any(|r| covers(r, a, len)))
                })
            };
            let writer = |at: usize, len: usize| {
                normal_at(at).is_some_and(|a| {
                    e.tables
                        .is_some_and(|t| t.map_writer_sites.iter().any(|r| covers(r, a, len)))
                })
            };
            for at in (offset.unwrap_or(0) % 2..bytes.len()).step_by(2) {
                let scalar_entry = scalar_data(at, 2);
                if !scalar_entry && cpu_base.is_some_and(|b| interior(b + at as u32)) {
                    continue;
                }
                let Ok(d) = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced) else {
                    continue;
                };
                // These have independently bound non-instruction representations.
                if !scalar_entry
                    && (native_data(at, d.len)
                        || directory_data(at, d.len)
                        || scalar_directory(at, d.len))
                {
                    continue;
                }
                for (i, operand) in d.insn.operands.into_iter().enumerate() {
                    // Scalar authority changes only the data-pointer view. Every
                    // aligned instruction view, including literal displacements,
                    // remains subject to the complete payload ownership check.
                    let ea_address = |ea| match ea {
                        Ea::Absolute { value, .. } => Some(value as usize),
                        Ea::Displacement {
                            value, bits: 32, ..
                        }
                        | Ea::Indexed {
                            value, bits: 32, ..
                        } => Some(value as u32 as usize),
                        Ea::PcRelative { value, .. } => cpu_base.and_then(|b| {
                            (b as usize + at + d.len).checked_add_signed(value as isize)
                        }),
                        _ => None,
                    };
                    let addresses = match operand {
                        Operand::Address(ea) => [ea_address(ea), None],
                        Operand::Immediate { value, bits: 32 } => [Some(value as usize), None],
                        Operand::IndexedMemory {
                            address,
                            value,
                            bits,
                            ..
                        } => [
                            ea_address(address),
                            (bits == 32).then_some(value as u32 as usize),
                        ],
                        _ => [None, None],
                    };
                    for address in addresses.into_iter().flatten() {
                        let control = matches!(
                            d.insn.mnemonic,
                            "JSR"
                                | "JMP"
                                | "BSR"
                                | "BRA"
                                | "BRN"
                                | "BHI"
                                | "BLS"
                                | "BCC"
                                | "BCS"
                                | "BNE"
                                | "BEQ"
                                | "BVC"
                                | "BVS"
                                | "BPL"
                                | "BMI"
                                | "BGE"
                                | "BLT"
                                | "BGT"
                                | "BLE"
                        );
                        let directory_read = normal_at(at)
                            .is_some_and(|a| covers(e.loader, a, d.len))
                            && address
                                .checked_sub(BASE)
                                .is_some_and(|a| e.directory.contains(&a));
                        let scalar_record = normal_at(at).is_some_and(|a| {
                            e.tables.is_some_and(|t| {
                                covers(&t.complete_code_bodies[0], a, d.len)
                                    && t.directory_ranges.iter().any(|r| BASE + r.start == address)
                            })
                        });
                        let map_read = matches!(operand, Operand::Address(_))
                            && d.insn.mnemonic == "MOV"
                            && i == 0;
                        if (!directory_read && owned(address))
                            || (table_target(address).is_some() && !control)
                            || (table_directory(address) && !scalar_record)
                            || (map_cell(address) && !map_read && !writer(at, d.len))
                        {
                            #[cfg(test)]
                            std::eprintln!("COMP typed base={base:x} offset={offset:?} expanded={expanded_index:?} at={at:x} target={address:x} {:?}",d.insn);
                            clear = false;
                        }
                    }
                }
            }
            for at in 0..bytes.len().saturating_sub(3) {
                let address = u32::from_be_bytes(bytes[at..at + 4].try_into().ok()?) as usize;
                let relevant = owned(address)
                    || table_target(address).is_some()
                    || table_directory(address)
                    || map_cell(address);
                if !relevant
                    || native_data(at, 4)
                    || cpu_base.is_some_and(|b| code_bytes(b + at as u32, 4))
                {
                    continue;
                }
                let array_slot = table_target(address).is_some_and(|index| {
                    normal_at(at).is_some_and(|a| {
                        e.tables.is_some_and(|t| {
                            t.pointer_slots[index] == a && BASE + t.ranges[index].start == address
                        })
                    })
                });
                let owned_metadata = directory_data(at, 4) || scalar_data(at, 4);
                if (owned(address) && !owned_metadata)
                    || (table_target(address).is_some() && !array_slot)
                    || table_directory(address)
                    || (map_cell(address) && !writer(at, 4))
                {
                    #[cfg(test)]
                    std::eprintln!("COMP raw base={base:x} offset={offset:?} expanded={expanded_index:?} at={at:x} target={address:x}");
                    clear = false;
                }
            }
        }
    }
    clear.then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use std::io::Write;
        let mut image = alloc::vec![255;0x200000];
        for (address, bytes) in [
            (
                0x57ae64,
                include_bytes!("native_comp/wrapper_and_inflate.bin").as_slice(),
            ),
            (
                0x57ccd0,
                include_bytes!("native_comp/fast_and_tables.bin").as_slice(),
            ),
            (
                0x57deae,
                include_bytes!("native_comp/shifts.bin").as_slice(),
            ),
            (
                0x57cc18,
                include_bytes!("native_comp/adler_combine.bin").as_slice(),
            ),
            (
                0x5abd02,
                include_bytes!("native_comp/constants.bin").as_slice(),
            ),
            (
                0x54b724,
                include_bytes!("native_comp/loader.bin").as_slice(),
            ),
        ] {
            image[address - BASE..address - BASE + bytes.len()].copy_from_slice(bytes);
        }
        image[0x1000..0x1004].copy_from_slice(b"COMP");
        let mut compressed = Vec::new();
        for i in 0..6 {
            let expanded = alloc::vec![i as u8;256];
            let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::none());
            enc.write_all(&expanded).unwrap();
            let original = enc.finish().unwrap();
            let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
            enc.write_all(&expanded).unwrap();
            let smaller = enc.finish().unwrap();
            let offset = 0x1d0000 + i * 512;
            image[offset..offset + 4].copy_from_slice(&256u32.to_be_bytes());
            image[offset + 4..offset + 4 + original.len()].copy_from_slice(&original);
            image[0x1004 + i * 8..0x1008 + i * 8]
                .copy_from_slice(&((BASE + offset) as u32).to_be_bytes());
            image[0x1008 + i * 8..0x100c + i * 8]
                .copy_from_slice(&((BASE + offset + original.len()) as u32).to_be_bytes());
            compressed.push((offset, original.len(), smaller));
        }
        let mut changed = image.clone();
        for (i, (offset, len, bytes)) in compressed.into_iter().enumerate() {
            changed[offset + 4..offset + 4 + bytes.len()].copy_from_slice(&bytes);
            changed[offset + 4 + bytes.len()..offset + 4 + len].fill(255);
            changed[0x1008 + i * 8..0x100c + i * 8]
                .copy_from_slice(&((BASE + offset + bytes.len()) as u32).to_be_bytes());
        }
        (image, alloc::vec![255;crate::image::KERNEL_LEN], changed)
    }
    #[test]
    fn original_prefix_payload_and_metadata_ownership() {
        let (image, kernel, changed) = synthetic();
        assert_eq!(prove(&image, &kernel, &changed).unwrap().tails.len(), 6);
        let mut bad = changed.clone();
        bad[0x800] ^= 1;
        assert!(prove(&image, &kernel, &bad).is_none());
        let mut external = image.clone();
        external[0x800..0x804].copy_from_slice(&0x5e0000u32.to_be_bytes());
        let mut external_changed = changed.clone();
        external_changed[0x800..0x804].copy_from_slice(&0x5e0000u32.to_be_bytes());
        assert!(prove(&external, &kernel, &external_changed).is_none());
        let mut resident = kernel;
        resident[0x800..0x804].copy_from_slice(&0x5e0008u32.to_be_bytes());
        assert!(prove(&image, &resident, &changed).is_none());
    }
    #[test]
    #[ignore = "requires paired native corpus and six recompressed streams"]
    fn actual_complete_comp_ownership() {
        let path = std::env::var("PIONEER_NATIVE_COMP_NORMAL").unwrap();
        let image = std::fs::read(&path).unwrap();
        let kernel = std::fs::read(path.replace(".bin", ".kernel.bin")).unwrap();
        let (_, streams) =
            crate::comp_streams::read(&image, crate::comp::MAX_TOTAL_EXPANDED, &mut || true)
                .unwrap()
                .unwrap();
        let mut changed = image.clone();
        for (i, stream) in streams.iter().enumerate() {
            if ![5].contains(&i) {
                continue;
            }
            let bytes = std::fs::read(format!(
                "{}/4596-stream-{i}.zlib",
                std::path::Path::new(&path).parent().unwrap().display()
            ))
            .unwrap();
            let start = stream.image_offset + 4;
            assert!(bytes.len() < stream.compressed_size);
            changed[start..start + bytes.len()].copy_from_slice(&bytes);
            changed[start + bytes.len()..start + stream.compressed_size].fill(255);
            changed[0x1008 + i * 8..0x100c + i * 8].copy_from_slice(
                &((BASE + stream.image_offset + bytes.len()) as u32).to_be_bytes(),
            );
        }
        assert!(prove(&image, &kernel, &changed).is_some());
        // Native scalar consumers still bind after changing numeric values.
        // That authority must never hide a real instruction-view payload edge.
        let scalar = comp_tables::observe(&image).unwrap().ranges[0].start;
        let target = (BASE + streams[5].image_offset + 4) as u32;
        use h8_asm::isa::{encode_insn, Insn, Reg, Size};
        for operand in [
            Operand::Immediate {
                value: target,
                bits: 32,
            },
            Operand::Address(Ea::Absolute {
                value: target,
                bits: 24,
            }),
            Operand::Address(Ea::Displacement {
                base: Reg::Long(1),
                value: target as i32,
                bits: 32,
            }),
        ] {
            let insn = if matches!(operand, Operand::Address(Ea::Absolute { .. })) {
                Insn::new("JSR", None, [operand, Operand::None, Operand::None])
            } else {
                Insn::new(
                    "MOV",
                    Some(Size::Long),
                    [operand, Operand::Register(Reg::Long(0)), Operand::None],
                )
            };
            let encoded = encode_insn(insn, Target::H8S2000, Mode::Advanced).unwrap();
            let mut bad_original = image.clone();
            let mut bad_changed = changed.clone();
            bad_original[scalar..scalar + encoded.len()].copy_from_slice(&encoded);
            bad_changed[scalar..scalar + encoded.len()].copy_from_slice(&encoded);
            assert!(comp_tables::observe(&bad_original).is_some());
            assert!(prove(&bad_original, &kernel, &bad_changed).is_none());
        }
    }
}
