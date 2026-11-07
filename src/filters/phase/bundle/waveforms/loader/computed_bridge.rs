//! Lower a complete computed donor loader into a plain target's DSP helper ABI.
//! Emission preserves the native arithmetic program; calibration, mode state,
//! opaque arithmetic semantics, and storage ownership remain caller obligations.
use super::*;
use crate::filters::phase::native;
use h8_asm::{
    isa::{decode_insn, encode_insn, Ea, Operand},
    Mode, Target,
};

/// Explicit target addresses for the computed program's non-DSP resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bindings {
    /// Caller-owned stored destination for the unscaled 72-byte donor basis.
    pub basis: u32,
    /// Adapted eight-mode calibration getter, preserving the donor contract.
    pub calibration: u32,
    /// Native signed multiply and divide primitives, respectively. The caller
    /// proves their register/stack/result semantics for the original arguments.
    pub arithmetic: [u32; 2],
    /// Adapted context provider, including initialized state and lifetime proof.
    pub mode_context: u32,
    /// Mode reader accepting that context and returning the donor mode domain.
    pub mode_reader: u32,
}
/// Contracts that emission itself cannot establish on the target platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirements {
    /// Complete observed source graph, including original calibration and mode
    /// state contracts and opaque arithmetic entries, for the owner to adapt.
    pub source: computed::Binding,
    /// Explicit destination roles whose semantics the owner must establish.
    pub bindings: Bindings,
    /// Existing target loader binding whose DSP helper ABI is retained.
    pub target: super::Binding,
}
/// Native code and raw data awaiting caller-owned placement. This is not a
/// complete-image patch or evidence that the outstanding contracts are met.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Emission {
    /// Complete logical instruction stream. Closed native branches permit the
    /// existing placement splitter to install it without changing the program.
    pub code: Vec<u8>,
    /// Raw signed basis bytes; never already-scaled coefficients.
    pub basis: [u8; 72],
    /// Remaining whole-mechanism obligations and selected target helper roles.
    pub requirements: Requirements,
    writer: writer::Binding,
    readback: readback::Binding,
}
fn stored(normal: &[u8], address: u32, length: usize) -> Result<Range<usize>, Error> {
    let at = address.checked_sub(0x410000).ok_or(Error::InvalidSpace)? as usize;
    let end = at.checked_add(length).ok_or(Error::InvalidSpace)?;
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    if address & 1 != 0
        || end > 0x1000000 - 0x410000
        || !regions.stored.iter().any(|r| {
            let start = r.as_ptr() as usize - normal.as_ptr() as usize;
            start <= at && end <= start + r.len()
        })
    {
        return Err(Error::InvalidSpace);
    }
    Ok(at..end)
}
fn closed_program(code: &[u8]) -> Result<(), Error> {
    let mut starts = Vec::new();
    let mut edges = Vec::new();
    let mut at = 0;
    while at < code.len() {
        let d = decode_insn(&code[at..], Target::H8S2000, Mode::Advanced)
            .map_err(|_| Error::ResourceMismatch)?;
        if d.len == 0
            || encode_insn(d.insn, Target::H8S2000, Mode::Advanced)
                .map_err(|_| Error::ResourceMismatch)?
                != code.get(at..at + d.len).ok_or(Error::ResourceMismatch)?
        {
            return Err(Error::ResourceMismatch);
        }
        starts.push(at);
        for op in d.insn.operands {
            if let Operand::Address(Ea::PcRelative { value, .. }) = op {
                edges.push(
                    (at + d.len)
                        .checked_add_signed(value as isize)
                        .ok_or(Error::ResourceMismatch)?,
                );
            }
        }
        at += d.len;
    }
    if edges.iter().any(|e| !starts.contains(e)) {
        return Err(Error::ResourceMismatch);
    }
    Ok(())
}
/// Emit the entire recognized computed donor program for a plain target.
/// Only declared helper and basis operands change. Saved registers, stack use,
/// signed scaling, clipping, fetch order, DSP addresses, and readback sequence
/// remain the donor's native instructions, including any proved compact fold.
///
/// The supplied helper addresses may refer to adapted bodies installed later.
/// This function verifies their address encodings, not their runtime contracts.
/// The returned requirements must be discharged before whole-image composition;
/// `verify_emitted` checks installed grammar but cannot prove opaque services.
pub fn emit(source: &[u8], target: &[u8], bindings: Bindings) -> Result<Emission, Error> {
    let source_binding = computed::observe(source)?;
    let (source_loader, shape, mut code) = super::bind(source)?;
    let before = super::observe(target)?;
    if before.computed {
        return Err(Error::ComputedUnsupported);
    }
    let writer = writer::observe(target, before.writer)?;
    let readback = readback::observe(target, before.readback, before.writer)?;
    let basis_range = stored(target, bindings.basis, 72)?;
    for helper in [
        bindings.calibration,
        bindings.mode_context,
        bindings.mode_reader,
    ] {
        stored(target, helper, 2)?;
    }
    for address in bindings.arithmetic {
        if address & 1 != 0
            || address < 0x100000
            || address as usize >= 0x410000 + target.len()
            || address > 0xfffffe
        {
            return Err(Error::ResourceMismatch);
        }
    }
    let getter = stored(target, before.coefficient_getter, 4)?;
    if [&writer.program, &readback.program, &getter]
        .into_iter()
        .chain(readback.clear.iter())
        .any(|r| r.start < basis_range.end && basis_range.start < r.end)
    {
        return Err(Error::InvalidSpace);
    }
    closed_program(&code)?;
    let mut call = 0;
    for field in shape.fields {
        let address = match field.kind {
            FieldKind::Call => {
                let address = match call {
                    0 | 1 => bindings.calibration,
                    2 | 3 | 7 => bindings.arithmetic[0],
                    4 | 5 | 8 | 9 => bindings.arithmetic[1],
                    6 | 10 => before.coefficient_getter,
                    11 => bindings.mode_context,
                    12 => bindings.mode_reader,
                    13 => before.readback,
                    _ => return Err(Error::ResourceMismatch),
                };
                call += 1;
                address
            }
            FieldKind::Data => bindings.basis,
            FieldKind::Literal if field.at == shape.writer => before.writer,
            // The source binder already checked this compact fold against its
            // calibration. Retaining it adds that same target-calibration
            // requirement; emission must not invent a replacement constant.
            FieldKind::Constant => continue,
            _ => return Err(Error::ResourceMismatch),
        };
        native::encoding::retarget_field(&mut code, field.at, field.width, address)
            .ok_or(Error::ResourceMismatch)?;
    }
    if call != 14 || !source_loader.computed {
        return Err(Error::ResourceMismatch);
    }
    closed_program(&code)?;
    let basis = source
        .get(source_binding.basis.clone())
        .ok_or(Error::ResourceMismatch)?
        .try_into()
        .map_err(|_| Error::ResourceMismatch)?;
    Ok(Emission {
        code,
        basis,
        requirements: Requirements {
            source: source_binding,
            bindings,
            target: before,
        },
        writer,
        readback,
    })
}
/// Observe the complete installed computed graph and verify every selected
/// helper address, the raw basis, logical instructions, and retained DSP ABI.
/// Calibration/mode grammar is observed from the installed bodies; equivalence
/// to donor state and opaque arithmetic remains the owner's separate proof.
/// No cached source bytes are used to classify unrecognized target instructions.
pub fn verify_emitted(image: &[u8], emission: &Emission) -> Result<computed::Binding, Error> {
    let actual = computed::observe(image)?;
    let expected = &emission.requirements;
    let bindings = expected.bindings;
    if actual.loader.loader != expected.source.loader.loader
        || actual.loader.coefficient_getter != expected.target.coefficient_getter
        || actual.loader.writer != expected.target.writer
        || actual.loader.readback != expected.target.readback
        || actual.loader.tables != Some([Table::Literal(bindings.basis); 2])
        || actual.arithmetic != bindings.arithmetic
        || 0x410000 + actual.calibration_program.start as u32 != bindings.calibration
        || 0x410000 + actual.mode_context.start as u32 != bindings.mode_context
        || 0x410000 + actual.mode_reader.start as u32 != bindings.mode_reader
        || image.get(actual.basis.clone()) != Some(emission.basis.as_slice())
        || super::logical_program(image)? != emission.code
        || writer::observe(image, actual.loader.writer)? != emission.writer
        || readback::observe(image, actual.loader.readback, actual.loader.writer)?
            != emission.readback
    {
        return Err(Error::VerificationFailed);
    }
    Ok(actual)
}

#[cfg(all(test, feature = "envelope"))]
mod tests {
    use super::*;
    fn fixture(hash: &str) -> Vec<u8> {
        let all: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/phase-native-spans.json"
        )))
        .unwrap();
        let f = all
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["original_sha256"] == hash)
            .unwrap();
        let mut image = alloc::vec![255; f["size"].as_u64().unwrap() as usize];
        let mut fill = |spans: &serde_json::Value| {
            for span in spans.as_array().unwrap() {
                let at = span[0].as_u64().unwrap() as usize;
                let h = span[1].as_str().unwrap();
                for i in 0..h.len() / 2 {
                    image[at + i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
                }
            }
        };
        fill(&f["spans"]);
        let basis: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/phase-computed-basis.json"
        )))
        .unwrap();
        if basis["original_sha256"] == hash {
            fill(&basis["spans"]);
        }
        image
    }
    const SOURCE: &str = "84b76c71728dd9c27d27c3cb974f062b55c59a7a26145c858dc45cc1a79db66a";
    const TARGET: &str = "87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1";
    #[test]
    fn complete_computed_program_installs_with_explicit_helper_roles() {
        let original = fixture(SOURCE);
        let target = fixture(TARGET);
        let kernel = alloc::vec![255; crate::image::KERNEL_LEN];
        let compact = computed::specialize_direction(&original, &target, &kernel).unwrap();
        for source in [&original, &compact] {
            let observed = computed::observe(source).unwrap();
            let bindings = Bindings {
                basis: 0x418000,
                calibration: 0x419000,
                arithmetic: observed.arithmetic,
                mode_context: 0x419400,
                mode_reader: 0x419800,
            };
            let emission = emit(source, &target, bindings).unwrap();
            assert_eq!(emission.basis.as_slice(), &source[observed.basis.clone()]);
            let (_, shape, source_code) = super::super::bind(source).unwrap();
            // Every non-address byte, including all stack/register/branch and
            // arithmetic instructions and compact constants, stays exact.
            for (at, (&a, &b)) in source_code.iter().zip(&emission.code).enumerate() {
                if !shape.fields.iter().any(|f| {
                    !matches!(f.kind, FieldKind::Constant) && (f.at..f.at + f.width).contains(&at)
                }) {
                    assert_eq!(a, b, "instruction byte {at}");
                }
            }
            let mut installed = target.clone();
            for (from, to) in [
                (&observed.calibration_program, bindings.calibration),
                (&observed.mode_context, bindings.mode_context),
                (&observed.mode_reader, bindings.mode_reader),
            ] {
                let at = (to - 0x410000) as usize;
                installed[at..at + from.len()].copy_from_slice(&source[from.clone()]);
            }
            let before = super::super::observe(&target).unwrap();
            for r in &before.spans {
                installed[r.clone()].fill(255);
            }
            let at = 0x1000;
            installed[at..at + emission.code.len()].copy_from_slice(&emission.code);
            installed[0x8000..0x8048].copy_from_slice(&emission.basis);
            let actual = verify_emitted(&installed, &emission)
                .expect("whole native computed graph with explicit source helper bodies");
            assert_eq!(actual.loader.writer, before.writer);
            assert_eq!(actual.loader.readback, before.readback);
            installed[0x8000] ^= 1;
            assert!(verify_emitted(&installed, &emission).is_err());
            installed[0x8000] ^= 1;
            installed[(before.writer - 0x410000) as usize + 90] ^= 1;
            assert!(verify_emitted(&installed, &emission).is_err());
        }
    }
    #[test]
    fn unbound_resources_and_wrong_direction_of_transfer_are_rejected() {
        let source = fixture(SOURCE);
        let target = fixture(TARGET);
        let observed = computed::observe(&source).unwrap();
        let bindings = Bindings {
            basis: 0x418000,
            calibration: 0x419000,
            arithmetic: observed.arithmetic,
            mode_context: 0x419400,
            mode_reader: 0x419800,
        };
        assert!(emit(&source, &source, bindings).is_err());
        assert!(emit(&target, &target, bindings).is_err());
        assert!(emit(
            &source,
            &target,
            Bindings {
                basis: 0x418001,
                ..bindings
            }
        )
        .is_err());
        assert!(emit(
            &source,
            &target,
            Bindings {
                arithmetic: [1, 2],
                ..bindings
            }
        )
        .is_err());
        let mut broken = source;
        broken[observed.loader.program.start + 126] ^= 1;
        assert!(emit(&broken, &target, bindings).is_err());
    }
}
