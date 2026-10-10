use super::*;
use crate::envelope::builder::KernelKeySource;
use crate::envelope::Layout;

const NAME: &str = "PIONEER BD-RW   BDR-205";
const PROGRAM: Range<usize> = 0x2000..0x3000;
/// A single unwritten byte inside program data: too short to be called fill.
const GAP: usize = 0x2800;

fn general() -> KernelIdentity<'static> {
    KernelIdentity {
        drive_name: NAME,
        hardware: "SAT 1014",
        kernel_tag: "GENERAL",
        kernel_version2: "0000",
    }
}

fn id52() -> KernelIdentity<'static> {
    KernelIdentity {
        kernel_tag: "ID52",
        ..general()
    }
}

/// An OEM-shaped Kernel: positional fill from `seed`, then program bytes,
/// receiver dispatcher, identity block, drive name and checksum written over it.
fn oem_kernel(seed: u32, name: &str, tag: &str) -> Vec<u8> {
    let mut k = fill_stream(seed, KERNEL_LEN);
    k[0x40..0x48].copy_from_slice(&[0xae, 0xfe, 0, 0, 0, 0, 0xae, 0xf0]);
    for (i, p) in PROGRAM.enumerate() {
        if p != GAP {
            k[p] = (i * 7 + 3) as u8;
        }
    }
    k[IDENTITY].copy_from_slice(b"SAT 1014        0000");
    k[KERNEL_TAG][..tag.len()].copy_from_slice(tag.as_bytes());
    k[0x4de0..0x4de0 + DRIVE_NAME_LEN].copy_from_slice(&drive_name_field(name).unwrap());
    k[CHECKSUM].fill(0);
    let fix = 0u32.wrapping_sub(be32_sum(&k));
    k[CHECKSUM].copy_from_slice(&fix.to_be_bytes());
    k
}

fn content_eq(a: &[u8], an: &str, b: &[u8], bn: &str) -> bool {
    kernel_image_equality(a, an, b, bn).unwrap()
}

#[test]
fn fill_seed_is_recovered_from_an_oem_build() {
    assert_eq!(
        kernel_fill_seed(&oem_kernel(0x6123fa, NAME, "GENERAL")),
        Some(0x6123fa)
    );
    assert_eq!(kernel_fill_seed(&vec![0; KERNEL_LEN]), None);
}

#[test]
fn erased_padding_kernels_compare_without_a_fill_stream() {
    let mut a = vec![0xffu8; KERNEL_LEN];
    for (i, p) in PROGRAM.enumerate() {
        a[p] = (i * 7 + 3) as u8;
    }
    a[IDENTITY].copy_from_slice(b"SAT 9400ID15    0000");
    a[CHECKSUM].fill(0);
    let mut b = a.clone();
    b[KERNEL_TAG][..4].copy_from_slice(b"ID56");
    b[CHECKSUM].copy_from_slice(&[1, 2, 3, 4]);
    assert_eq!(kernel_fill_seed(&a), None);
    assert_eq!(kernel_image_equality(&a, NAME, &b, NAME), Some(true));
    b[PROGRAM.start] ^= 1;
    assert_eq!(kernel_image_equality(&a, NAME, &b, NAME), Some(false));
    // Without the SAT identity block nothing outside the drive name is masked.
    let mut c = a.clone();
    c[HARDWARE].copy_from_slice(b"ATA 0007");
    let mut d = c.clone();
    d[KERNEL_TAG][..4].copy_from_slice(b"ID56");
    assert_eq!(kernel_image_equality(&c, NAME, &d, NAME), Some(false));
}

#[test]
fn legacy_sized_kernels_compare_as_raw_bytes_minus_drive_name() {
    // Smaller legacy little-endian DVR layout: identity is the header, not the
    // body, so no SAT identity/checksum masking applies.
    const LEGACY: usize = 0x5000;
    let pio = "PIONEER DVD-RW  DVR-107D";
    let asus = "ASUS    DRW-0804P";
    let mut a = vec![0u8; LEGACY];
    for (i, b) in a.iter_mut().enumerate() {
        *b = (i * 13 + 7) as u8;
    }
    a[0x900..0x900 + DRIVE_NAME_LEN].copy_from_slice(&drive_name_field(pio).unwrap());
    let mut b = a.clone();
    // Same program, rebranded ASUS: differs only in the drive-name field.
    b[0x900..0x900 + DRIVE_NAME_LEN].copy_from_slice(&drive_name_field(asus).unwrap());
    assert_eq!(kernel_fill_seed(&a), None);
    assert_eq!(kernel_image_equality(&a, pio, &b, asus), Some(true));
    // A real program-byte change is still seen.
    b[0x40] ^= 1;
    assert_eq!(kernel_image_equality(&a, pio, &b, asus), Some(false));
    // Different decoded length => different program.
    assert_eq!(
        kernel_image_equality(&a, NAME, &a[..LEGACY - 4], NAME),
        Some(false)
    );
    // Too small to be a Kernel body.
    assert_eq!(kernel_image_equality(&a[..16], NAME, &a, NAME), None);
}

#[test]
fn clone_rewrites_identity_and_marks_fill_with_seed_zero() {
    let source = oem_kernel(0x6123fa, NAME, "GENERAL");
    let clone = clone_kernel_image(&source, NAME, &id52()).unwrap();
    assert_eq!(&clone[KERNEL_TAG], b"ID52    ");
    assert_eq!(&clone[HARDWARE], b"SAT 1014");
    assert_eq!(be32_sum(&clone), 0);
    assert_eq!(kernel_fill_seed(&clone), Some(0));
    assert_eq!(&clone[PROGRAM.start..GAP], &source[PROGRAM.start..GAP]);
    // A lone unwritten byte cannot be told from code, so it is kept.
    assert_eq!(clone[GAP], source[GAP]);
    assert!(content_eq(&source, NAME, &clone, NAME));
}

#[test]
fn builds_differing_only_in_fill_and_identity_share_content() {
    let pioneer = oem_kernel(0x6123fa, NAME, "GENERAL");
    let plextor_name = "PLEXTOR BD-R   PX-B940SA";
    let plextor = oem_kernel(0x382ad6, plextor_name, "ID17");
    assert!(content_eq(&pioneer, NAME, &plextor, plextor_name));
    let mut changed = plextor.clone();
    changed[PROGRAM.start + 1] ^= 1;
    assert!(!content_eq(&pioneer, NAME, &changed, plextor_name));
}

#[test]
fn clone_replaces_the_drive_name() {
    let source = oem_kernel(0x6123fa, NAME, "GENERAL");
    let to = KernelIdentity {
        drive_name: "PLEXTOR BD-R   PX-B940SA",
        kernel_tag: "ID17",
        ..general()
    };
    let clone = clone_kernel_image(&source, NAME, &to).unwrap();
    assert_eq!(
        &clone[0x4de0..0x4de0 + DRIVE_NAME_LEN],
        b"PLEXTOR BD-R   PX-B940SA"
    );
    assert!(occurrences(&clone, &drive_name_field(NAME).unwrap()).is_empty());
}

#[test]
fn clone_rejects_inputs_it_cannot_explain() {
    let source = oem_kernel(0x6123fa, NAME, "GENERAL");
    let err = |image: &[u8], from: &str, to: &KernelIdentity<'_>| {
        clone_kernel_image(image, from, to).unwrap_err()
    };
    assert_eq!(
        err(&source[..0x8000], NAME, &id52()),
        Error::KernelStructure
    );
    let mut unbalanced = source.clone();
    unbalanced[PROGRAM.start] ^= 1;
    assert_eq!(err(&unbalanced, NAME, &id52()), Error::KernelStructure);
    assert_eq!(
        err(&source, "PIONEER BD-RW   BDR-206", &id52()),
        Error::DriveNameNotFound
    );
    assert_eq!(err(&source, "PIONEER", &id52()), Error::MissingModel);
    let long_tag = KernelIdentity {
        kernel_tag: "ID52LONGER",
        ..general()
    };
    assert_eq!(err(&source, NAME, &long_tag), Error::KernelIncomplete);
    let bad_hw = KernelIdentity {
        hardware: "ATA 1014",
        ..general()
    };
    assert_eq!(err(&source, NAME, &bad_hw), Error::KernelIncomplete);
    let mut no_fill = source.clone();
    for (p, b) in no_fill.iter_mut().enumerate() {
        if !(PROGRAM.contains(&p)
            || IDENTITY.contains(&p)
            || (0x40..0x48).contains(&p)
            || (0x4de0..0x4de0 + DRIVE_NAME_LEN).contains(&p))
        {
            *b = 0;
        }
    }
    no_fill[CHECKSUM].fill(0);
    let fix = 0u32.wrapping_sub(be32_sum(&no_fill));
    no_fill[CHECKSUM].copy_from_slice(&fix.to_be_bytes());
    assert_eq!(err(&no_fill, NAME, &id52()), Error::KernelFillNotFound);
}

#[test]
fn clone_kernel_envelope_round_trips_with_the_requested_key() {
    let source = oem_kernel(0x6123fa, NAME, "GENERAL");
    assert_eq!(kernel_layout_from_image(&source), Some(Layout::KernelFront));
    let envelope =
        encode_kernel_envelope(&source, NAME, &KernelBuild::from_seed(0x123456)).unwrap();
    let build = KernelBuild {
        revision: "0000",
        date: "00/00/00",
        key: KernelKeySource::Seed(0x47d001),
    };
    let clone = clone_kernel(&envelope, &id52(), &build).unwrap();
    let decoded = decode_envelope(&clone).unwrap();
    let header = decoded.header().unwrap();
    assert_eq!(header.kernel_version, "ID52");
    assert_eq!(header.hardware_version, "SAT 1014");
    assert_eq!(header.id, NAME);
    assert_eq!(decoded.encoding_seed(), Some(0x47d001));
    assert_eq!(kernel_fill_seed(&decoded.image), Some(0));
    assert!(content_eq(&source, NAME, &decoded.image, NAME));
    assert_eq!(kernel_equality(&envelope, &clone), Some(true));
    let mut other = source.clone();
    other[PROGRAM.start] ^= 1;
    other[PROGRAM.start + 1] ^= 1;
    let other = encode_kernel_envelope(&other, NAME, &KernelBuild::from_seed(0x123456));
    assert!(
        other.is_err(),
        "changed program without checksum fix is rejected"
    );
    assert_eq!(kernel_equality(&envelope, b"not an envelope"), None);
    assert_eq!(
        kernel_image_equality(&source[..16], NAME, &source, NAME),
        None
    );
    assert_eq!(
        clone_kernel(b"not an envelope", &id52(), &build).unwrap_err(),
        Error::KernelUndecodable
    );
}

/// `PIONEER_KERNEL_CLONE_FIXTURE` names an OEM Kernel envelope.
#[test]
fn oem_kernel_clones_to_same_content_when_configured() {
    let Ok(path) = std::env::var("PIONEER_KERNEL_CLONE_FIXTURE") else {
        return;
    };
    let source = std::fs::read(path).unwrap();
    let decoded = decode_envelope(&source).unwrap();
    let header = decoded.header().unwrap();
    assert!(kernel_fill_seed(&decoded.image).is_some_and(|seed| seed != 0));
    let to = KernelIdentity {
        drive_name: &header.id,
        hardware: &header.hardware_version,
        kernel_tag: "ID52",
        kernel_version2: &header.kernel_version2,
    };
    let clone = clone_kernel(&source, &to, &KernelBuild::from_seed(0x47d001)).unwrap();
    let image = decode_envelope(&clone).unwrap().image;
    assert_eq!(kernel_fill_seed(&image), Some(0));
    assert!(content_eq(&decoded.image, &header.id, &image, &header.id));
}
