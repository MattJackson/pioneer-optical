use super::*;

pub(crate) fn fixture(kernel: &mut [u8]) {
    // Synthetic warm entry at 0x20, a RAM-copy descriptor, and the programmer's
    // interrupt-mask/restart epilogue. No real firmware is embedded.
    kernel[0x20..0x30].copy_from_slice(&[
        1, 0, 0x6d, 0xf3, 1, 0, 0x6d, 0xf4, 0x7a, 7, 0, 0, 0x80, 0, 4, 0x80,
    ]);
    kernel[0x2000..0x2016].copy_from_slice(&[
        0x7a, 0, 0, 0x40, 0x21, 0, 0x7a, 1, 0, 0x40, 0x21, 0x10, 0x7a, 2, 0, 0, 0x28, 0, 0x5e,
        0x40, 0x30, 0,
    ]);
    kernel[0x2100..0x2108].copy_from_slice(&[0xf9, 0x80, 3, 9, 0x5e, 0x40, 0, 0x20]);
}

#[test]
fn extracts_operands_and_checks_direction() {
    let mut a = vec![0; KERNEL_LEN];
    fixture(&mut a);
    assert_eq!(kernel_startup_entry(&a), Some(0x400020));
    assert_eq!(kernel_handoff_entry(&a), Some(0x400020));
    assert_eq!(check_kernel_handoff(&a, &a), Ok(()));
    let mut b = a.clone();
    b.copy_within(0x20..0x30, 0x2a);
    b[0x20..0x2a].fill(0);
    assert_eq!(kernel_startup_entry(&b), Some(0x40002a));
    assert_eq!(
        check_kernel_handoff(&a, &b),
        Err(KernelHandoffError::Mismatch {
            installed: 0x400020,
            target: 0x40002a
        })
    );
    // The incoming image's own updater operand is an independent fact.
    assert_eq!(check_kernel_handoff(&b, &a), Ok(()));
}

#[test]
fn missing_ambiguous_or_unbound_signatures_refuse() {
    let mut a = vec![0; KERNEL_LEN];
    fixture(&mut a);
    let empty = vec![0; KERNEL_LEN];
    assert_eq!(
        check_kernel_handoff(&empty, &a),
        Err(KernelHandoffError::UnknownInstalled)
    );
    assert_eq!(
        check_kernel_handoff(&a, &empty),
        Err(KernelHandoffError::UnknownTarget)
    );
    let mut bad = a.clone();
    bad[0x2000] = 0;
    assert_eq!(kernel_handoff_entry(&bad), None); // naked restart bytes do not count
    let mut bad = a.clone();
    bad[0x200e..0x2012].copy_from_slice(&0xffffu32.to_be_bytes());
    assert_eq!(kernel_handoff_entry(&bad), None); // RAM copy exceeds RAM
    let mut bad = a.clone();
    bad.copy_within(0x20..0x30, 0x60);
    assert_eq!(kernel_startup_entry(&bad), None);
    let mut bad = a.clone();
    bad[0x2108..0x2110].copy_from_slice(&[0xf9, 0x80, 3, 9, 0x5e, 0x40, 0, 0x2a]);
    assert_eq!(kernel_handoff_entry(&bad), None);
    assert_eq!(kernel_startup_entry(&a[..100]), None);
}

#[test]
fn newer_startup_and_service_epilogue() {
    let mut a = vec![0; KERNEL_LEN];
    fixture(&mut a);
    a[0x20..0x30].fill(0);
    a[0x100..0x108].copy_from_slice(STATE_CLEAR);
    a[0x108..0x118].copy_from_slice(&[
        1, 0, 0x6d, 0xf3, 1, 0x20, 0x6d, 0xf4, 0x7a, 7, 0, 0, 0x80, 0, 4, 0x80,
    ]);
    a[0x2100..0x210c]
        .copy_from_slice(&[0xfa, 0x80, 3, 0xa, 0xf8, 0x2a, 0x5d, 0x60, 0x5e, 0x40, 1, 0]);
    assert_eq!(kernel_startup_entry(&a), Some(0x400100));
    assert_eq!(check_kernel_handoff(&a, &a), Ok(()));
    a[0x2106] = 0;
    assert_eq!(kernel_handoff_entry(&a), None);
}

#[test]
fn decoded_corpus_signatures_when_configured() {
    let Ok(root) = std::env::var("PIONEER_DECODED_KERNEL_CORPUS") else {
        return;
    };
    let (mut known, mut unknown) = (0, 0);
    for path in std::fs::read_dir(root).unwrap() {
        let path = path.unwrap().path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("bin") {
            continue;
        }
        let body = std::fs::read(&path).unwrap();
        match (kernel_handoff_entry(&body), kernel_startup_entry(&body)) {
            (Some(a), Some(b)) => {
                assert_eq!(a, b, "self-update handoff mismatch: {}", path.display());
                assert_eq!(check_kernel_handoff(&body, &body), Ok(()));
                known += 1;
            }
            _ => {
                assert!(check_kernel_handoff(&body, &body).is_err());
                unknown += 1;
            }
        }
    }
    assert!(known > 0);
    eprintln!("Kernel handoff corpus: {known} recognized, {unknown} refused as unknown");
}
