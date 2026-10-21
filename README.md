# pioneer-optical

[![CI](https://github.com/MattJackson/pioneer-optical/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MattJackson/pioneer-optical/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/pioneer-optical.svg)](https://crates.io/crates/pioneer-optical)
[![docs.rs](https://img.shields.io/docsrs/pioneer-optical)](https://docs.rs/pioneer-optical)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)

A Rust library for working with **Pioneer BD/DVD optical drives** and their
firmware. It encodes vendor SCSI commands, decodes drive responses, inspects
firmware images, and prepares and executes receiver-bound firmware updates.

Use it to build drive utilities, firmware inspection tools, backup workflows,
or update applications. You provide the operating-system SCSI transport; the
library supplies protocol logic and typed results.

Its sister library, [`mediatek-optical`](https://github.com/MattJackson/mediatek-optical),
uses the same transport conventions and development workflow. See the
[sibling API map](docs/sibling-api.md) when moving between them. Both have a
**dependency-free `no_std` core**, an allocation-free `drive` feature, optional
firmware analysis, and typed update preparation and verification.

## Install

```toml
[dependencies]
pioneer-optical = { version = "1.0", features = ["drive"] }
```

Rust **1.75 or newer** is required. The default build has no enabled features.
Enable `drive` for live commands, or select the analysis features below for
working with files without connecting a drive.

## Identify a drive

Pass an existing transport to `drive::identify`. This example reads identity
without entering update mode or changing settings:

```rust,no_run
use pioneer_optical::{drive, Identity};

pub fn identify<T: drive::Transport>(
    transport: &mut T,
) -> Result<Identity, drive::Error<T::Error>> {
    let identity = drive::identify(transport)?;
    println!("{} {} {}", identity.vendor(), identity.product(), identity.revision());
    Ok(identity)
}
```

Implement `drive::Transport` for your SCSI pass-through adapter. Its `exec`
method receives the command bytes and a `drive::Data` value describing the data
phase, then returns the actual transferred byte count. `sense` exposes the
most recent failed command's sense triplet. Preserve `Data::None`, `Data::In`
and `Data::Out` exactly, including zero-length data-out commands. Do not retry
firmware writes automatically.

The library handles command construction and bounded transfers. Your application
opens the device, supplies timeouts and exclusive access, and persists backups.
`drive::read_memory` reads into a caller-owned buffer; firmware-derived layouts
and protocol bounds determine which addresses are meaningful.

## Choose features

| Feature | Use it for | Environment |
| --- | --- | --- |
| none | `cdb`, `Identity`, controller types and protocol constants | `no_std`, no allocation |
| `drive` | Identification, reads and command sequences over `Transport` | `no_std`, no allocation |
| `image` | Decoded firmware families, ABI and startup requirements | `std` |
| `envelope` | Load, decode, repack, build and sign envelopes; prepare updates | `std`; includes `image` |
| `analysis` | Bounded single-envelope region and metadata analysis | `std`; includes `envelope` |
| `firmware-info` | H8 memory layout, callback and ABI inspection | `std`; includes `image` |
| `std` | Standard-library error integration without firmware features | `std` |

`drive` also provides `device::Device` for typed live information and settings.
Unknown wire values and unavailable capabilities remain explicit; setters
read support, validate, write once and read back. See the
[protocol guide](docs/protocol-guide.md) for settings and persistence behavior.

## Inspect firmware files

Enable `envelope`. Loading recognizes the file's framing and decodes its payload:

```rust,no_run
use pioneer_optical::envelope::{DecodeError, Envelope};

pub fn inspect(bytes: &[u8]) -> Result<(), DecodeError> {
    let envelope = Envelope::load(bytes)?;
    let info = envelope.info();
    println!("{} {}: {}", info.model, info.revision, info.kind);
    Ok(())
}
```

For a Normal whose decode needs Kernel evidence, use
`Envelope::load_with_kernel`. Successful loading establishes file-format facts;
it does not establish drive compatibility. `envelope::Update::load` checks a
Kernel/Normal pair. Firmware analysis reports unsupported or ambiguous patterns
explicitly rather than guessing a model-specific address.

## Prepare and execute an update

Enable `drive` and `envelope`. Use the captured **installed** Kernel/Normal pair
as receiver evidence, then prepare the target separately:

```rust,no_run
use pioneer_optical::{envelope::Update, receiver::Receiver};

pub fn prepare(
    current_kernel: &[u8], current_normal: &[u8],
    target_kernel: &[u8], target_normal: &[u8],
) -> Result<pioneer_optical::receiver::PreparedUpdate, Box<dyn std::error::Error>> {
    let installed = Update::load(current_kernel, current_normal)?;
    let receiver = Receiver::from_installed(&installed)?;
    let target = Update::load(target_kernel, target_normal)?;
    Ok(receiver.prepare(target)?)
}
```

Preparation performs no device I/O. `PreparedUpdate::flash` rebinds the live
receiver, migrates required startup settings, transfers each required pass,
restores a temporary Kernel when needed, and confirms target startup and Kernel
readback. `prepare_normal` supports a Normal-only update.

`PreparedUpdate::flash` requires complete Kernel and Normal readback.
`flash_completed` returns a `FlashOutcome` with target-startup evidence and
explicit readback flags; `normal_verified == false` means limited verification.
Every readable mismatch fails through both methods. A successful return requires
target-specific startup, not merely readiness. `execute(..., ExecutionMode::Recovery)` is the explicit
recovery path.

[examples/flash.rs](examples/flash.rs) provides a compiled host integration with
`ExecutionRuntime` and `FlashTransport`. Its executable does not access hardware.
Low-level `drive::Session` and methods ending in `_unchecked` are protocol
primitives and do not supply the complete update procedure.

Before execution, the host must capture a backup, obtain the required consent,
check tray conditions, and ensure both transports address the same physical
drive exclusively. Interrupted or incompatible firmware writes can make a drive
unusable. No hardware writes are performed by the examples or test suite.

## Handle errors

Import `pioneer_optical::CodedError` for stable machine-readable identifiers:

```rust
use pioneer_optical::CodedError;
use pioneer_optical::drive::Error;

let error = Error::<()>::Short { expected: 36, actual: 8 };
assert_eq!(error.code(), "pioneer.drive.short");
```

Use codes for translation or routing, match typed variants for parameters, and
preserve nested causes in diagnostics. English `Display` wording is not a
parsing contract. Handle unknown future codes and non-exhaustive enums.

## Develop and test

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo test --locked --doc --all-features
python3 .github/scripts/check-features.py test
python3 .github/scripts/check-features.py doc
```

The Python checks require Python 3.11+. CI exercises every distinct feature
configuration, Rust 1.75 library builds, bare-metal `no_std`, doctests and packaged
sources before publication. README Rust examples are compiled by doctests with
their required features enabled.

Firmware corpus tests require external, hash-pinned files; skipped or unavailable
inputs are not counted as passes. See [tests/OEM_FACTS.md](tests/OEM_FACTS.md), the
[protocol guide](docs/protocol-guide.md), and [release audit](RELEASE.md) for
reproduction and evidence limits. Simulated transports and offline firmware
analysis do not certify physical programming or power-loss recovery.

## License

MIT. See [LICENSE-MIT](LICENSE-MIT).
