# Changelog

All notable changes to `pioneer-optical` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.9.0] - 2026-10-04

### Added
- Feature `envelope`: the firmware envelope codec. `header_info`,
  `decode_envelope`, `decode_envelope_with_kernel`, `DecodedEnvelope::repack`,
  COMP stream parsing and rebuild, `downgrade_patch`; `envelope::signature`
  (Normal signature verification and signing); `envelope::builder` (Kernel and
  Normal envelope construction from decoded images). Requires `std`.
- `ComponentKind` (`Kernel`/`Normal`/`Plane`) with `From<Role>`; replaces the
  `file_type` strings and `envelope_role`, which is removed.
- `envelope::Layout` enum replaces the `layout` strings.
- `envelope::Error` (with `Display` and `std::error::Error`) replaces
  `&'static str` errors in `builder` and `signature`.
- `DecodedEnvelope::{family, is_uhd, required_abi, provided_abi, role}`.
- Feature `std`; `envelope` implies `image` and `std`.

- `HeaderInfo::targets(&Identity)` and `DecodedEnvelope::targets`;
  `EnvelopeInfo` carries `hardware_version` and `kernel_version`.
- `Debug` on all public types (`SigningKey` is redacted), `Default` for
  `HeaderOpaque`; `#[non_exhaustive]` on enums and output structs.

### Changed
- `KernelLayout` is removed; `kernel_layout_from_image` returns `Layout`, and
  `validate_encrypted_pair` derives the layout (no `kernel_layout` parameter).
- `DowngradePatchError` is folded into `envelope::Error`;
  `KERNEL_CHECKSUM_COMPENSATION` is removed (the delta depends on the marker).
- `DecodedEnvelope::info` is private: use `info()`. `file_type` fields are
  renamed `kind`. `ComponentKind` serializes in kebab-case.
- `encode_encrypted_pair` rejects a Normal whose required ABI the Kernel does
  not provide (`Error::AbiMismatch`). `image` bounds each inflate by the declared
  size. `Error::NotAscii` now rejects non-ASCII UTF-8.
- `PioneerInfo`, `PioneerHeaderInfo`, `PioneerHeaderOpaque` become
  `EnvelopeInfo`, `HeaderInfo`, `HeaderOpaque`. `HeaderInfo::file_type` is
  `Option<ComponentKind>`.
- `image` and `envelope` share one COMP directory parser (at most 16 address
  pairs) and one `miniz_oxide` 0.9.

## [0.8.0] - 2026-10-04

One domain model across the crate. Breaking.

### Changed
- CDB constructors and constants move to `cdb`. `transfer_kernel` /
  `transfer_normal` become `cdb::transfer(Role, off, len)`; the DVR handshake
  CDBs are `cdb::dvr_arm` / `dvr_challenge` / `dvr_response`.
- `response::Inquiry`, `response::VendorIdentity` and `flash::Identity` merge
  into the root `Identity` (`Identity::parse(inquiry, vendor)`). `class()`
  returns `Option<DriveClass>`.
- `kernel_mode` becomes `dvr`; `dvr::solve` returns the response payload.
- Feature `highlevel` becomes `drive`; modules `transport` and `flash` merge
  into `drive`. `Transport::exec` takes a `Data` (`None` / `In` / `Out`).
  `FlashError` becomes `drive::Error`, adding `Oversize`, `Challenge` and
  `UnknownClass`.
- `drive::enter_update(t, class, control)` takes the control buffer and returns
  a `Session` with `write(Role, off, data)` and `finish()`. Dropping a session
  sends nothing.
- `drive::read_memory(t, off, buf)` reads `buf.len()` bytes.
- Feature `fw` becomes `image`; module `fw` becomes `image`. `get_family`
  becomes `family`, returning `Family`. `AbiRequired` / `AbiProvided` merge
  into `Abi` (`required_abi`, `provided_abi`, `Abi::is_satisfied_by`,
  `Abi::missing_from`). Results are unchanged.
- `drive` no longer allocates.

### Removed
- `fw::profile` / `Profile`, `fw::abi_compatible`, `fw::get_abi_match`,
  `flash::vendor_identity`, `KERNEL_END`, and the deprecated root handshake
  constructors.

[0.8.0]: https://github.com/MattJackson/pioneer-optical/releases/tag/v0.8.0

## [0.7.1] - 2026-10-04

### Added
- `fw::abi_required`, `fw::abi_provided`, `fw::abi_compatible`, `fw::get_abi_match`
  (plus `AbiRequired` / `AbiProvided`, `AbiRequired::missing_from`, `KERNEL_BASE`,
  `KERNEL_END`): a deterministic Normal<->Kernel ABI test on envelope-decoded
  bodies, behind the existing `fw` feature. `AbiRequired` is the set of Kernel
  entry addresses (`0x400000..=0x40FFFF`) a Normal calls via `JSR/JMP @aa:24`,
  found by an instruction-synchronised H8S/2000 sweep (a call is accepted only
  after 128 consecutive well-formed instructions, which rejects data lookalikes).
  `AbiProvided` is the set of callable entry addresses of a 64 KiB Kernel.
  Compatible iff required is a subset of provided; each set also carries an
  FNV-1a id. Validated over 506 distinct 8xxx/9xxx bodies (383 Normals x 122
  Kernels): 10 distinct required sets, three disjoint ABI generations, zero
  incompatibility inside any shipped bundle, and no cross-generation pair is
  compatible. Informational only; no existing API changes.

[0.7.1]: https://github.com/MattJackson/pioneer-optical/releases/tag/v0.7.1

## [0.7.0] - 2026-10-04

### Added
- New non-default `highlevel` cargo feature exposing a drive-generic flash
  API so a flasher can drive a Pioneer unit with zero knowledge of raw SCSI
  CDBs. Two new modules:
  - `transport` — a `Transport` trait (plus `TransferDir`) that the flasher
    implements once over its OS pass-through (SG_IO / SPTI / libusb / mock);
  - `flash` — `Drive::identify`, `Identity` + `DriveClass`,
    `enter_kernel_mode`, `KernelSession` (`write_kernel` / `write_normal` /
    `finish`), `read_memory` and `vendor_identity`. Internally these call the
    existing public CDB constructors; the raw catalogue is unchanged.
- `flash::enter_kernel_mode` performs the DVR F3/F2/F2 LCG handshake
  (real CDBs, real seed recovery via `kernel_mode::solve`, real inverted-LCG
  response byte) before `3B 04 FF` on `DriveClass::Dvr`, and issues
  `3B 04 FF` alone on `DriveClass::Bd`. The DVR path is complete and
  executable but **experimental — not yet verified on hardware**.
- `FlashError` promotes the drive's `05/24/00` sense refusal to
  `FlashError::Locked` so callers can distinguish "locked / wrong state /
  unsupported on this platform" from transport errors.
- Unit tests with an in-memory mock `Transport` assert the exact CDB sequence
  (and payload bytes) for BD enter, BD write_kernel/write_normal/finish, the
  full DVR F3→F2 read→F2 write (with the computed response byte)→04/FF
  handshake, and the knock-then-read `read_memory` sequence.
- The `highlevel` feature pulls in `alloc`. The default build remains
  `no_std`, allocation-free and dependency-free.

### Changed
- Rewrote the `kernel_mode` module docs and the crate-level "privilege"
  overview to reflect reality: "kernel mode" throughout this crate is the
  OEM update session entered by `3B 04 FF` (not the F3/F2 handshake). On BD
  firmware the F3/F2 CDBs are inert — handlers are phase-gated, set a single
  RAM flag, call no LCG — a conclusion from direct disassembly of the
  BDR-UD04 / `SAT 8A10` Normal body. The handshake math is retained for the
  DVR path used by `flash::enter_kernel_mode`.

### Deprecated
- The three raw DVR-handshake CDB constructors `kernel_mode_arm`,
  `kernel_mode_challenge` and `kernel_mode_response` are now
  `#[deprecated]` with a pointer to `flash::enter_kernel_mode`. They remain
  callable (and byte-exact) for anyone still issuing CDBs by hand.

[0.7.0]: https://github.com/MattJackson/pioneer-optical/releases/tag/v0.7.0

## [0.6.0] - 2026-10-04

### Added
- Optional `fw` module (non-default `fw` feature): firmware-body analysis over
  envelope-decoded Pioneer bodies — `fw::get_family` (deterministic crossflash
  family id), `fw::is_uhd` (UHD capability signature test) and `fw::profile`
  (reported laser/asic/pins/board/servo/flash components). Faithful Rust port of
  the reverse-engineered `hw_id.py`, validated to reproduce its partition over
  441 corpus images (18 families, KAT 13/13, 0 UHD mismatches).
- The `fw` feature pulls in `alloc` and `miniz_oxide` (zlib inflate for COMP
  streams). The default build remains `no_std`, allocation-free and dependency-free.

[0.6.0]: https://github.com/MattJackson/pioneer-optical/releases/tag/v0.6.0

## [0.5.0] - 2026-10-04

Initial release.

### Added
- Named, documented CDB constructors for the Pioneer optical-drive vendor
  command set: `vendor_identity`, `read_memory`, `knock` (read unlock),
  `enter_update` / `transfer_kernel` / `transfer_normal` / `finish` (OEM update
  sequence), `kernel_mode_arm` / `kernel_mode_challenge` / `kernel_mode_response`
  (write unlock), and `inquiry` / `test_unit_ready` / `get_event_status`.
- Field constants for every opcode, mode, buffer-id and length.
- Byte-exact catalogue test.
- `#![no_std]`, allocation-free, unsafe-free, zero dependencies.

[0.5.0]: https://github.com/MattJackson/pioneer-optical/releases/tag/v0.5.0

## [0.7.2] - 2026-10-04

### Added

- `flash::Identity::kernel_tag()` and `flash::Identity::normal_tag()` —
  installed Kernel/Normal ID tag accessors (vendor-identity bytes `0x18..0x20`
  and `0x20..0x28`). These are what Pioneer's OEM updater compares, byte-for-
  byte, against a Normal envelope's `Kernel Version` / `Destination` header
  fields to decide whether a Normal-only patch is safe for the drive's current
  Kernel generation. See `README.md` for the flasher-side policy.
