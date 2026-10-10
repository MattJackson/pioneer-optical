# Changelog

All notable changes to `pioneer-optical` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.14.0] - 2026-10-09

### Changed
- `kernel_content_mask` / `kernel_equality` now compare Kernels of any decoded
  length, not only the 64 KiB SAT layout. Identity-block and checksum masking
  applies only where a SAT identity sits, so legacy little-endian DVR Kernels
  (identity in the header, no positional fill) compare as raw bytes minus their
  drive name. Kernels of different decoded length are different programs.

## [0.13.0] - 2026-10-09

### Added
- `envelope::clone_kernel` re-identifies an existing Kernel envelope: it keeps
  the program, rewrites the drive name and the `0x1000` identity block
  (hardware, Kernel tag, Version2), replaces the build's positional LCG fill
  with the seed-0 stream, recomputes the `0x1020` checksum and re-encodes with
  the supplied revision, date and key. `clone_kernel_image` does the same on a
  decoded image.
- `envelope::kernel_fill_seed` recovers a Kernel build's fill seed; `Some(0)`
  marks a Kernel produced by `clone_kernel`.
- `envelope::kernel_equality` (envelopes) and `kernel_image_equality` (decoded
  images) compare two Kernels by program content, ignoring identity, drive
  name, checksum and fill.
- `envelope::kernel_content_mask` marks identity, checksum, drive-name and fill
  bytes so two Kernels can be compared by program content.
- `Error::KernelFillNotFound` and `Error::DriveNameNotFound`.

## [0.12.4] - 2026-10-09

### Added
- `production`: decode the original product code and factory test date from
  the read-only A0 parameters response, and the country of manufacture from
  the serial suffix (`JP` Japan, `WL` China). `Device::parameters` reads it.

## [0.12.3] - 2026-10-08

### Changed
- Separate read-only firmware inspection from envelope encoding/signing. Shared
  bounded COMP decoding avoids hashes and recompression when inspecting layout.
- Use one validated COMP-loader recognizer for analysis and memory layout;
  conflicting destinations now reject layout rather than omit occupied memory.
- Use h8-asm's H8S decoder for instruction boundaries and memory-helper ABI
  tracing. The `image` feature now requires `std`; default and `drive` remain
  `no_std` and allocation-free.
- Firmware inspection returns typed errors with stable `CodedError` identities.
  Device and settings codec errors also expose stable codes; layout limitations
  are structured values.
- Callback discovery reports generic check, preparation and main addresses.
  Hook-specific acceptance policy belongs to consumers.

### API migration
- Opcode arguments are `u8`. `OpcodeSite` address fields are named
  `registry_address`, `object_address`, `table_address`, `check_address`,
  `prepare_address` and `main_address`.
- `layout::Range` uses validated constructors and `start()`, `end()`, `length()`
  accessors; deserialization rejects empty or reversed intervals.
- Buffer start/length sentinels are `Option<u32>`. `BufferEntry::range` resolves
  intervals within a caller-supplied controller window. `Layout::buffer_conflicts`
  accepts the candidate interval instead of assuming a 512-byte allocation.

### Fixed
- Validate every callback target's bounds/alignment consistently, including
  check and preparation callbacks for high opcodes.
- Calculate overlay tail from the greatest occupied end, including overlaps.
- Preserve cancellation checkpoints through COMP report generation.

## [0.12.2] - 2026-10-08

### Added
- Discover callback objects for all 256 opcode registry entries, including
  READ DISC STRUCTURE, with complete object-pointer bounds checks.

### Fixed
- Inspect generic COMP memory-layout evidence for BD firmware as well as UHD.
  UHD capability remains reported separately; recognizing an image does not
  establish a free RAM region.

## [0.12.1] - 2026-10-08

### Added
- Generic, allocation-free settings codecs with typed current/saved values,
  supported feature children, choices, editability and persistence metadata.
- Live device snapshots, MMC media information, and typed Quiet Drive, PureRead
  and DVD region get/set operations with explicit policies and readback outcomes.
- Offline settings-builder evidence and a per-image Pioneer hoard census.
- Rust regression coverage for malformed and truncated responses, unknown flags,
  alternate codecs, partial transfers, command direction and read-only settings.

### Fixed
- Reject real-time PureRead changes and persistence policies disallowed by the codec.
- Reject contradictory saved Quiet mode readback and include firmware signatures
  that end exactly at an analysis boundary.

## [0.11.3] - 2026-10-08

### Added
- Envelope inspection methods expose parsed headers, raw encoding keys and signature
  presence/verification using the existing parser and verifier.
- Typed reconstruction placeholder detection requires combined seed and metadata
  markers. Neither a match nor a non-match establishes OEM provenance.

## [0.11.2] - 2026-10-08

### Added
- `Envelope::normal_layout()` and `NormalLayout::from_kernel()` derive bounded
  Normal capture reads from a verified H8 Kernel's checksum and descriptor code.
  Both header-derived and fixed-extent layouts are supported without model tables
  or probing unrelated drive memory. Unknown, conflicting and ambiguous evidence
  fails explicitly with stable `pioneer.normal_layout.*` error codes.
- Layout validation checks the Normal descriptor, extent and complete checksum.
  Synthetic instruction, malformed-input and corpus regression tests cover the API.

## [0.11.1] - 2026-10-07

### Added
- Stable namespaced error codes through `CodedError` for application diagnostics
  and future localization.

## [0.11.0] - 2026-10-07

### Changed (breaking)
- Remove model-specific raw-backup layouts and their decode-policy bypass.
- Detect envelope formats through internal codecs and reject ambiguous framing.

### Added
- `Update::load` prepares and authenticates complete Kernel/Normal pairs without device I/O.
- `image::receiver_control_key` extracts recognized update-entry keys from receiver code, with no default-key fallback.
- `ident` exposes firmware banner parsing and embedded OEM identity recovery.
- `Envelope::load` with typed recognition and integrity errors, including payload
  offsets, expected lengths, alignment, and checksum values.
- Sparse little-endian checksum wrappers for Kernel and Normal components,
  including checksum validation and checksum regeneration on repack.
- `kernel_transfer_image` converts front-key and derived-key Kernel files into
  a common receiver representation. This conversion does not authorize flashing.
- `normal_transfer_image` rebuilds continuous keyed Normal payloads using the
  receiving Kernel policy, refusing bad checksums and unrecovered data.
- `image::kernel_marker_policy` identifies receiver marker checks from code,
  independently of editable marker bytes or firmware catalogs.
- Separate regression suites for codec ambiguity, raw detection, checksum
  wrappers, malformed inputs, and independent receiver decoding.

## [0.10.0] - 2026-10-05

Clean base release. All earlier versions (0.5.0, 0.7.2, 0.8.0, 0.9.0) are yanked;
depend on 0.10.

### Changed (breaking)
- `file_type` renamed to `kind`; `ComponentKind` serializes kebab-case.
- `KernelLayout` removed; `info()` is private; error types folded.
- `targets()` rejects empty fields.

### Fixed
- `drive::read_memory` rejects offsets beyond 24 bits; transport-reported
  lengths are clamped to the buffer.
- COMP inflate capped at 64 MiB per stream and 256 MiB per envelope.
- `rebuild_last_comp` no longer panics when the last stream overlaps the
  directory; `carve_live_main` finds an image ending exactly at end of dump.
- A failed signing attempt restores the original signature region.

### Tests
- Mutation-killing tests across image, abi, envelope, drive, signature and lib.

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
  `HeaderOpaque`; `#[non_exhaustive]` on enums and on `EnvelopeInfo`, `UniformRange`,
  `CompStreamInfo`, `LiveMainImage` and `KernelXorPolicy`.

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
  `EnvelopeInfo`, `HeaderInfo`, `HeaderOpaque`. `HeaderInfo::kind` is
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
