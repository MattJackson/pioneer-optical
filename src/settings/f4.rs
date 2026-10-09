//! The structurally recognized Pioneer F4 variants and their command encodings.
use super::*;

/// Exact capability block retained for future firmware variants.
#[derive(Clone, Debug)]
pub struct F4Response {
    raw: [u8; 256],
}
impl F4Response {
    /// Decode a complete F4 block. Zero-filled/refused buffers are not state.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let b = bytes.get(..256)?;
        // Bytes 0/1 are legacy feature flags, not a universal magic signature.
        let sentinel_prefix = b[..2] == [255, 255];
        let feature_prefix =
            b[..2].iter().all(|v| matches!(v, 0 | 1 | 255)) && b[11..15] == [255; 4];
        if (!sentinel_prefix && !feature_prefix) || b.iter().all(|v| *v == 255) {
            return None;
        }
        let mut raw = [0; 256];
        raw.copy_from_slice(b);
        Some(Self { raw })
    }
    /// Raw response, including unknown firmware extensions.
    pub fn raw(&self) -> &[u8; 256] {
        &self.raw
    }
    /// Current mode and independent write support.
    pub fn quiet_drive(&self) -> QuietState {
        let decode = |byte| match byte {
            0 => Observed::Known(QuietMode::Standard),
            1 => Observed::Known(QuietMode::Performance),
            2 => Observed::Known(QuietMode::Quiet),
            3 => Observed::Known(QuietMode::PersistentQuiet),
            255 => Observed::NotReported,
            v => Observed::Unknown(v),
        };
        let current = decode(self.raw[2]);
        let saved = decode(self.raw[3]);
        // Older firmware stops populating the block before the support flags.
        let writable = match (self.raw[45], self.raw[43]) {
            (1, _) => Support::Supported,
            (0, 1) => Support::Unsupported,
            _ => Support::Unknown,
        };
        QuietState {
            current,
            saved,
            writable,
        }
    }
    /// PureRead uses an explicit support field even on earlier response layouts.
    pub fn pure_read(&self) -> Capability<PureReadState> {
        match support(self.raw[9]) {
            Support::Unsupported => return Capability::Unsupported,
            Support::Unknown => return Capability::Unknown,
            Support::Supported => {}
        }
        let current = match (self.raw[4], self.raw[5]) {
            (0, _) => Observed::Known(PureReadMode::Standard),
            (1, 8) => Observed::Known(PureReadMode::Master),
            (1, 254) => Observed::Known(PureReadMode::Perfect),
            (255, _) => Observed::NotReported,
            (1, v) => Observed::Unknown(v),
            (v, _) => Observed::Unknown(v),
        };
        Capability::Supported(PureReadState {
            current,
            real_time: match support(self.raw[29]) {
                Support::Unsupported => Capability::Unsupported,
                Support::Unknown => Capability::Unknown,
                Support::Supported => Capability::Supported(match self.raw[28] {
                    0 => Observed::Known(false),
                    1 => Observed::Known(true),
                    255 => Observed::NotReported,
                    v => Observed::Unknown(v),
                }),
            },
            version: match self.raw[49] {
                0 | 255 => None,
                v => Some(v),
            },
        })
    }
}

/// Pioneer vendor F4 response and corresponding proven command formats.
/// This is a protocol probe, not a claim that all Pioneer firmware implements F4.
#[derive(Clone, Copy, Debug, Default)]
pub struct VendorF4;
impl Codec for VendorF4 {
    fn query(&self) -> Result<Command, CodecError> {
        Command::read(&[0x3c, 2, 0xf4, 0, 0, 0, 0, 1, 0, 0], 256)
    }
    fn decode(&self, response: &[u8]) -> Result<Settings, CodecError> {
        let response = F4Response::parse(response).ok_or(CodecError::Malformed)?;
        Ok(Settings {
            quiet: response.quiet_drive(),
            pure: response.pure_read(),
            controls: Controls::default(),
        }
        .with_controls(self))
    }
    fn controls(&self, settings: &Settings) -> Controls {
        let persistence = PersistenceOptions {
            volatile: true,
            saved: true,
        };
        let pure_support = match settings.pure {
            Capability::Supported(_) => Support::Supported,
            Capability::Unsupported => Support::Unsupported,
            Capability::Unknown => Support::Unknown,
        };
        let real_time = match settings.pure {
            Capability::Supported(p) => match p.real_time {
                Capability::Supported(_) => Support::Supported,
                Capability::Unsupported => Support::Unsupported,
                Capability::Unknown => Support::Unknown,
            },
            _ => pure_support,
        };
        Controls {
            quiet: Control {
                choices: QUIET_CHOICES,
                writable: settings.quiet.writable,
                persistence,
            },
            pure: Control {
                choices: PURE_CHOICES,
                writable: pure_support,
                persistence,
            },
            real_time: Control {
                choices: BOOL_CHOICES,
                writable: real_time,
                persistence,
            },
        }
    }
    fn quiet_write(
        &self,
        mode: QuietMode,
        persistence: Persistence,
    ) -> Result<Command, CodecError> {
        let mut cdb = [0xbb, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0];
        cdb[10] = 0x80
            | mode as u8
            | if persistence == Persistence::Saved {
                0x40
            } else {
                0
            };
        Command::new(&cdb)
    }
    fn pure_read_write(
        &self,
        value: PureReadValue,
        persistence: Persistence,
    ) -> Result<Command, CodecError> {
        let mut payload = [0; 256];
        payload[0..2].copy_from_slice(&[1, 0x80]);
        payload[2..5].copy_from_slice(&match value.mode {
            PureReadMode::Standard => [0, 0, 0],
            PureReadMode::Master => [1, 8, 64],
            PureReadMode::Perfect => [1, 254, 1],
        });
        payload[5] = u8::from(persistence == Persistence::Saved);
        payload[6] = u8::from(value.real_time);
        Command::write(&[0x3b, 1, 0xfa, 0, 0, 0, 0, 1, 0, 0], &payload)
    }
}

const QUIET_CHOICES: &[Value] = &[
    Value::Quiet(QuietMode::Standard),
    Value::Quiet(QuietMode::Performance),
    Value::Quiet(QuietMode::Quiet),
    Value::Quiet(QuietMode::PersistentQuiet),
];
const PURE_CHOICES: &[Value] = &[
    Value::PureRead(PureReadMode::Standard),
    Value::PureRead(PureReadMode::Master),
    Value::PureRead(PureReadMode::Perfect),
];
const BOOL_CHOICES: &[Value] = &[Value::Boolean(false), Value::Boolean(true)];
