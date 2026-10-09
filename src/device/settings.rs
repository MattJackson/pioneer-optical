//! Live settings queries and verified writes using the selected wire codec.
use super::{Device, Error, Readable, Writable, WriteOutcome};
use crate::drive::{Data, Transport};
pub use crate::settings::*;

/// Typed Quiet Drive query/setting. Setting a mode requests firmware-optimal
/// read/write speeds using SET CD SPEED, matching the vendor mode operation.
#[derive(Clone, Copy, Debug)]
pub struct QuietDrive;
/// Typed PureRead query/setting.
#[derive(Clone, Copy, Debug)]
pub struct PureRead;
/// Typed standard DVD RPC query/setting.
#[derive(Clone, Copy, Debug)]
pub struct DvdRegion;

impl Readable for QuietDrive {
    type State = QuietState;
    fn read<T: Transport>(&self, d: &mut Device<'_, T>) -> Result<Self::State, Error<T::Error>> {
        Ok(d.settings()?.quiet_drive())
    }
}
impl Readable for PureRead {
    type State = Capability<PureReadState>;
    fn read<T: Transport>(&self, d: &mut Device<'_, T>) -> Result<Self::State, Error<T::Error>> {
        Ok(d.settings()?.pure_read())
    }
}
impl Readable for DvdRegion {
    type State = crate::rpc::State;
    fn read<T: Transport>(&self, d: &mut Device<'_, T>) -> Result<Self::State, Error<T::Error>> {
        let mut b = [0; 8];
        let n = d.read(&crate::rpc::report_key(), &mut b)?;
        crate::rpc::State::parse(&b[..n]).ok_or(Error::Malformed)
    }
}
fn require<E>(s: Support) -> Result<(), Error<E>> {
    match s {
        Support::Supported => Ok(()),
        Support::Unsupported => Err(Error::Unsupported),
        Support::Unknown => Err(Error::NotReported),
    }
}
fn validate_control<E>(
    control: Control,
    value: Value,
    policy: Persistence,
) -> Result<(), Error<E>> {
    require(control.writable)?;
    if !control.persistence.allows(policy) || !control.choices.contains(&value) {
        return Err(Error::InvalidValue);
    }
    Ok(())
}
fn verify<S, E>(
    result: Result<S, Error<E>>,
    matches: impl FnOnce(&S) -> bool,
) -> WriteOutcome<S, E> {
    match result {
        Ok(s) if matches(&s) => WriteOutcome::Verified(s),
        Ok(s) => WriteOutcome::Mismatch(s),
        Err(e) => WriteOutcome::Unverified(e),
    }
}
impl Writable for QuietDrive {
    type Value = QuietMode;
    type Policy = Persistence;
    fn write<T: Transport>(
        &self,
        d: &mut Device<'_, T>,
        value: QuietMode,
        policy: Persistence,
    ) -> Result<WriteOutcome<QuietState, T::Error>, Error<T::Error>> {
        let settings = d.settings()?;
        let before = settings.quiet_drive();
        validate_control(settings.controls.quiet, Value::Quiet(value), policy)?;
        require(before.writable)?;
        if before.current == Observed::Known(value) && policy == Persistence::Volatile {
            return Ok(WriteOutcome::Unchanged(before));
        }
        let command = d
            .settings_codec
            .quiet_write(value, policy)
            .map_err(super::codec_error)?;
        if !d.write_setting(&command)? {
            return Ok(WriteOutcome::Unverified(Error::Malformed));
        }
        Ok(verify(d.get(*self), |s| {
            s.current == Observed::Known(value)
                && (policy != Persistence::Saved
                    || !matches!(s.saved, Observed::Known(saved) if saved != value))
        }))
    }
}
fn real_time_matches(state: Capability<Observed<bool>>, value: bool) -> bool {
    match state {
        Capability::Supported(Observed::Known(v)) => v == value,
        Capability::Unsupported => !value,
        _ => false,
    }
}
impl Writable for PureRead {
    type Value = PureReadValue;
    type Policy = Persistence;
    fn write<T: Transport>(
        &self,
        d: &mut Device<'_, T>,
        value: PureReadValue,
        policy: Persistence,
    ) -> Result<WriteOutcome<Capability<PureReadState>, T::Error>, Error<T::Error>> {
        let settings = d.settings()?;
        validate_control(settings.controls.pure, Value::PureRead(value.mode), policy)?;
        let before = settings.pure_read();
        let state = match &before {
            Capability::Supported(state) => state,
            Capability::Unsupported => return Err(Error::Unsupported),
            Capability::Unknown => return Err(Error::NotReported),
        };
        match state.real_time {
            Capability::Supported(current) => {
                if current != Observed::Known(value.real_time) || policy == Persistence::Saved {
                    validate_control(
                        settings.controls.real_time,
                        Value::Boolean(value.real_time),
                        policy,
                    )?;
                }
            }
            Capability::Unsupported if value.real_time => return Err(Error::Unsupported),
            Capability::Unknown => return Err(Error::NotReported),
            Capability::Unsupported => {}
        }
        if state.current == Observed::Known(value.mode)
            && real_time_matches(state.real_time, value.real_time)
            && policy == Persistence::Volatile
        {
            return Ok(WriteOutcome::Unchanged(before));
        }
        let command = d
            .settings_codec
            .pure_read_write(value, policy)
            .map_err(super::codec_error)?;
        if !d.write_setting(&command)? {
            return Ok(WriteOutcome::Unverified(Error::Malformed));
        }
        Ok(verify(d.get(*self), |s| {
            s.supported().is_some_and(|s| {
                s.current == Observed::Known(value.mode)
                    && real_time_matches(s.real_time, value.real_time)
            })
        }))
    }
}
/// A validated DVD region number; zero is not a region-free setter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region(u8);
impl Region {
    /// Accept regions 1 through 8 only.
    pub const fn new(number: u8) -> Option<Self> {
        if number >= 1 && number <= 8 {
            Some(Self(number))
        } else {
            None
        }
    }
    /// Number as presented to the user.
    pub const fn number(self) -> u8 {
        self.0
    }
}
impl Writable for DvdRegion {
    type Value = Region;
    type Policy = Persistent;
    fn write<T: Transport>(
        &self,
        d: &mut Device<'_, T>,
        value: Region,
        _: Persistent,
    ) -> Result<WriteOutcome<crate::rpc::State, T::Error>, Error<T::Error>> {
        let before = d.get(*self)?;
        if before.scheme != 1 {
            return Err(Error::Unsupported);
        }
        let mask = !(1u8 << (value.0 - 1));
        if before.prohibited_regions == mask {
            return Ok(WriteOutcome::Unchanged(before));
        }
        if before.user_changes_remaining == 0 || before.type_code == 3 {
            return Err(Error::RegionLocked);
        }
        let data = [0, 6, 0, 0, mask, 0, 0, 0];
        let n = d.exec(&[0xa3, 0, 0, 0, 0, 0, 0, 0, 0, 8, 6, 0], Data::Out(&data))?;
        if n != data.len() {
            return Ok(WriteOutcome::Unverified(Error::Malformed));
        }
        Ok(verify(d.get(*self), |s| s.prohibited_regions == mask))
    }
}
