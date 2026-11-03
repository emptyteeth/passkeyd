use crate::ctaphid::{CtapStatus, ctaphid::Ctaphid};
use ctaphid_types::Channel;
use log::info;
use passkeyd_abi::config::Config;

/// Reset is not implemented.
///
/// The spec allows an authenticator to disable it on a transport and requires
/// `CTAP2_ERR_OPERATION_DENIED` when it does — but also requires it to be
/// supported on USB HID if that transport is available, so this is a deviation
/// to be closed by a real implementation. Until then, answer rather than leave
/// the platform waiting for a response that never comes.
pub fn handle(hid: &mut Ctaphid, _config: &Config, channel: Channel) -> anyhow::Result<()> {
    info!("Reset requested but not supported; clear the passkey store by hand");
    hid.send_cbor_status(channel, CtapStatus::OperationDenied)
}
