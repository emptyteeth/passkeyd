use crate::ctaphid::{CtapStatus, ctaphid::Ctaphid};
use ctaphid_types::Channel;
use log::info;
use passkeyd_abi::config::Config;

/// There is never an assertion to continue from.
///
/// `GetAssertion` returns a single credential and no `numberOfCredentials`, so
/// a platform has no reason to send this. The spec's answer when no
/// `GetAssertion` parameters are remembered is `CTAP2_ERR_NOT_ALLOWED`.
pub fn handle(hid: &mut Ctaphid, _config: &Config, channel: Channel) -> anyhow::Result<()> {
    info!("GetNextAssertion without a pending assertion");
    hid.send_cbor_status(channel, CtapStatus::NotAllowed)
}
