use ctap_types::ctap2::client_pin;
use ctaphid_types::Channel;
use log::debug;
use passkeyd_abi::config::Config;

use crate::ctaphid::{CtapStatus, ctaphid::Ctaphid};

/// ClientPIN is not supported, and `getInfo` says so: the `clientPin` option is
/// absent, and user verification is done with the built-in method instead.
///
/// Every subcommand is answered with an error. The host is free to ask anyway,
/// and a panic here would take the daemon down in the middle of a ceremony.
pub fn handle(
    hid: &mut Ctaphid,
    _config: &Config,
    channel: Channel,
    req: client_pin::Request<'_>,
) -> anyhow::Result<()> {
    debug!("Rejecting ClientPIN subcommand {:?}", req.sub_command);
    hid.send_cbor_status(channel, CtapStatus::UnsupportedOption)
}
