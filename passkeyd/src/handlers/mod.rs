use ctap_types::ctap2::{self, Request};
use ctaphid_types::Channel;
use log::{debug, error};
use passkeyd_abi::config::Config;

use crate::ctaphid::{CtapStatus, ctaphid::Ctaphid};

pub mod client_pin;
pub mod get_assertion;
pub mod get_info;
pub mod get_next_assertion;
pub mod make_credential;
pub mod reset;
pub mod selection;

pub fn dispatch(
    hid: &mut Ctaphid,
    config: &Config,
    channel: Channel,
    cbor: &[u8],
) -> anyhow::Result<()> {
    // Anything on the wire can be malformed, and the HID device is reachable
    // by the logged-in user; never unwrap a request.
    let request = match Request::deserialize(cbor) {
        Ok(request) => request,
        Err(e) => {
            error!("Cannot parse CTAP request: {e:?}");
            let status = match e {
                ctap2::Error::InvalidCommand => CtapStatus::InvalidCommand,
                ctap2::Error::MissingParameter => CtapStatus::MissingParameter,
                ctap2::Error::CborUnexpectedType => CtapStatus::CborUnexpectedType,
                _ => CtapStatus::InvalidCbor,
            };
            hid.send_cbor_status(channel, status)?;
            return Ok(());
        }
    };

    let cmd_name = get_request_name(&request);

    debug!(
        "Received CTAP instruction: '{}' on channel {}",
        cmd_name, channel
    );

    let result = match request {
        Request::GetInfo => get_info::handle(hid, config, channel),
        Request::MakeCredential(req) => make_credential::handle(hid, config, channel, req),
        Request::GetAssertion(req) => get_assertion::handle(hid, config, channel, req),
        Request::GetNextAssertion => get_next_assertion::handle(hid, config, channel),
        Request::ClientPin(req) => client_pin::handle(hid, config, channel, req),
        Request::Reset => reset::handle(hid, config, channel),
        Request::Selection => selection::handle(hid, config, channel),

        // Commands this authenticator does not implement. GetInfo advertises
        // none of them, so a well-behaved platform will not send them; answer
        // with an error instead of panicking if one does.
        Request::CredentialManagement(_) | Request::LargeBlobs(_) | Request::Vendor(_) | _ => {
            debug!("Unsupported CTAP instruction: '{}'", cmd_name);
            hid.send_cbor_status(channel, CtapStatus::UnsupportedOption)?;
            Ok(())
        }
    };

    if result.is_ok() {
        debug!("Acknowledged CTAP instruction: '{}'", cmd_name);
    }

    result
}

fn get_request_name(request: &Request) -> &'static str {
    match request {
        Request::GetInfo => "GetInfo",
        Request::MakeCredential(_) => "MakeCredential",
        Request::GetAssertion(_) => "GetAssertion",
        Request::GetNextAssertion => "GetNextAssertion",
        Request::ClientPin(_) => "ClientPin",
        Request::Reset => "Reset",
        Request::CredentialManagement(_) => "CredentialManagement",
        Request::Selection => "Selection",
        Request::LargeBlobs(_) => "LargeBlobs",
        Request::Vendor(_) => "Vendor",
        _ => "Unknown/Unsupported",
    }
}
