use ctap_types::ctap2::get_info;
use ctaphid_types::Channel;
use passkeyd_abi::config::Config;

use crate::ctaphid::ctaphid::Ctaphid;

pub fn handle(hid: &mut Ctaphid, _config: &Config, channel: Channel) -> anyhow::Result<()> {
    let mut response = get_info::ResponseBuilder {
        versions: ctap_types::Vec::from_iter([get_info::Version::Fido2_0]),
        aaguid: ctap_types::Bytes::from_slice(&[0u8; 16]).unwrap(),
    }
    .build();

    let mut options = get_info::CtapOptions::default();
    options.client_pin = None; // PIN support
    options.cred_mgmt = None;
    options.large_blobs = None;
    options.pin_uv_auth_token = None;

    options.up = true; //up support
    options.uv = Some(true); //user verification
    options.rk = true;
    options.plat = Some(true);

    response.options = Some(options);

    // send_cbor() frames the response properly. send_64response() tops out at
    // a single 64-byte report, which this response is already close to.
    hid.send_cbor(channel, response)
}
