use crate::{
    cerds,
    ctaphid::{CtapStatus, TransportError, ctaphid::Ctaphid},
};
use ctap_types::{ctap2::get_assertion, serde::cbor_serialize_to};
use ctaphid_types::{Channel, Command};
use log::{debug, error, info};
use passkeyd_abi::config::Config;

pub fn handle(
    hid: &mut Ctaphid,
    config: &Config,
    channel: Channel,
    req: get_assertion::Request<'_>,
) -> anyhow::Result<()> {
    // One line per ceremony. Firefox has been seen asking twice in a row on
    // some sites; the request shape is what tells the two calls apart.
    info!(
        "GetAssertion: rp={}, allow_list={}, options(up,uv,rk)={:?}, cdh={:02x?}",
        req.rp_id,
        match req.allow_list.as_ref() {
            Some(list) => list.len().to_string(),
            None => "discoverable".to_string(),
        },
        req.options.as_ref().map(|o| (o.up, o.uv, o.rk)),
        &req.client_data_hash[..req.client_data_hash.len().min(4)],
    );

    let response = cerds::get::get(hid, channel, config, req);
    let mut report = [0u8; size_of::<get_assertion::Response>() + 1]; //approx size.

    match response {
        Ok(res) => {
            let size = match cbor_serialize_to(&res, &mut report[1..]) {
                Ok(size) => size,
                Err(e) => {
                    // The host is waiting on this request. Answer it, even when
                    // the answer could not be built.
                    error!("Failed to serialize the GetAssertion response: {e:?}");
                    hid.send_cbor_status(channel, CtapStatus::Other)?;
                    return Ok(());
                }
            };
            let final_cbor = &mut report[..size + 1];
            hid.send_response(channel, Command::Cbor, final_cbor)?;
            debug!("Acknowledged ctab instruction \'GetAssertion\'");
        }
        Err(e) => {
            if let Some(err) = e.downcast_ref::<CtapStatus>() {
                report[0] = *err as u8;
                hid.send_64response(channel, Command::Cbor, &report[0..1])?;
            } else if let Some(err) = e.downcast_ref::<TransportError>() {
                hid.send_portocal_error(err.channel, err.err)?;
            } else {
                report[0] = CtapStatus::Other as u8;
                hid.send_64response(channel, Command::Cbor, &report[0..1])?;
            }
        }
    };

    Ok(())
}
