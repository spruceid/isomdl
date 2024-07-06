use anyhow::{Context, Result};
use std::collections::BTreeMap;

use isomdl::definitions::device_request::{DataElements, Namespaces};
use isomdl::presentation::device::{Document, Documents, PermittedItems};
use isomdl::presentation::{device, reader, Stringify};

fn main() -> Result<()> {
    let mdl_encoded = include_str!("../../test/stringified-mdl.txt").to_string();

    let mdl = Document::parse(mdl_encoded).context("could not parse mdl")?;
    let docs = Documents::new("org.iso.18013.5.1.mDL".to_string(), mdl);

    // init device
    let (device_sm_engaged, qr) = device::SessionManagerInit::initialise(docs, None, None)?
        // create qr code
        .qr_engagement()?;

    // define required elements by the reader
    let requested_elements = Namespaces::new(
        "org.iso.18013.5.1".into(),
        DataElements::new("age_over_21".to_string(), false),
    );

    // reader scan qr code
    let (mut reader_sm, session_request, _) =
        reader::SessionManager::establish_session(qr, requested_elements)?;

    // device accept reader request
    let (mut device_sm, items) = device_sm_engaged.process_session_establishment(
        serde_cbor::value::from_value(serde_cbor::from_slice(&session_request)?)?,
    )?;

    // check for any errors
    while let Some((_, _to_sign)) = device_sm.get_next_signature_payload() {
        // todo: implement signing
        device_sm.submit_next_signature(vec![1, 2, 3, 4, 5])?;
    }
    if device_sm.response_ready() {
        // we got an error, send it to reader
        let res = reader_sm.handle_response(
            &device_sm
                .retrieve_response()
                .ok_or_else(|| anyhow::anyhow!("no response to retrieve"))?,
        )?;
        println!("reader response: {res:?}");
        println!("we sent errors, terminating");
        return Ok(());
    }

    // device prepare response
    let mut permitted = PermittedItems::new();
    let mut fields = BTreeMap::new();
    fields.insert(
        "org.iso.18013.5.1".to_string(),
        vec!["age_over_21".to_string()],
    );
    permitted.insert("org.iso.18013.5.1.mDL".into(), fields);
    device_sm.prepare_response(&items, permitted);
    while let Some((_, _to_sign)) = device_sm.get_next_signature_payload() {
        // todo: implement signing
        device_sm.submit_next_signature(vec![1, 2, 3, 4, 5])?;
    }

    // send response to reader
    if device_sm.response_ready() {
        // send response to reader
        let res = reader_sm.handle_response(
            &device_sm
                .retrieve_response()
                .ok_or_else(|| anyhow::anyhow!("no response to retrieve"))?,
        )?;
        println!("{:?}", res);
    } else {
        // todo: is this a valid state?
    }

    Ok(())
}
