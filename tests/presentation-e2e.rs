use crate::isomdl::definitions::device_engagement::{
    BleOptions, CentralClientMode, DeviceRetrievalMethod, DeviceRetrievalMethods,
};
use crate::isomdl::definitions::helpers::NonEmptyMap;
use crate::isomdl::definitions::helpers::Tag24;
use crate::isomdl::definitions::issuer_signed::{self};
use crate::isomdl::definitions::session::SessionEstablishment;
use crate::isomdl::definitions::IssuerSigned;
use crate::isomdl::definitions::{DeviceResponse, Mso};
use crate::isomdl::presentation::{
    device::{Document, SessionManagerInit},
    reader::SessionManager,
};
use hex::FromHex;
use isomdl;
use issuer_signed::IssuerSignedItem;
use std::collections::HashMap;
use uuid::Uuid;

#[test]
fn presentation_integration_test() {
    //creating a dummy device::Document to pass into SessionManagerInit from a ISO test vector
    //Document is normally recovered from mobile app storage
    static DEVICE_RESPONSE_CBOR: &str = include_str!("../test/definitions/device_response.cbor");
    let device_response_bytes =
        <Vec<u8>>::from_hex(DEVICE_RESPONSE_CBOR).expect("unable to convert cbor hex to bytes");

    let device_response_input: DeviceResponse = serde_cbor::from_slice(&device_response_bytes)
        .expect("unable to decode cbor as an IssuerSigned");
    let documents_input = device_response_input
        .documents
        .unwrap()
        .first()
        .unwrap()
        .clone();

    let nmspc = documents_input.issuer_signed.namespaces.unwrap();
    let iso_mdl_nmspc =
        Vec::<Tag24<IssuerSignedItem>>::from(nmspc.get("org.iso.18013.5.1").unwrap().clone());

    let mut identifiers: Vec<String> = vec![];
    let mut values: Vec<Tag24<IssuerSignedItem>> = vec![];
    let mut np = HashMap::<String, Tag24<IssuerSignedItem>>::new();

    for item in iso_mdl_nmspc {
        let it = item.into_inner();
        identifiers.push(it.element_identifier.clone());
        values.push(Tag24::<IssuerSignedItem>::new(it).unwrap());
    }

    for (i, _el) in identifiers.iter().enumerate() {
        let key = identifiers.get(i).unwrap().clone();
        let value = values.get(i).unwrap().clone();
        np.insert(key, value);
    }

    let document_namespace_elements = NonEmptyMap::try_from(np).unwrap();

    let uuid = Uuid::now_v1(&[0, 1, 2, 3, 4, 5]);
    static ISSUER_SIGNED_CBOR: &str = include_str!("../test/definitions/issuer_signed.cbor");
    let cbor_bytes =
        <Vec<u8>>::from_hex(ISSUER_SIGNED_CBOR).expect("unable to convert cbor hex to bytes");
    let signed: IssuerSigned =
        serde_cbor::from_slice(&cbor_bytes).expect("unable to decode cbor as an IssuerSigned");
    let mso_bytes = signed
        .issuer_auth
        .payload()
        .expect("expected a COSE_Sign1 with attached payload, found detached payload");
    let mso: Tag24<Mso> =
        serde_cbor::from_slice(mso_bytes).expect("unable to parse payload as Mso");

    let document_namespace =
        NonEmptyMap::new("org.iso.18013.5.1".into(), document_namespace_elements);

    let document = Document {
        id: uuid,
        issuer_auth: signed.issuer_auth,
        mso: mso.into_inner(),
        namespaces: document_namespace,
    };

    let drms = DeviceRetrievalMethods::new(DeviceRetrievalMethod::BLE(BleOptions {
        peripheral_server_mode: None,
        central_client_mode: Some(CentralClientMode { uuid }),
    }));
    //initialise session for device
    let session = SessionManagerInit::initialise(
        NonEmptyMap::new("org.iso.18013.5.1.mDL".into(), document),
        Some(drms),
        None,
    )
    .expect("could not start a session");
    let (engaged_state, qr_code_uri) = session.qr_engagement().expect("unexpected qr engagement");

    //specify requested data
    let mut data_element = HashMap::<String, bool>::new();
    for id in identifiers {
        data_element.insert(id, false);
    }

    let data_elements = NonEmptyMap::try_from(data_element).unwrap();

    let namespaces = NonEmptyMap::new("org.iso.18013.5.1".to_string(), data_elements);

    // generate SessionEstablishment from Reader
    let mut reader_sm = SessionManager::establish_session(qr_code_uri, namespaces).unwrap();

    let request = reader_sm.1; // this is a SessionEstablishment

    let session_establishment: SessionEstablishment =
        serde_cbor::from_slice(&request).expect("not a valid SessionEstablishment");

    // Engage Session for Device -> prepares a response
    let mut device_sm = engaged_state
        .process_session_establishment(session_establishment)
        .expect("could not process session_establishment");

    // retrieve signature payloads
    device_sm.get_next_signature_payload();

    //introduce externally signed signature:
    let signature: Vec<u8> = vec![1, 5, 4, 3, 6, 7, 8];

    //submit signatures for payloads
    let _still_ok = device_sm.submit_next_signature(signature);
    let response = device_sm
        .retrieve_response()
        .expect("could not retrieve response");

    //reader handles response
    //reader currently ignores non-string elements
    let presentment_response = reader_sm.0.handle_response(&response);
    println!("{:?}", presentment_response);
}
