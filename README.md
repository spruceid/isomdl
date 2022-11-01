# isomdl

ISO mDL implementation in Rust
# isomdl

ISO mDL implementation in Rust

Usage:
This implementation uses a structure that separates issuance and presentation functionality in their respective folders.
For issuance purposes:
-use issuance/mdoc.rs
For presentation purposes:
-use presentation/device.rs for the holder interactions
-use presentation/reader.rs for the verifier interactions


##Issuance:
To issue an mdoc call 

```Mdoc::issue(doc_type: String,namespaces: HashMap<String, HashMap<String, CborValue>>, x5chain: X5Chain,validity_info: ValidityInfo,digest_algorithm: DigestAlgorithm, device_key_info: DeviceKeyInfo,signer: Signer+SignatureAlgorithm,)```

- doc_type is always expected to be "org.iso.18013.5.1.mDL" 

- namespaces specify the data elements to be issued to within the mdoc

- x5chain represents the certificate chain, you can use x5chain.builder() to construct the certificate chain based on your .pem or .der

- validity_info should be set by the issuer and details the validity of the mdoc
a valid validity_info object looks as follows: 
    ValidityInfo {signed: OffsetDateTime (UTC),valid_from: OffsetDateTime (UTC),valid_until: OffsetDateTime (UTC),expected_update: Option<OffsetDateTime (UTC)>,};

- digest_algorithm specifies the hashing algortihm for protecting data elements during transport. This library supports SHA-256, SHA-384 and SHA-512.

- device_key_info contains at a minimum a device_key (the public part of the key pair used for mdoc authentication: "SDeviceKey.Pub"). It must be formatted as an RFC 8152 COSE_KEY. 
key_authorizations within the device_key_info specifies the namespaces and/or data_elements that the keys are authorized to authenticate.

- signer contains the issuer_key as an ecdsa::SigningKey, used to sign over the entire mobile_security_object.



<h2>Presentation:</h2>

<h3>Device:</h3>
If you are implementing functionality for an mDL holder, call on functions in presentation/device.rs

expose a QR code to initiate an mdl presentation session by first calling:
1. `SessionMagagerInit::initialise(documents: Documents,device_retrieval_methods: Option<NonEmptyVec<DeviceRetrievalMethod>>,server_retrieval_methods: Option<ServerRetrievalMethods>,)`

documents: load in one or more Documents that contain the mDL
device_retrieval_methods: Specify BLE to be your device_retrieval_method
server_retrieval_methods: set to None

2. and then calling 
`SessionManager::qr_engagement()`

qr_engagement() returns a SessionManagerEngaged that you can use to process a SessionEstablishment message once received from the reader.
When receiving the SessionEstablishment, process it by calling:

3. `SessionManagerEngaged::process_session_establishment(session_establishment: SessionEstablishment)`
returns a SessionManager, that handles the readers request for data and prepares a response

4. `SessionManager::get_next_signature_payload()`

5. `SessionManager::submit_next_signature()`
The session_manager checks if all signatures have been submitted and sets the state to ReadyToRespond.

to retrieve the response to send over to the reader, call:

6. `SessionManager::retrieve_response()`

The device can now wait for another request, or terminate the session:

<h3>Reader</h3>:
If you are implementing functionality for an mdl verifier, call on functions in preentation/reader.rs

A reader establishes a mDL presentation session by first scanning an mDL holder's qr code. The reader uses the embedded information to send out a SessionEstablishment message:

1. `SessionManager::establish_session(qr_code: String,namespaces: device_request::Namespaces,)`

qr_code: the base64 url-encoded string read from the qr code when scanning
namespaces: the namespaces (and data fields) that the verifier wants to request from the mDL holder. This can be any subset of valid mDL data elements as specified in ISO18013-5

2. `SessionManager::handle_response(response &[u8])`
output is the proved data elements relayed by the device



Implementation Limitations:
This implementation of ISO mDL:
- does not feature server retrieval functionality
- currently only allows for presentation initiation by the mDL Holder showing a QR code (no NFC, no WiFi aware)
- currenlty only supports BLE transport for presentation
- currently only allows a reader to request an "org.iso.18013.5.1.mDL" docType in a presentation
- A holder is currently not notified of which requested elements the verifier intends to retain
