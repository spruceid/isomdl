#[macro_use]
extern crate base64_serde;
extern crate serde;
extern crate serde_derive;
extern crate base64;
extern crate serde_json;

use std::io::Cursor;
use std::sync::Arc;

use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_web::http::Uri;
use actix_web::dev::Url;

use serde::de::Unexpected;
use serde::{Deserialize, Deserializer, Serialize, Serializer};


mod vdl_vc {
    use super::*;

    use ssi::jwk::JWK;
    use ssi::vc::Credential;
    use serde_json::{json, Value};

    // SIGNED EXAMPLE FOLLOWS (WITHOUT CORRECT SIG)
    pub fn example_vdl_json() -> Value {
        json!({
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://w3id.org/security/suites/ed25519-2020/v1",
              "https://w3id.org/vdl/v1"
            ],
            "type": [
              "VerifiableCredential",
              "Iso18013DriversLicense"
            ],
            "issuer": "did:key:z6MkjxvA4FNrQUhr8f7xhdQuP1VPzErkcnfxsRaU5oFgy2E5",
            "issuanceDate": "2018-01-15T10:00:00.0000000-07:00",
            "expirationDate": "2022-08-27T12:00:00.0000000-06:00",
            "credentialSubject": {
              "id": "did:example:12347abcd",
              "license": {
                "type": "Iso18013DriversLicense",
                "document_number": "542426814",
                "family_name": "TURNER",
                "given_name": "SUSAN",
                "portrait": "/9j/4AAQSkZJRgABAQEAkACQA...gcdgck5HtRRSClooooP/2Q==",
                "birth_date": "1998-08-28",
                "issue_date": "2018-01-15T10:00:00.0000000-07:00",
                "expiry_date": "2022-08-27T12:00:00.0000000-06:00",
                "issuing_country": "US",
                "issuing_authority": "CO",
                "driving_privileges": [{
                  "codes": [{"code": "D"}],
                  "vehicle_category_code": "D",
                  "issue_date": "2019-01-01",
                  "expiry_date": "2027-01-01"
                },
                {
                  "codes": [{"code": "C"}],
                  "vehicle_category_code": "C",
                  "issue_date": "2019-01-01",
                  "expiry_date": "2017-01-01"
                }],
                "un_distinguishing_sign": "USA",
              },
            },
            "proof": {
              "type": "Ed25519Signature2020",
              "created": "2021-06-20T00:17:01Z",
              "verificationMethod": "did:key:z6MkjxvA4FNrQUhr8f7xhdQuP1VPzErkcnfxsRaU5oFgy2E5#z6MkjxvA4FNrQUhr8f7xhdQuP1VPzErkcnfxsRaU5oFgy2E5",
              "proofPurpose": "assertionMethod",
              "proofValue": "z4zKSH1WmuSQ8tcpSB6mtaSGhtzvMnBQSckqrpTDm3wQyNfHd6rctuST2cyzaKSY135Kp6ZYMyFaiLvBUjJ89GP7V"
            }
        })
    }

    pub fn example_vdl_vc() -> Result<Credential, String> {
        serde_json::from_value(example_vdl_json())
            .map_err(|e| format!("example_vdl_vc: {}", e))
    }

    pub fn example_jwk() -> Result<JWK, String> {
        // wget https://raw.githubusercontent.com/spruceid/ssi/v0.4.0/tests/ed25519-2020-10-18.json
        let key_str = include_str!("../tests/ed25519-2020-10-18.json");
        serde_json::from_str(key_str)
            .map_err(|e| format!("example_jwk: {}", e))
    }

    pub async fn example_vdl_proof() -> Result<String, String> {
        let key: JWK = example_jwk()?;

        let mut issue_options = ssi::vc::LinkedDataProofOptions::default();
        issue_options.verification_method =
            Some(ssi::vc::URI::String("did:key:z6MkjxvA4FNrQUhr8f7xhdQuP1VPzErk\
                                      cnfxsRaU5oFgy2E5#z6MkjxvA4FNrQUhr8f7xhdQu\
                                      P1VPzErkcnfxsRaU5oFgy2E5".to_string()));

        let resolver = didkit::DID_METHODS.to_resolver();
        let proof = example_vdl_vc()?
            .generate_proof(&key, &issue_options, resolver)
            .await
            .map_err(|e| format!("proof error: {:?}", e));

        Ok(format!("{}", serde_json::to_string_pretty(&proof)
                   .map_err(|e| format!("example_vdl_proof: {}", e))?))
    }

    #[cfg(test)]
    mod vdl_tests {
        use super::*;
        use tokio;

        #[test]
        fn test_example_vdl_vc() {
            assert_eq!(example_vdl_vc().map(|_| ()), Ok(()))
        }

        #[test]
        fn test_example_jwk() {
            assert_eq!(example_jwk().map(|_| ()), Ok(()))
        }

        #[tokio::test]
        async fn test_verify_example_vdl_vc() {
            let vc = example_vdl_vc().unwrap();
            let resolver = didkit::DID_METHODS.to_resolver();
            let result = format!("{:?}", vc.verify(None, resolver).await);
            assert_eq!(result,
                       "VerificationResult { checks: [Proof], warnings: [], \
                       errors: [\"Crypto error\"] }".to_string());
        }

        #[tokio::test]
        async fn test_example_vdl_proof() {
            let result = example_vdl_proof().await;
            assert_eq!(result, Ok("{\n  \"Err\": \"proof error: KeyMismatch\"\n}".to_string()))
        }
    }


    pub fn example_vdl_json_unsigned() -> Value {
        json!({
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://w3id.org/security/suites/ed25519-2020/v1",
              "https://w3id.org/vdl/v1"
            ],
            "type": [
              "VerifiableCredential",
              "Iso18013DriversLicense"
            ],
            "issuer": "did:example:foo#key3",
            "issuanceDate": "2018-01-15T10:00:00.0000000-07:00",
            "expirationDate": "2022-08-27T12:00:00.0000000-06:00",
            "credentialSubject": {
              "id": "did:example:12347abcd",
              "license": {
                "type": "Iso18013DriversLicense",
                "document_number": "542426814",
                "family_name": "TURNER",
                "given_name": "SUSAN",
                "portrait": "/9j/4AAQSkZJRgABAQEAkACQA...gcdgck5HtRRSClooooP/2Q==",
                "birth_date": "1998-08-28",
                "issue_date": "2018-01-15T10:00:00.0000000-07:00",
                "expiry_date": "2022-08-27T12:00:00.0000000-06:00",
                "issuing_country": "US",
                "issuing_authority": "CO",
                "driving_privileges": [{
                  "codes": [{"code": "D"}],
                  "vehicle_category_code": "D",
                  "issue_date": "2019-01-01",
                  "expiry_date": "2027-01-01"
                },
                {
                  "codes": [{"code": "C"}],
                  "vehicle_category_code": "C",
                  "issue_date": "2019-01-01",
                  "expiry_date": "2017-01-01"
                }],
                "un_distinguishing_sign": "USA",
              },
            },
        })
    }

    pub fn example_vdl_vc_unsigned() -> Result<Credential, String> {
        serde_json::from_value(example_vdl_json_unsigned())
            .map_err(|e| format!("example_vdl_vc_unsigned: {}", e))
    }

    #[cfg(test)]
    mod vdl_unsigned_tests {
        use super::*;
        use tokio;

        #[test]
        fn test_example_vdl_vc_unsigned() {
            assert_eq!(example_vdl_vc_unsigned().map(|_| ()), Ok(()))
        }

        #[tokio::test]
        async fn test_example_vdl_json_unsigned() {
            // let key: JWK = example_jwk()?;
            let key: JWK = example_jwk().unwrap();

            let mut issue_options = ssi::vc::LinkedDataProofOptions::default();
            issue_options.verification_method = None;
                // Some(ssi::vc::URI::String("did:example:foo#key3".to_string()));

            let resolver = didkit::DID_METHODS.to_resolver();
            let proof = example_vdl_vc_unsigned()
                .unwrap()
                .generate_proof(&key, &issue_options, resolver)
                .await
                .map_err(|e| format!("proof error: {:?}", e));

            // assert_eq!(example_vdl_json_unsigned().map(|_| ()), Ok(()))
            assert_eq!(proof.map(|x| format!("{:?}", x)), Ok("".to_string()))

            // vc.add_proof(proof);
            // vc.validate().unwrap();
            // let verification_result = vc.verify(None, &DIDExample, &mut context_loader).await;
            // println!("{:#?}", verification_result);
            // assert!(verification_result.errors.is_empty());
        }
    }
}
// use crate::vdl_vc;



// oidc4vci:
// - /initiate_issuance -> JWT (as defined in dual prov doc), for inperson prov this is consumed by dmv internally, for remote prov this is consumed by the mdl app and protected by an access token issued by the dmv idp. note, the latter was not fully agreed.

// document verification:
// - /document_verification -> remote prov only. define as needed, should also contain the case-number for internal reference. for in person prov, this might be a different api that is not public facing.

// MOSTLY DONE
// - /token -> as defined in dual prov doc
// - /credential -> as defined in dual prov doc
// - /generate_qr_code -> gets any URI to generate a QR Code with a link (will be used to generate initiate issuance request

// DONE:
// document verification:
// - /eligibility -> expects any payload and provides a result object with a status, the status is always success (for now)

mod base64_serde_type {
    use base64::{URL_SAFE_NO_PAD};

    base64_serde::base64_serde_type!(pub Base64UrlSafeNoPad, URL_SAFE_NO_PAD);
}
use crate::base64_serde_type::Base64UrlSafeNoPad;

mod url_value {
    use super::*;

    /// A Url with PartialEq and (De)Serialize
    #[derive(Clone, Debug)]
    pub struct UrlValue {
        pub url: Url,
    }

    impl UrlValue {
        pub fn to_string(&self) -> String {
            format!("{}", self.url.uri())
        }
    }

    impl PartialEq for UrlValue {
        fn eq(&self, other: &Self) -> bool {
            self.url.path() == other.url.path()
        }
    }

    impl Serialize for UrlValue {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            self.url.path().serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for UrlValue {
        fn deserialize<D>(deserializer: D) -> Result<UrlValue, D::Error>
        where
            D: Deserializer<'de>,
        {
            // deserializer.deserialize_i32(I32Visitor)
            <String as Deserialize>::deserialize(deserializer)
                .and_then(|x| {
                    let mut encoded_str = "dummy_key=".to_string();
                    encoded_str.push_str(&x);
                    let result_list: Vec<(String, String)> =
                        serde_urlencoded::from_str(&encoded_str)
                        .map_err(|e| serde::de::Error::invalid_type(
                            Unexpected::Other(&format!("not urlencoded: ({}, {})", x, e)),
                            &"URL-encoded string"))?;
                    let (_, result) = &result_list[0];
                    Ok(result.clone())
                })
                .and_then(|x: String| Ok(UrlValue {
                    url: Url::new(x
                                  .parse::<Uri>()
                                  .map_err(|e|
                                      serde::de::Error::invalid_type(
                                          Unexpected::Other(&format!("InvalidUri: ({}, {})", x, e)),
                                          &"URL-encoded issuer URL"))?),
                }))
        }
    }
}
use crate::url_value::UrlValue;

mod https_dmv_ca_gov_mdl {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum HttpsDmvCaGovMdl {
        #[serde(rename = "https://dmv.ca.gov/mdl")]
        HttpsDmvCaGovMdl,
    }

    impl HttpsDmvCaGovMdl {
        pub fn string() -> String {
            "https://dmv.ca.gov/mdl".to_string()
        }

        pub fn to_string(&self) -> String {
            Self::string()
        }
    }

    #[cfg(test)]
    mod https_dmv_ca_gov_mdl_tests {
        use super::*;

        #[test]
        fn test_serialize_https_dmv_ca_gov_mdl() {
            let input = HttpsDmvCaGovMdl::HttpsDmvCaGovMdl;
            let result = serde_json::to_value(input)
                .map_err(|e| format!("{}", e))
                .and_then(|json_value|
                    // TODO: skip to_value, unneeded
                    serde_json::to_string_pretty(&json_value)
                        .map_err(|e| format!("{}", e)));

            let expected = format!("\"{}\"", HttpsDmvCaGovMdl::string());
            assert_eq!(result, Ok(expected))
        }

        #[test]
        fn test_deserialize_https_dmv_ca_gov_mdl() {
            let input = format!("\"{}\"", HttpsDmvCaGovMdl::string());
            let result = serde_json::from_str(&input)
                .map_err(|e| format!("{}", e));
            let expected = HttpsDmvCaGovMdl::HttpsDmvCaGovMdl;
            assert_eq!(result, Ok(expected))
        }
    }
}
use crate::https_dmv_ca_gov_mdl::HttpsDmvCaGovMdl;

mod urn_ietf_params_oauth_grant_type_pre_authorized_code {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum UrnIetfParamsOauthGrantTypePreAuthorizedCode {
        #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
        UrnIetfParamsOauthGrantTypePreAuthorizedCode,
    }

    impl UrnIetfParamsOauthGrantTypePreAuthorizedCode {
        pub fn string() -> String {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string()
        }

        // pub fn to_string(&self) -> String {
        //     Self::string()
        // }
    }

    #[cfg(test)]
    mod urn_ietf_params_oauth_grant_type_pre_authorized_code_tests {
        use super::*;

        #[test]
        fn test_serialize_urn_ietf_params_oauth_grant_type_pre_authorized_code() {
            let input = UrnIetfParamsOauthGrantTypePreAuthorizedCode::UrnIetfParamsOauthGrantTypePreAuthorizedCode;
            let result = serde_json::to_value(input)
                .map_err(|e| format!("{}", e))
                .and_then(|json_value|
                    // TODO: skip to_value, unneeded
                    serde_json::to_string_pretty(&json_value)
                        .map_err(|e| format!("{}", e)));

            let expected = format!("\"{}\"", UrnIetfParamsOauthGrantTypePreAuthorizedCode::string());
            assert_eq!(result, Ok(expected))
        }

        #[test]
        fn test_deserialize_urn_ietf_params_oauth_grant_type_pre_authorized_code() {
            let input = format!("\"{}\"", UrnIetfParamsOauthGrantTypePreAuthorizedCode::string());
            let result = serde_json::from_str(&input)
                .map_err(|e| format!("{}", e));
            let expected = UrnIetfParamsOauthGrantTypePreAuthorizedCode::UrnIetfParamsOauthGrantTypePreAuthorizedCode;
            assert_eq!(result, Ok(expected))
        }
    }
}
use crate::urn_ietf_params_oauth_grant_type_pre_authorized_code::UrnIetfParamsOauthGrantTypePreAuthorizedCode;

mod jwt_const_string {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum JwtConstString {
        #[serde(rename = "jwt")]
        JwtConstString,
    }

    impl JwtConstString {
        pub fn string() -> String {
            "jwt".to_string()
        }
    }

    #[cfg(test)]
    mod jwt_const_string_tests {
        use super::*;

        #[test]
        fn test_serialize_jwt_const_string() {
            let input = JwtConstString::JwtConstString;
            let result = serde_json::to_value(input)
                .map_err(|e| format!("{}", e))
                .and_then(|json_value|
                    // TODO: skip to_value, unneeded
                    serde_json::to_string_pretty(&json_value)
                        .map_err(|e| format!("{}", e)));

            let expected = format!("\"{}\"", JwtConstString::string());
            assert_eq!(result, Ok(expected))
        }

        #[test]
        fn test_deserialize_jwt_const_string() {
            let input = format!("\"{}\"", JwtConstString::string());
            let result = serde_json::from_str(&input)
                .map_err(|e| format!("{}", e));
            let expected = JwtConstString::JwtConstString;
            assert_eq!(result, Ok(expected))
        }
    }
}
use crate::jwt_const_string::JwtConstString;

mod invalid_request {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum InvalidRequest {
        #[serde(rename = "invalid_request")]
        InvalidRequest,
    }

    impl InvalidRequest {
        pub fn string() -> String {
            "invalid_request".to_string()
        }
    }

    #[cfg(test)]
    mod invalid_request_tests {
        use super::*;

        #[test]
        fn test_serialize_invalid_request() {
            let input = InvalidRequest::InvalidRequest;
            let result = serde_json::to_value(input)
                .map_err(|e| format!("{}", e))
                .and_then(|json_value|
                    // TODO: skip to_value, unneeded
                    serde_json::to_string_pretty(&json_value)
                        .map_err(|e| format!("{}", e)));

            let expected = format!("\"{}\"", InvalidRequest::string());
            assert_eq!(result, Ok(expected))
        }

        #[test]
        fn test_deserialize_invalid_request() {
            let input = format!("\"{}\"", InvalidRequest::string());
            let result = serde_json::from_str(&input)
                .map_err(|e| format!("{}", e));
            let expected = InvalidRequest::InvalidRequest;
            assert_eq!(result, Ok(expected))
        }
    }
}
use crate::invalid_request::InvalidRequest;

mod invalid_or_missing_proof {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum InvalidOrMissingProof {
        #[serde(rename = "invalid_or_missing_proof")]
        InvalidOrMissingProof,
    }

    impl InvalidOrMissingProof {
        pub fn string() -> String {
            "invalid_or_missing_proof".to_string()
        }
    }

    #[cfg(test)]
    mod invalid_or_missing_proof_tests {
        use super::*;

        #[test]
        fn test_serialize_invalid_or_missing_proof() {
            let input = InvalidOrMissingProof::InvalidOrMissingProof;
            let result = serde_json::to_value(input)
                .map_err(|e| format!("{}", e))
                .and_then(|json_value|
                    // TODO: skip to_value, unneeded
                    serde_json::to_string_pretty(&json_value)
                        .map_err(|e| format!("{}", e)));

            let expected = format!("\"{}\"", InvalidOrMissingProof::string());
            assert_eq!(result, Ok(expected))
        }

        #[test]
        fn test_deserialize_invalid_or_missing_proof() {
            let input = format!("\"{}\"", InvalidOrMissingProof::string());
            let result = serde_json::from_str(&input)
                .map_err(|e| format!("{}", e));
            let expected = InvalidOrMissingProof::InvalidOrMissingProof;
            assert_eq!(result, Ok(expected))
        }
    }
}
use crate::invalid_or_missing_proof::InvalidOrMissingProof;


#[derive(Clone, Debug)]
struct AppState { }

impl AppState {
    pub fn new() -> Self {
        Self { }
    }
}

/// Expects any payload and provides a result object with a status.
///
/// The status is always success (for now)
#[get("/eligibility")]
async fn eligibility_api(_request: HttpRequest) -> impl Responder {
    HttpResponse::Ok().body("eligible: 0 checks performed.\n")
}


///////////////////////////////////////////////////////////////////////////////////////
//// BEGIN OIDC4VCI
///////////////////////////////////////////////////////////////////////////////////////

// Credential Response
// Depending on the chosen Option in the previous section, OIDC4VCI returns the issued mDL and a W3C Verifiable Credential as a response to the credential request or the deferred credential request in the credential parameter. The credential parameter is encoded as a base64-URL-encoded value. Additionally, a format parameter is returned that indicates the credential format.

// Example:

// {
//   credential = "bWR...",
//   format = "mdoc_b64u_cbor",
//   …
// }
// W3C Verifiable Credential Formats
// Spruce will support W3C Verifiable Credentials in two conforming formats: (1) JWT encoded and also (2) JSON-LD signatures (via Linked Data Integrity), allowing for interoperability with JWT-compatible systems and also LD-dependent systems alike (such as TrueAge).

// Request and Response Definitions
// - OIDCVCI Initiate Issuance Request (QR Code)
// - The OIDC4VCI Initiate Issuance Request is encoded in a QR Code that the DMV clerk prints out or shows on 
//     their screen. The QR Code is generated by the DMV service and will invoke the mDL app via universal 
//     links, deep links, app links etc. In case a user PIN is required, the DMV clerk would communicate the 
//     PIN to the user out-of-band, e.g., verbal communication, separate letter, email, text message. A PIN is 
//     required to prevent MITM attacks in case an attacker is able to get access to the QR Code.

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum FormatQR {
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "png")]
    Png,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RequestQR {
    /// URL-encoded issuer URL of the OIDC4VCI OP, e.g., https://op.dmv.ca.gov.
    /// This parameter may be used to retrieve the OP configuration via OIDC
    /// Discovery but the OP configuration is pre-populated and cached in the
    /// mDL app. The OP configuration typically provides a JSON object that
    /// contains information about supported grant types, public keys, credential types etc.
    issuer: UrlValue,

    /// Contains a pre-authorized credential type which the mDL app can request.
    /// The credential_type must be set to https://dmv.ca.gov/mdl.
    credential_type: HttpsDmvCaGovMdl,

    /// The code represents the DMV’s authorization for the mDL app to obtain
    /// credentials of the types specified by the credential_type parameters.
    /// This code must be short lived and single-use.
    #[serde(rename = "pre-authorized_code")]
    pre_authorized_code: String,

    /// (Optional) Boolean value indicating whether a user PIN is required.
    /// Default is false.
    user_pin_required: Option<bool>,

    /// (Optional) json or png format
    format: Option<FormatQR>,
}

impl RequestQR {
    /// Returns user_pin_required.unwrap() or false if None
    pub fn user_pin_required_default(&self) -> bool {
        self.user_pin_required.unwrap_or(false)
    }

    /// Returns format.unwrap() or FormatQR::Json if None
    pub fn format_default(&self) -> FormatQR {
        *self.format.as_ref().unwrap_or(&FormatQR::Json)
    }

    /// Return the path and query for the URI
    pub fn path_and_query(&self) ->
        Result<actix_web::http::uri::PathAndQuery, String> {
        let mut issuer_str = self.issuer.to_string();
        if issuer_str.ends_with('/') { issuer_str.pop(); }
        let queries = vec![
            ("issuer", issuer_str),
            ("credential_type", self.credential_type.to_string()),
            ("pre-authorized_code", self.pre_authorized_code.clone()),
            ("user_pin_required", format!("{}", self.user_pin_required_default())),
        ];

        let mut path_and_query_str = "/?".to_string();
        path_and_query_str.push_str(
            &serde_urlencoded::to_string(&queries)
            .map_err(|e| format!("urlencoded Error: {}", e))?);
        path_and_query_str.parse()
            .map_err(|e| format!("InvalidUri: {}", e))
    }

    /// customscheme://example_authority?
    ///     issuer=https%3A%2F%2Fop.dmv.ca.gov
    ///     &credential_type=https%3A%2F%2Fdmv.ca.gov%2Fmdl
    ///     &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
    ///     &user_pin_required=true
    pub fn uri(&self) -> Result<Uri, String> {
        Ok(actix_web::http::uri::Builder::new()
            .scheme("customscheme")
            .authority("example_authority")
            .path_and_query(self.path_and_query()?)
            .build()
            .map_err(|e| format!("HttpError: {}", e))?)
    }
}

#[cfg(test)]
mod request_qr_tests {
    use super::*;

    #[test]
    fn test_request_qr_path_and_query() {

        let issuer_uri = Uri::from_static(
            "https://op.dmv.ca.gov");

        let request_qr = RequestQR {
            issuer: UrlValue {
                url: Url::new(issuer_uri),
            },

            credential_type: HttpsDmvCaGovMdl::HttpsDmvCaGovMdl,
            pre_authorized_code:
                "SplxlOBeZQQYbYS6WxSbIA".to_string(),
            user_pin_required: None,
            format: None,
        };

        let expected =
            "/?issuer=https%3A%2F%2Fop.dmv.ca.gov&credential_type=https%3A%2F%2\
            Fdmv.ca.gov%2Fmdl&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA&user_p\
            in_required=false".to_string();

        assert_eq!(request_qr.path_and_query()
                   .map(|path_and_query| path_and_query.as_str().to_string()),
                   Ok(expected))
    }

    #[test]
    fn test_request_qr_uri() {

        let issuer_uri = Uri::from_static(
            "https://op.dmv.ca.gov");

        let request_qr = RequestQR {
            issuer: UrlValue {
                url: Url::new(issuer_uri),
            },

            credential_type: HttpsDmvCaGovMdl::HttpsDmvCaGovMdl,
            pre_authorized_code:
                "SplxlOBeZQQYbYS6WxSbIA".to_string(),
            user_pin_required: Some(true),
            format: None,
        };

        let expected = Uri::from_static(
            "customscheme://example_authority?issuer=https%3A%2F%2Fop.dmv.ca.go\
            v&credential_type=https%3A%2F%2Fdmv.ca.gov%2Fmdl&pre-authorized_cod\
            e=SplxlOBeZQQYbYS6WxSbIA&user_pin_required=true");

        assert_eq!(request_qr.uri(), Ok(expected))
    }

}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct QrCodeError {
    error: String,
}

impl std::fmt::Display for QrCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl actix_web::ResponseError for QrCodeError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::InternalServerError().body(self.error.clone())
    }
}

/// <app-link>://?
///     issuer=https%3A%2F%2Fop.dmv.ca.gov
///     &credential_type=https%3A%2F%2Fdmv.ca.gov%2Fmdl
///     &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
///     &user_pin_required=true
///
/// Example: Decoded content of the QR Code generated by the DMV Service
///
/// - OIDCVCI Initiate Issuance Response
/// - N/A. The OIDC4VCI Initiate Issuance Request does not define or require a response.
/// - OIDC4VCI Token Request
/// - After the OIDC4VCI Initiate Issuance Request invokes the mDL app, the mDL app sends the OIDC4VCI Token 
///     Request to the OIDC4VCI token endpoint of the DMV service. 
#[get("/generate_qr_code")]
async fn qr_code_api(request: web::Form<RequestQR>) -> Result<HttpResponse, QrCodeError> {
    let uri = request.uri()
        .map_err(|e| QrCodeError { error: format!("{}", e) })?;
    match request.format_default() {
        FormatQR::Json => {
            let response = uri.to_string();
            Ok(HttpResponse::Ok().json(response))
        },
        FormatQR::Png => {
            let uri_bytes = format!("{}", uri);
            let mut png_bytes = Cursor::new(Vec::new());
            let () = qrcode::QrCode::new(uri_bytes)
                .map_err(|e| QrCodeError { error: format!("{}", e) })
                .and_then(|x| {
                    let png = x
                        .render::<image::Luma<u8>>()
                        .build();
                    image::DynamicImage::ImageLuma8(png)
                        .write_to(&mut png_bytes, image::ImageOutputFormat::Png)
                        .map_err(|e| QrCodeError { error: format!("{}", e) })
                })?;
            Ok(HttpResponse::Ok()
                .content_type(actix_web::http::header::ContentType::png())
                .body(png_bytes.into_inner()))
        },
    }
}

/// POST /token HTTP/1.1
///   Host: op.dmv.ca.gov
///   Content-Type: application/x-www-form-urlencoded
///
///   grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
///   &client_id=NzbLsXh8...
///   &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
///   &user_pin=493536
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenRequest {
    /// The OIDC grant type that is being used.
    /// In this case, the grant type must be set to
    /// "urn:ietf:params:oauth:grant-type:pre-authorized_code".
    grant_type: UrnIetfParamsOauthGrantTypePreAuthorizedCode,

    /// The pre-authorized_code that was populated through the OIDC4VCI
    /// Initiate Issuance Request.
    #[serde(rename = "pre-authorized_code")]
    pre_authorized_code: String,

    /// The OIDC client identifier of the mDL app.
    /// Since the mDL app is considered a public client the identifier is chosen
    /// by the mDL app.
    /// It provides no additional security for the DMV service.
    client_id: String,

    /// (Optional) String value containing a user PIN.
    /// This value must be present if user_pin_required was set to true in the
    /// OIDC4VCI Initiate Issuance Request.
    /// The string value must consist of a maximum of 8 numeric characters (the numbers 0 - 9).
    user_pin: Option<String>,
}

// HTTP/1.1 200 OK
//   Content-Type: application/json
//   Cache-Control: no-store
//   Pragma: no-cache
//
// {
//   "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
//   "token_type": "bearer",
//   "expires_in": 86400,
//   "c_nonce": "tZignsnFbp",
//   "c_nonce_expires_in": 86400
// }
//
// Example: Successful OIDC4VCI Token Response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    /// OAuth2 access token that can be used to retrieve the credentials from the
    /// OIDC4VCI credential endpoint.
    access_token: oauth2::AccessToken,

    /// OAuth2 token type. This value must be bearer.
    token_type: oauth2::basic::BasicTokenType,

    /// The expiration time of the OAuth2 access token (in seconds)
    /// since the response was generated where the DMV service will stop accepting
    /// requests at the OIDC4VCI credentials endpoint for the OAuth2 access token.
    expires_in: u64,

    /// String containing a nonce to be used to create a proof of possession of
    /// key material when requesting a credential.
    c_nonce: String,

    /// Integer denoting the lifetime in seconds of the c_nonce.
    c_nonce_expires_in: u64,
}

impl TokenResponse {
    pub fn example() -> Self {
        let access_token =
            oauth2::AccessToken::new(
                "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ".to_string());
        let token_type =
            oauth2::basic::BasicTokenType::Bearer;
        let expires_in = 86400;
        let c_nonce = "tZignsnFbp".to_string();
        let c_nonce_expires_in = 86400;

        Self {
            access_token,
            token_type,
            expires_in,
            c_nonce,
            c_nonce_expires_in,
        }
    }
}

/// If the OIDC4VCI Token Request was unsuccessful, e.g., invalid or expired
/// pre-authorized_code, multiple use of pre-authorized_code, invalid PIN etc.,
/// the DMV Service returns an error response as defined below.
///
/// HTTP/1.1 400 Bad Request
///   Content-Type: application/json
///   Cache-Control: no-store
///   Pragma: no-cache
///
/// {
///    "error": "invalid_request"
/// }
///
/// - Example: OIDC4VCI Token Error Response
/// - OIDC4VCI Credential Request
/// - After the mDL App successfully obtains an access_token from the OIDC4VCI
///     token endpoint, the mDL app sends an OIDC4VCI Credential Request to the
///     OIDC4VCI credentials endpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenError {
    /// The value must be invalid_request as per OIDC Core.
    error: InvalidRequest,
}

impl Default for TokenError {
    fn default() -> Self {
        Self {
            error: InvalidRequest::InvalidRequest,
        }
    }
}

// TODO: /token

/// POST /token HTTP/1.1
///   Host: op.dmv.ca.gov
///   Content-Type: application/x-www-form-urlencoded
///
///   grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
///   &client_id=NzbLsXh8...
///   &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
///   &user_pin=493536
///
/// Example: OIDC4VCI Token Request
/// - OIDC4VCI Token Response
/// - If the OIDC4VCI Token Request was successful, the DMV Service would return
///   a successful token response as defined below.
#[post("/token")]
async fn token_api(request: web::Form<TokenRequest>) -> impl Responder {
    if request.user_pin.as_ref().map(|user_pin| user_pin == "").unwrap_or(false) {
        HttpResponse::BadRequest().json(TokenError::default())
    } else {
        HttpResponse::Ok().json(TokenResponse::example())
    }
}




// jwt Header
//
// alg
// - The JWS algorithm as per JOSE IANA registry, e.g., ES256.
//     Note, this algorithm is limited by the device’s capabilities.
//     Private keys used to generate the signature should be secured in the secure enclave. 
//
// typ
// - This value must be JWT.
//
// jwk
// - The public key in JSON Web Key (JWK) format that must be used to verify the signature of the JWT.
//
// Table: Details of OIDC4VCI JWT Headers

// - jwt Payload
// iss
// - The OIDC client identifier used prior with the OIDC4VCI token endpoint.
//
// aud
// - The audience of the JWT that verifies the proof of possession.
//     The value must be the URI of the DMV service, e.g., op.dmv.ca.gov.
//
// iat
// - The time when the proof of possession was created.
//
// nonce
// - A nonce value chosen by the DMV service that is equal to the last retrieved c_nonce.

/// The format of the credential,
/// either ldp_vc (for W3C Verifiable Credential) or mdoc_b64u_cbor (for ISO 18013-5).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CredentialFormat {
    #[serde(rename = "ldp_vc")]
    LdpVc,
    #[serde(rename = "mdoc_b64u_cbor")]
    MdocB64uCbor,
}

/// The format of the credential being requested.
/// The value must be either mdoc_b64u_cbor or jwt_vc.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CredentialRequestFormat {
    #[serde(rename = "jwt_vc")]
    JwtVc,
    #[serde(rename = "mdoc_b64u_cbor")]
    MdocB64uCbor,
}

/// Claims in the JWT credential
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialClaims {
    example_claim: String,
}

impl CredentialClaims {
    pub fn example() -> Self {
        Self {
            example_claim: "example_claim_contents".to_string(),
        }
    }
}

/// Doesn't check any signatures
#[derive(Clone, Debug)]
pub struct CredentialJwt {
    jwt: Arc<jsonwebtoken::TokenData<CredentialClaims>>,
}

impl CredentialJwt {
    pub fn new(jwt: jsonwebtoken::TokenData<CredentialClaims>) -> Self {
        Self {
            jwt: Arc::new(jwt),
        }
    }

    pub fn example_header() -> jsonwebtoken::Header {
        jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256)
    }

    pub fn example_secret() -> &'static str {
        "example_secret"
    }

    pub fn example_encoding_key() -> jsonwebtoken::EncodingKey {
        jsonwebtoken::EncodingKey::from_secret(Self::example_secret().as_ref())
    }

    pub fn example_decoding_key() -> jsonwebtoken::DecodingKey {
        jsonwebtoken::DecodingKey::from_secret(Self::example_secret().as_ref())
    }

    /// Doesn't check any signatures
    pub fn example_validation() -> jsonwebtoken::Validation {
        let mut validation =
            jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.insecure_disable_signature_validation();
        validation.required_spec_claims = std::collections::HashSet::new();
        validation
    }

    pub fn example() -> Self {
        Self::new(jsonwebtoken::TokenData {
            header: Self::example_header(),
            claims: CredentialClaims::example(),
        })
    }
}

impl Serialize for CredentialJwt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let header = Self::example_header();
        let key = Self::example_encoding_key();
        jsonwebtoken::encode(&header, &self.jwt.claims, &key)
            .map_err(|e| serde::ser::Error::custom(format!("{}", e)))?
            .serialize(serializer)
    }
}

/// Doesn't check any signatures
impl<'de> Deserialize<'de> for CredentialJwt {
    fn deserialize<D>(deserializer: D) -> Result<CredentialJwt, D::Error>
    where
        D: Deserializer<'de>,
    {
        <String as Deserialize>::deserialize(deserializer)
            .and_then(|jwt_str|
                jsonwebtoken::decode(&jwt_str,
                                     &Self::example_decoding_key(),
                                     &Self::example_validation())
                    .map_err(|e| serde::de::Error::custom(format!("{}", e))))
            .map(|result| CredentialJwt::new(result))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialRequestProof {
    /// The value indicates the type of the proof of possession and must be jwt.
    proof_type: JwtConstString,

    /// The JWT that represents the proof of possession.
    /// A JWT is of the form
    /// <base64-URL-encoded-header>.<base64-URL-encoded-payload>.<base64-URL-encoded-signature>.
    jwt: CredentialJwt,
}

impl CredentialRequestProof {
    pub fn example() -> Self {
        Self {
            proof_type: JwtConstString::JwtConstString,
            jwt: CredentialJwt::example(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CredentialRequestProofString {
    credential_request_proof: CredentialRequestProof,
}

impl Serialize for CredentialRequestProofString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_json::to_value(self.credential_request_proof.clone())
            .map_err(|e| serde::ser::Error::custom(format!("{}", e)))
            // TODO: skip to_value, unneeded
            .and_then(|json| serde_json::to_string_pretty(&json)
                .map_err(|e|
                    serde::ser::Error::custom(
                        format!("error to JSON: ({}, {})", json, e))))
            .and_then(|string| string.serialize(serializer))
    }
}

impl<'de> Deserialize<'de> for CredentialRequestProofString {
    fn deserialize<D>(deserializer: D) -> Result<CredentialRequestProofString, D::Error>
    where
        D: Deserializer<'de>,
    {
        <String as Deserialize>::deserialize(deserializer)
            .and_then(|string| serde_json::from_str(&string)
                .map(|x| CredentialRequestProofString {
                    credential_request_proof: x,
                })
                .map_err(|e|
                    serde::de::Error::custom(
                        format!("error from JSON: ({:?}, {})", string, e))))
    }
}



/// Table: Details of OIDC4VCI JWT Payload
///
/// POST /credential HTTP/1.1
///   Host: op.dmv.ca.gov
///   Content-Type: application/x-www-form-urlencoded
///   Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ
///
/// type=mdoc_b64u_cbor
/// proof=%7B%22type%22:%22...-ace0-9c5210e16c32%22%7D
///
/// - Example: OIDC4VCI Credential Request
/// - OIDC4VCI Credential Response
/// - If the OIDC4VCI Credential Request was successful,
///     the DMV Service would return a successful credential response as defined below.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// The type of credential being requested.
    /// It corresponds to the credential_type parameter in the OIDC4VCI Initiate
    /// Issuance Request.
    ///
    /// The value must be https://dmv.ca.gov/mdl.
    #[serde(rename = "type")]
    _type: HttpsDmvCaGovMdl,

    /// The format of the credential being requested.
    /// The value must be either mdoc_b64u_cbor or jwt_vc.
    format: CredentialRequestFormat,

    /// A JSON Object containing proof of possession of the key material the
    /// issued credential shall be bound to. The proof object must contain a
    /// proof_type and a jwt element.
    proof: CredentialRequestProofString,
}

/// Table: Details of Successful OIDC4VCI Credential Response
///
/// HTTP/1.1 200 OK
///   Content-Type: application/json
///   Cache-Control: no-store
///   Pragma: no-cache
///
/// {
///   "format": "mdoc_b64u_cbor"
///   "credential" : "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L",
///   "c_nonce": "fGFF7UkhLa",
///   "c_nonce_expires_in": 86400
/// }
///
/// Example: Successful OIDC4VCI Credential Response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialResponse {
    /// The format of the credential,
    /// either ldp_vc (for W3C Verifiable Credential) or mdoc_b64u_cbor
    /// (for ISO 18013-5).
    format: CredentialFormat,

    /// The base64-encoded representation of the credential.
    /// For ldp_vc, it contains the JSON-LD object,
    /// for mdoc:b64u:cbor,
    /// it contains the base64-encoded CBOR serialization of the mDL.
    #[serde(with = "Base64UrlSafeNoPad")]
    credential: Vec<u8>,

    /// String containing a new nonce to be used to create a proof of possession
    /// of key material when requesting a credential.
    c_nonce: String,

    /// Integer denoting the lifetime in seconds of the c_nonce.
    c_nonce_expires_in: u64,
}

impl CredentialResponse {
    // TODO: BETTER EXAMPLE CREDENTIAL
    pub fn example() -> Self {
        // "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L"
        let credential: Vec<u8> = vec![0,1,2,3,4,5,6,7];

        Self {
            format: CredentialFormat::LdpVc,
            credential,
            c_nonce: "fGFF7UkhLa".to_string(),
            c_nonce_expires_in: 86400,
        }
    }
}

/// If the OIDC4VCI Credential Request was unsuccessful because the request did
/// not contain a proof of possession (PoP) or an invalid PoP, the DMV Service
/// returns an error response as defined below.
///
/// Table: Details of OIDC4VCI Credential Error Response (PoP)
///
/// HTTP/1.1 400 Bad Request
///   Content-Type: application/json
///   Cache-Control: no-store
///   Pragma: no-cache
///
/// {
///   "error": "invalid_or_missing_proof"
///   "error_description":
///        "Credential issuer requires proof element in credential request"
///   "c_nonce": "8YE9hCnyV2",
///   "c_nonce_expires_in": 86400
/// }
///
/// Example: OIDC4VCI Credential Error Response (PoP)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialInvalidProof {
    /// The value must be invalid_or_missing_proof.
    error: InvalidOrMissingProof,

    /// The error description.
    error_description: String,

    /// String containing a new nonce to be used to create a proof of possession
    /// of key material when requesting a credential.
    c_nonce: String,

    /// Integer denoting the lifetime in seconds of the c_nonce.
    c_nonce_expires_in: u64,
}

impl CredentialInvalidProof {
    pub fn example() -> Self {
        Self {
            error: InvalidOrMissingProof::InvalidOrMissingProof,
            error_description:
                "Credential issuer requires proof element in credential \
                request".to_string(),
            c_nonce: "8YE9hCnyV2".to_string(),
            c_nonce_expires_in: 86400,
        }
    }
}

/// If the OIDC4VCI Credential Request was unsuccessful because the request was
/// invalid, or contained an expired access_token, or multiple use of
/// access_token per credential type and format, the DMV Service returns an error
/// response as defined below.
///
/// Table: Details of OIDC4VCI Credential Error Response (other)
///
/// HTTP/1.1 400 Bad Request
///   Content-Type: application/json
///   Cache-Control: no-store
///   Pragma: no-cache
///
/// {
///  "error": "invalid_request"
/// }
///
/// Example: OIDC4VCI Token Error Response (other)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialInvalidRequest {
    /// The value must be invalid_request as per OIDC Core.
    error: InvalidRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CredentialError {
    InvalidProof(CredentialInvalidProof),
    InvalidRequest(CredentialInvalidRequest),
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProof(error) => write!(f, "{:?}", error),
            Self::InvalidRequest(error) => write!(f, "{:?}", error),
        }
    }
}

impl actix_web::ResponseError for CredentialError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        actix_web::http::StatusCode::BAD_REQUEST
    }

    fn error_response(&self) -> HttpResponse {
        match self {
            Self::InvalidProof(error) => HttpResponse::BadRequest().json(error),
            Self::InvalidRequest(error) => HttpResponse::BadRequest().json(error),
        }
    }
}

// TODO OAuth2 access_token
/// DEMO FUNCTIONALITY: if request.format == LdpVc, return example else error
///
/// TODO: The OIDC4VCI credential endpoint is protected with the access_token
/// that is sent in the HTTP Authorization header of type Bearer as per OAuth2.
#[post("/credential")]
async fn credential_api(request: web::Form<CredentialRequest>) ->
    Result<HttpResponse, CredentialError> {
    match request.format {
        CredentialRequestFormat::JwtVc =>
            Ok(HttpResponse::Ok().json(CredentialResponse::example())),
        CredentialRequestFormat::MdocB64uCbor =>
            // Err(CredentialError::InvalidProof(CredentialInvalidProof::example())),
            Err(CredentialError::InvalidRequest(CredentialInvalidRequest { error: InvalidRequest::InvalidRequest })),
    }
}

// TODO: /credential


///////////////////////////////////////////////////////////////////////////////////////
//// END OIDC4VCI
///////////////////////////////////////////////////////////////////////////////////////


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Example CredentialRequestProof: \n{:?}\n",
             serde_json::to_string_pretty(&CredentialRequestProof::example()));
             // serde_urlencoded::to_string(CredentialRequestProof::example()));

    let server_root = "127.0.0.1";
    let server_port = 9999;
    let server_address = format!("http://{}:{}", server_root, server_port);
    println!("Starting server at {} ..", server_address);

    let app_state = AppState::new();
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .service(eligibility_api)
            .service(qr_code_api)
            .service(token_api)
            .service(credential_api)
    })
    .bind((server_root, server_port))?
    .run()
    .await
}

