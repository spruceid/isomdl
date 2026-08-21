use elliptic_curve::sec1::ToEncodedPoint;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use p256::SecretKey;
use time::OffsetDateTime;

use crate::definitions::device_key::cose_key::{CoseKey, EC2Curve, EC2Y};
use crate::definitions::namespaces::{
    org_iso_18013_5_1::OrgIso1801351, org_iso_18013_5_1_aamva::OrgIso1801351Aamva,
};
use crate::definitions::traits::{FromJson, ToNamespaceMap};

use super::*;

static ISSUER_CERT: &[u8] = include_bytes!("../../test/issuance/issuer-cert.pem");
static ISSUER_KEY: &str = include_str!("../../test/issuance/issuer-key.pem");

fn isomdl_data() -> serde_json::Value {
    serde_json::json!(
        {
          "family_name":"Smith",
          "given_name":"Alice",
          "birth_date":"1980-01-01",
          "issue_date":"2020-01-01",
          "expiry_date":"2030-01-01",
          "issuing_country":"US",
          "issuing_authority":"NY DMV",
          "document_number":"DL12345678",
          "portrait":include_str!("../../test/issuance/portrait.b64"),
          "driving_privileges":[
            {
               "vehicle_category_code":"A",
               "issue_date":"2020-01-01",
               "expiry_date":"2030-01-01"
            },
            {
               "vehicle_category_code":"B",
               "issue_date":"2020-01-01",
               "expiry_date":"2030-01-01"
            }
          ],
          "un_distinguishing_sign":"USA",
          "administrative_number":"ABC123",
          "sex":1,
          "height":170,
          "weight":70,
          "eye_colour":"hazel",
          "hair_colour":"red",
          "birth_place":"Canada",
          "resident_address":"138 Eagle Street",
          "portrait_capture_date":"2020-01-01T12:00:00Z",
          "age_in_years":43,
          "age_birth_year":1980,
          "age_over_18":true,
          "age_over_21":true,
          "issuing_jurisdiction":"US-NY",
          "nationality":"US",
          "resident_city":"Albany",
          "resident_state":"New York",
          "resident_postal_code":"12202-1719",
          "resident_country": "US"
        }
    )
}

fn aamva_isomdl_data() -> serde_json::Value {
    serde_json::json!(
        {
          "domestic_driving_privileges":[
            {
              "domestic_vehicle_class":{
                "domestic_vehicle_class_code":"A",
                "domestic_vehicle_class_description":"unknown",
                "issue_date":"2020-01-01",
                "expiry_date":"2030-01-01"
              }
            },
            {
              "domestic_vehicle_class":{
                "domestic_vehicle_class_code":"B",
                "domestic_vehicle_class_description":"unknown",
                "issue_date":"2020-01-01",
                "expiry_date":"2030-01-01"
              }
            }
          ],
          "name_suffix":"1ST",
          "organ_donor":1,
          "veteran":1,
          "family_name_truncation":"N",
          "given_name_truncation":"N",
          "aka_family_name.v2":"Smithy",
          "aka_given_name.v2":"Ally",
          "aka_suffix":"I",
          "weight_range":3,
          "race_ethnicity":"AI",
          "EDL_credential":1,
          "sex":1,
          "DHS_compliance":"F",
          "resident_county":"001",
          "hazmat_endorsement_expiration_date":"2024-01-30",
          "CDL_indicator":1,
          "DHS_compliance_text":"Compliant",
          "DHS_temporary_lawful_status":1,
        }
    )
}

#[test]
fn issue_minimal_mdoc() -> anyhow::Result<()> {
    minimal_test_mdoc()?;
    Ok(())
}

/// The point of [`issue_test_mdoc`]: the chain it embeds is one a test can trust.
#[tokio::test]
async fn issued_test_mdoc_chain_validates() -> anyhow::Result<()> {
    use crate::definitions::x509::{test::TestPki, validation::ValidationRuleset};

    let pki = TestPki::issuer();
    let mdoc = issue_test_mdoc(&pki, MDL_DOC_TYPE, valid_for_a_year())?;

    // The chain travels in the issuer_auth unprotected header, which is where a
    // reader will look for it.
    let x5chain = X5Chain::from_cbor(
        mdoc.issuer_auth
            .unprotected
            .rest
            .iter()
            .find(|(label, _)| {
                label
                    == &coset::Label::Int(
                        crate::definitions::x509::x5chain::X5CHAIN_COSE_HEADER_LABEL,
                    )
            })
            .map(|(_, value)| value.clone())
            .expect("issued mdoc has no x5chain header"),
    )?;

    let outcome = ValidationRuleset::Mdl
        .validate(&x5chain, &pki.iaca_registry(), &pki.fetcher())
        .await;
    assert!(outcome.success(), "{outcome:?}");
    Ok(())
}

/// [`TestPki::reader`] mints a chain the reader ruleset accepts, which is what makes it
/// usable for holder-side tests.
#[tokio::test]
async fn test_reader_pki_chain_validates() {
    use crate::definitions::x509::{
        test::TestPki, trust_anchor::TrustPurpose, validation::ValidationRuleset,
    };

    let pki = TestPki::reader();
    let outcome = ValidationRuleset::MdlReaderOneStep
        .validate(
            &pki.x5chain(),
            &pki.registry(TrustPurpose::ReaderCa),
            &pki.fetcher(),
        )
        .await;
    assert!(outcome.success(), "{outcome:?}");
}

/// [`TestPki::fetcher_revoking`] and [`TestPki::leaf_serial`] together produce a CRL that
/// actually names this PKI's own signer, which is what makes revocation testable.
#[tokio::test]
async fn a_revoked_leaf_is_rejected() {
    use crate::definitions::x509::{test::TestPki, validation::ValidationRuleset};

    let pki = TestPki::issuer();
    let outcome = ValidationRuleset::Mdl
        .validate(
            &pki.x5chain(),
            &pki.iaca_registry(),
            &pki.fetcher_revoking(&[pki.leaf_serial()]),
        )
        .await;
    assert!(!outcome.success(), "a revoked signer should not validate");
}

/// [`issue_test_mdoc_with_namespaces`] carries attributes that have nothing to do with
/// `org.iso.18013.5.1`, which is what a non-mDL credential needs.
#[test]
fn an_mdoc_can_be_issued_with_its_own_namespaces() -> anyhow::Result<()> {
    use crate::definitions::x509::test::TestPki;

    let namespaces: Namespaces = [(
        "com.example.credential.1".to_string(),
        [(
            "favourite_colour".to_string(),
            ciborium::Value::Text("blue".to_string()),
        )]
        .into_iter()
        .collect(),
    )]
    .into_iter()
    .collect();

    let mdoc = issue_test_mdoc_with_namespaces(
        &TestPki::issuer(),
        "com.example.credential.1",
        valid_for_a_year(),
        namespaces,
    )?;

    assert!(mdoc.namespaces.contains_key("com.example.credential.1"));
    Ok(())
}

pub use crate::definitions::MDL_DOC_TYPE;

/// A validity window that is open now and stays open for a year.
///
/// A `valid_until` of `now()` produces credentials that
/// were expired the instant they were issued — harmless while nothing checked, but a
/// trap once MSO validity is enforced.
pub fn valid_for_a_year() -> ValidityInfo {
    let now = OffsetDateTime::now_utc();
    ValidityInfo {
        signed: now,
        valid_from: now,
        valid_until: now + time::Duration::days(365),
        expected_update: None,
    }
}

/// A validity window that closed an hour ago.
pub fn expired() -> ValidityInfo {
    let now = OffsetDateTime::now_utc();
    ValidityInfo {
        signed: now - time::Duration::days(2),
        valid_from: now - time::Duration::days(2),
        valid_until: now - time::Duration::hours(1),
        expected_update: None,
    }
}

/// A validity window that has not opened yet.
pub fn not_yet_valid() -> ValidityInfo {
    let now = OffsetDateTime::now_utc();
    ValidityInfo {
        signed: now,
        valid_from: now + time::Duration::hours(1),
        valid_until: now + time::Duration::days(365),
        expected_update: None,
    }
}

fn minimal_test_mdoc_builder() -> Builder {
    minimal_test_mdoc_builder_for(MDL_DOC_TYPE, valid_for_a_year())
}

/// [`minimal_test_mdoc_builder`] with the doc type and validity window chosen by the
/// caller. The namespaces are the mDL ones regardless of doc type — tests that care
/// about the doc type do not care what is inside it.
fn minimal_test_mdoc_builder_for(doc_type: &str, validity_info: ValidityInfo) -> Builder {
    let doc_type = doc_type.to_string();
    let isomdl_namespace = String::from("org.iso.18013.5.1");
    let aamva_namespace = String::from("org.iso.18013.5.1.aamva");

    let isomdl_data = OrgIso1801351::from_json(&isomdl_data())
        .unwrap()
        .to_ns_map();
    let aamva_data = OrgIso1801351Aamva::from_json(&aamva_isomdl_data())
        .unwrap()
        .to_ns_map();

    let namespaces = [
        (isomdl_namespace, isomdl_data),
        (aamva_namespace, aamva_data),
    ]
    .into_iter()
    .collect();

    let digest_algorithm = DigestAlgorithm::SHA256;

    let der = include_str!("../../test/issuance/device_key.b64");
    let der_bytes = base64::decode(der).unwrap();
    let key = p256::SecretKey::from_sec1_der(&der_bytes).unwrap();
    let pub_key = key.public_key();
    let ec = pub_key.to_encoded_point(false);
    let x = ec.x().unwrap().to_vec();
    let y = EC2Y::Value(ec.y().unwrap().to_vec());
    let device_key = CoseKey::EC2 {
        crv: EC2Curve::P256,
        x,
        y,
    };

    let device_key_info = DeviceKeyInfo {
        device_key,
        key_authorizations: None,
        key_info: None,
    };

    Mdoc::builder()
        .doc_type(doc_type)
        .namespaces(namespaces)
        .validity_info(validity_info)
        .digest_algorithm(digest_algorithm)
        .device_key_info(device_key_info)
}

/// Issue an mdoc under a [`TestPki`], so that the resulting chain validates against
/// `pki.iaca_registry()`.
///
/// [`minimal_test_mdoc`] cannot do this: it signs with the committed
/// `test/issuance` key, whose certificate is not under any root a test controls.
///
/// The device key is the one in `test/issuance/device_key.b64`, so
/// `Device::create_signing_key()` can produce the matching DeviceAuth signature.
pub(crate) fn issue_test_mdoc(
    pki: &crate::definitions::x509::test::TestPki,
    doc_type: &str,
    validity_info: ValidityInfo,
) -> anyhow::Result<Mdoc> {
    Ok(minimal_test_mdoc_builder_for(doc_type, validity_info)
        .issue::<SigningKey, Signature>(pki.x5chain(), pki.leaf_key.clone())
        .expect("failed to issue mdoc"))
}

/// Issue an mdoc carrying `namespaces` rather than the built-in mDL ones.
///
/// Needed to exercise a credential from another ecosystem, whose attributes live under
/// its own namespace and have nothing to do with `org.iso.18013.5.1`.
pub(crate) fn issue_test_mdoc_with_namespaces(
    pki: &crate::definitions::x509::test::TestPki,
    doc_type: &str,
    validity_info: ValidityInfo,
    namespaces: Namespaces,
) -> anyhow::Result<Mdoc> {
    Ok(minimal_test_mdoc_builder_for(doc_type, validity_info)
        .namespaces(namespaces)
        .issue::<SigningKey, Signature>(pki.x5chain(), pki.leaf_key.clone())
        .expect("failed to issue mdoc"))
}

pub fn minimal_test_mdoc() -> anyhow::Result<Mdoc> {
    let mdoc_builder = minimal_test_mdoc_builder();

    let x5chain = X5Chain::builder()
        .with_pem_certificate(ISSUER_CERT)
        .unwrap()
        .build()
        .unwrap();
    let signer: SigningKey = SecretKey::from_pkcs8_pem(ISSUER_KEY)
        .expect("failed to parse pem")
        .into();

    Ok(mdoc_builder
        .issue::<SigningKey, Signature>(x5chain, signer)
        .expect("failed to issue mdoc"))
}

#[test]
fn decoy_digests() {
    let mdoc_builder = minimal_test_mdoc_builder();
    let x5chain = X5Chain::builder()
        .with_pem_certificate(ISSUER_CERT)
        .unwrap()
        .build()
        .unwrap();
    let signer: SigningKey = SecretKey::from_pkcs8_pem(ISSUER_KEY)
        .expect("failed to parse pem")
        .into();

    let mdoc_decoy = &mdoc_builder
        .clone()
        .issue::<SigningKey, Signature>(x5chain.clone(), signer.clone())
        .unwrap();

    let mdoc_builder = mdoc_builder.enable_decoy_digests(false);
    let mdoc_no_decoy_1 = &mdoc_builder
        .clone()
        .issue::<SigningKey, Signature>(x5chain.clone(), signer.clone())
        .unwrap();
    let mdoc_no_decoy_2 = &mdoc_builder
        .issue::<SigningKey, Signature>(x5chain, signer)
        .unwrap();

    // Asserting on number of digests
    assert_eq!(
        mdoc_decoy
            .namespaces
            .values()
            .fold(0, |acc, x| acc + x.len()),
        mdoc_no_decoy_1
            .namespaces
            .values()
            .fold(0, |acc, x| acc + x.len()),
    );
    assert_ne!(
        mdoc_decoy
            .mso
            .value_digests
            .values()
            .fold(0, |acc, x| acc + x.len()),
        mdoc_no_decoy_1
            .mso
            .value_digests
            .values()
            .fold(0, |acc, x| acc + x.len()),
    );
    assert_eq!(
        mdoc_no_decoy_1
            .mso
            .value_digests
            .values()
            .fold(0, |acc, x| acc + x.len()),
        mdoc_no_decoy_2
            .mso
            .value_digests
            .values()
            .fold(0, |acc, x| acc + x.len()),
    );
}
