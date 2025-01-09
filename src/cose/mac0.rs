use ::hmac::Hmac;
use coset::cwt::ClaimsSet;
use coset::{
    mac_structure_data, CborSerializable, CoseError, CoseMac0, MacContext,
    RegisteredLabelWithPrivate,
};
use digest::{Mac, MacError};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::cose::{MaybeTagged, SignatureAlgorithm};

/// Prepared `COSE_Mac0` for remote signing.
///
/// To produce a `COSE_Mac0` do the following:
///
/// 1. Set the signature algorithm with [coset::HeaderBuilder::algorithm].
/// 2. Produce a signature remotely, according to the chosen signature algorithm,
///    using the [PreparedCoseMac0::signature_payload] as the payload.
/// 3. Generate the `COSE_Mac0` by passing the produced signature into
///    [PreparedCoseMac0::finalize].
///
/// Example:
/// ```
/// use coset::iana;
/// use digest::Mac;
/// use hex::FromHex;use hmac::Hmac;
/// use sha2::Sha256;
/// use isomdl::cose::mac0::PreparedCoseMac0;
///
/// let key = Vec::<u8>::from_hex("a361316953796d6d6574726963613305622d318f187418681869187318201869187318201874186818651820186b18651879").unwrap();
/// let signer = Hmac::<Sha256>::new_from_slice(&key).expect("failed to create HMAC signer");
/// let protected = coset::HeaderBuilder::new()
///     .algorithm(iana::Algorithm::HMAC_256_256)
///     .build();
/// let unprotected = coset::HeaderBuilder::new().key_id(b"11".to_vec()).build();
/// let builder = coset::CoseMac0Builder::new()
///     .protected(protected)
///     .unprotected(unprotected)
///     .payload(b"This is the content.".to_vec());
/// let prepared = PreparedCoseMac0::new(builder, None, None, true).unwrap();
/// let signature_payload = prepared.signature_payload();
/// let signature = tag(signature_payload, &signer).unwrap();
/// let cose_mac0 = prepared.finalize(signature);
/// fn tag(signature_payload: &[u8], s: &Hmac<Sha256>) -> anyhow::Result<Vec<u8>> {
///     let mut mac = s.clone();
///     mac.reset();
///     mac.update(signature_payload);
///     Ok(mac.finalize().into_bytes().to_vec())
///  }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedCoseMac0 {
    cose_mac0: MaybeTagged<CoseMac0>,
    tag_payload: Vec<u8>,
}

/// Errors that can occur when building, signing or verifying a COSE_Mac0.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the COSE_Mac0 has an attached payload but an detached payload was provided")]
    DoublePayload,
    #[error("the COSE_Mac0 has a detached payload which was not provided")]
    NoPayload,
    #[error("tag did not match the structure expected by the verifier: {0}")]
    MalformedTag(MacError),
    #[error("tag is already present")]
    AlreadyTagged,
    #[error("error occurred when tagging COSE_Mac0: {0}")]
    Tagging(MacError),
    #[error("unable to set ClaimsSet: {0}")]
    UnableToDeserializeIntoClaimsSet(CoseError),
}

/// Result with error type: [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Result for verification of a COSE_Mac0.
#[derive(Debug)]
pub enum VerificationResult {
    Success,
    Failure(String),
    Error(Error),
}

impl VerificationResult {
    /// Result of verification.
    ///
    /// `false` implies the signature is inauthentic or the verification algorithm encountered an
    /// error.
    pub fn is_success(&self) -> bool {
        matches!(self, VerificationResult::Success)
    }

    /// Translate to a std::result::Result.
    ///
    /// Converts failure reasons and errors into a String.
    pub fn into_result(self) -> Result<(), String> {
        match self {
            VerificationResult::Success => Ok(()),
            VerificationResult::Failure(reason) => Err(reason),
            VerificationResult::Error(e) => Err(format!("{}", e)),
        }
    }

    /// Retrieve the error if the verification algorithm encountered an error.
    pub fn into_error(self) -> Option<Error> {
        match self {
            VerificationResult::Error(e) => Some(e),
            _ => None,
        }
    }
}

impl PreparedCoseMac0 {
    pub fn new(
        builder: coset::CoseMac0Builder,
        detached_payload: Option<&[u8]>,
        aad: Option<&[u8]>,
        tagged: bool,
    ) -> Result<Self> {
        let cose_mac0 = builder.build();

        // Check if the payload is present and if it is attached or detached.
        // Needs to be exclusively attached or detached.
        let payload = match (cose_mac0.payload.as_ref(), detached_payload) {
            (Some(_), Some(_)) => return Err(Error::DoublePayload),
            (None, None) => return Err(Error::NoPayload),
            (Some(payload), None) => payload.clone(),
            (None, Some(payload)) => payload.to_vec(),
        };
        // Create the signature payload ot be used later on signing.
        let tag_payload = mac_structure_data(
            MacContext::CoseMac0,
            cose_mac0.protected.clone(),
            aad.unwrap_or_default(),
            &payload,
        );

        Ok(Self {
            cose_mac0: MaybeTagged::new(tagged, cose_mac0),
            tag_payload,
        })
    }

    /// Returns the signature payload that needs to be used to tag it.
    pub fn signature_payload(&self) -> &[u8] {
        &self.tag_payload
    }

    /// Finalize the COSE_Mac0 by adding the tag.
    pub fn finalize(self, tag: Vec<u8>) -> MaybeTagged<CoseMac0> {
        let mut cose_mac0 = self.cose_mac0;
        cose_mac0.inner.tag = tag;
        cose_mac0
    }
}

impl MaybeTagged<CoseMac0> {
    /// Verify that the tag of a `COSE_Mac0` is authentic.
    pub fn verify(
        &self,
        verifier: &Hmac<Sha256>,
        detached_payload: Option<&[u8]>,
        external_aad: Option<&[u8]>,
    ) -> VerificationResult {
        if let Some(RegisteredLabelWithPrivate::Assigned(alg)) =
            self.inner.protected.header.alg.as_ref()
        {
            if verifier.algorithm() != *alg {
                return VerificationResult::Failure(
                    "algorithm in protected headers did not match verifier's algorithm".into(),
                );
            }
        }

        let payload = match (self.inner.payload.as_ref(), detached_payload) {
            (None, None) => return VerificationResult::Error(Error::NoPayload),
            (Some(attached), None) => attached,
            (None, Some(detached)) => detached,
            _ => return VerificationResult::Error(Error::DoublePayload),
        };

        let tag = &self.inner.tag;

        // Create the signature payload ot be used later on signing.
        let tag_payload = mac_structure_data(
            MacContext::CoseMac0,
            self.inner.protected.clone(),
            external_aad.unwrap_or_default(),
            payload,
        );

        let mut mac = verifier.clone();
        mac.reset();
        mac.update(&tag_payload);
        match mac.verify_slice(tag) {
            Ok(()) => VerificationResult::Success,
            Err(e) => VerificationResult::Failure(format!("tag is not authentic: {}", e)),
        }
    }

    /// Retrieve the CWT claims set.
    pub fn claims_set(&self) -> Result<Option<ClaimsSet>> {
        match self.inner.payload.as_ref() {
            None => Ok(None),
            Some(payload) => ClaimsSet::from_slice(payload).map_or_else(
                |e| Err(Error::UnableToDeserializeIntoClaimsSet(e)),
                |c| Ok(Some(c)),
            ),
        }
    }
}

mod hmac {
    use coset::iana;
    use hmac::Hmac;
    use sha2::Sha256;

    use super::super::SignatureAlgorithm;

    impl SignatureAlgorithm for Hmac<Sha256> {
        fn algorithm(&self) -> iana::Algorithm {
            iana::Algorithm::HMAC_256_256
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cbor;
    use crate::cose::mac0::{CoseMac0, PreparedCoseMac0};
    use crate::cose::MaybeTagged;
    use coset::cwt::{ClaimsSet, Timestamp};
    use coset::{iana, CborSerializable, Header};
    use digest::Mac;
    use hex::FromHex;
    use hmac::Hmac;
    use sha2::Sha256;

    static COSE_MAC0: &str = include_str!("../../test/definitions/cose/mac0/serialized.cbor");
    static KEY: &str = include_str!("../../test/definitions/cose/mac0/secret_key");

    const RFC8392_KEY: &str = "6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19";
    const RFC8392_MAC0: &str = "d18443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b715820a377dfe17a3c3c3bdb363c426f85d3c1a1f11007765965017602f207700071b0";

    #[test]
    fn roundtrip() {
        let bytes = Vec::<u8>::from_hex(COSE_MAC0).unwrap();
        let parsed: MaybeTagged<CoseMac0> =
            cbor::from_slice(&bytes).expect("failed to parse COSE_MAC0 from bytes");
        let roundtripped = cbor::to_vec(&parsed).expect("failed to serialize COSE_MAC0");
        assert_eq!(
            bytes, roundtripped,
            "original bytes and roundtripped bytes do not match"
        );
    }

    #[test]
    fn tagging() {
        let key = Vec::<u8>::from_hex(KEY).unwrap();
        let signer = Hmac::<Sha256>::new_from_slice(&key).expect("failed to create HMAC signer");
        let protected = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::HMAC_256_256)
            .build();
        let unprotected = coset::HeaderBuilder::new().key_id(b"11".to_vec()).build();
        let builder = coset::CoseMac0Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(b"This is the content.".to_vec());
        let prepared = PreparedCoseMac0::new(builder, None, None, false).unwrap();
        let signature_payload = prepared.signature_payload();
        let signature = tag(signature_payload, &signer).unwrap();
        let cose_mac0 = prepared.finalize(signature);
        let serialized = cbor::to_vec(&cose_mac0).expect("failed to serialize COSE_MAC0");

        let expected = Vec::<u8>::from_hex(COSE_MAC0).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_MAC0 and signed data do not match"
        );
    }

    fn tag(signature_payload: &[u8], s: &Hmac<Sha256>) -> anyhow::Result<Vec<u8>> {
        let mut mac = s.clone();
        mac.reset();
        mac.update(signature_payload);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    #[test]
    fn verifying() {
        let key = Vec::<u8>::from_hex(KEY).unwrap();
        let verifier =
            Hmac::<Sha256>::new_from_slice(&key).expect("failed to create HMAC verifier");

        let cose_mac0_bytes = Vec::<u8>::from_hex(COSE_MAC0).unwrap();
        let cose_mac0: MaybeTagged<CoseMac0> =
            cbor::from_slice(&cose_mac0_bytes).expect("failed to parse COSE_MAC0 from bytes");

        cose_mac0
            .verify(&verifier, None, None)
            .into_result()
            .expect("COSE_MAC0 could not be verified")
    }

    #[test]
    fn remote_tagging() {
        let key = Vec::<u8>::from_hex(KEY).unwrap();
        let signer = Hmac::<Sha256>::new_from_slice(&key).expect("failed to create HMAC signer");
        let protected = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::HMAC_256_256)
            .build();
        let unprotected = coset::HeaderBuilder::new().key_id(b"11".to_vec()).build();
        let builder = coset::CoseMac0Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(b"This is the content.".to_vec());
        let prepared = PreparedCoseMac0::new(builder, None, None, false).unwrap();
        let signature_payload = prepared.signature_payload();
        let signature = tag(signature_payload, &signer).unwrap();
        let cose_mac0 = prepared.finalize(signature);

        let serialized = cbor::to_vec(&cose_mac0).expect("failed to serialize COSE_MAC0");
        let expected = Vec::<u8>::from_hex(COSE_MAC0).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_MAC0 and signed data do not match"
        );

        let verifier =
            Hmac::<Sha256>::new_from_slice(&key).expect("failed to create HMAC verifier");
        cose_mac0
            .verify(&verifier, None, None)
            .into_result()
            .expect("COSE_MAC0 could not be verified")
    }

    fn rfc8392_example_inputs() -> (Header, Header, ClaimsSet) {
        let protected = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build();

        let unprotected = coset::HeaderBuilder::new()
            .key_id(
                hex::decode("4173796d6d65747269634543445341323536").expect("error decoding key id"),
            )
            .build();

        let claims_set = ClaimsSet {
            issuer: Some("coap://as.example.com".to_string()),
            subject: Some("erikw".to_string()),
            audience: Some("coap://light.example.com".to_string()),
            expiration_time: Some(Timestamp::WholeSeconds(1444064944)),
            not_before: Some(Timestamp::WholeSeconds(1443944944)),
            issued_at: Some(Timestamp::WholeSeconds(1443944944)),
            cwt_id: Some(hex::decode("0b71").unwrap()),
            rest: vec![],
        };

        (protected, unprotected, claims_set)
    }

    #[test]
    fn tagging_cwt() {
        // Using key from RFC8392 example
        let key = hex::decode(RFC8392_KEY).unwrap();
        let signer = Hmac::<Sha256>::new_from_slice(&key).expect("failed to create HMAC signer");
        let (protected, unprotected, claims_set) = rfc8392_example_inputs();
        let builder = coset::CoseMac0Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(claims_set.to_vec().expect("failed to set claims set"));
        let prepared = PreparedCoseMac0::new(builder, None, None, true).unwrap();
        let signature_payload = prepared.signature_payload();
        let signature = tag(signature_payload, &signer).expect("failed to sign CWT");
        let cose_mac0 = prepared.finalize(signature);
        let serialized = cbor::to_vec(&cose_mac0).expect("failed to serialize COSE_MAC0");
        let expected = hex::decode(RFC8392_MAC0).unwrap();

        assert_eq!(
            expected, serialized,
            "expected COSE_MAC0 and signed CWT do not match"
        );
    }

    #[test]
    fn deserializing_tdeserializing_signed_cwtagged_cwt() {
        let cose_mac0_bytes = hex::decode(RFC8392_MAC0).unwrap();
        let cose_mac0: MaybeTagged<CoseMac0> =
            cbor::from_slice(&cose_mac0_bytes).expect("failed to parse COSE_MAC0 from bytes");
        let parsed_claims_set = cose_mac0
            .claims_set()
            .expect("failed to parse claims set from payload")
            .expect("retrieved empty claims set");
        let (_, _, expected_claims_set) = rfc8392_example_inputs();
        assert_eq!(parsed_claims_set, expected_claims_set);
    }
}
