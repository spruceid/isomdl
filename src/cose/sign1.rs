use coset::cwt::ClaimsSet;
use coset::{
    sig_structure_data, CborSerializable, CoseError, CoseSign1, RegisteredLabelWithPrivate,
    SignatureContext,
};
use serde::{Deserialize, Serialize};
use signature::Verifier;

use crate::cose::{MaybeTagged, SignatureAlgorithm};

/// Prepared `COSE_Sign1` for remote signing.
///
/// To produce a `COSE_Sign1,` do the following:
///
/// 1. Set the signature algorithm with [coset::HeaderBuilder::algorithm].
/// 2. Produce a signature remotely, according to the chosen signature algorithm,
///    using the [PreparedCoseSign1::signature_payload] as the payload.
/// 3. Generate the `COSE_Sign1` by passing the produced signature into
///    [PreparedCoseSign1::finalize].
///
/// Example:
/// ```
/// use coset::iana;
/// use hex::FromHex;
/// use p256::ecdsa::{Signature, SigningKey};
/// use p256::SecretKey;
/// use signature::{SignatureEncoding, Signer, SignerMut};
/// use isomdl::cose::sign1::{Error, PreparedCoseSign1};
/// use isomdl::cose::SignatureAlgorithm;
///
/// let key = Vec::<u8>::from_hex("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap();
/// let signer: SigningKey = SecretKey::from_slice(&key).unwrap().into();
/// let protected = coset::HeaderBuilder::new()
///     .algorithm(iana::Algorithm::ES256)
///     .build();
/// let unprotected = coset::HeaderBuilder::new().key_id(b"11".to_vec()).build();
/// let builder = coset::CoseSign1Builder::new()
///     .protected(protected)
///     .unprotected(unprotected)
///     .payload(b"This is the content.".to_vec());
/// let prepared = PreparedCoseSign1::new(builder, None, None, true).unwrap();
/// let signature_payload = prepared.signature_payload();
/// let signature = sign::<SigningKey, Signature>(signature_payload, &signer).unwrap();
/// let cose_sign1 = prepared.finalize(signature);
///
/// fn sign<S, Sig>(signature_payload: &[u8], s: &S) -> anyhow::Result<Vec<u8>>
/// where
///     S: Signer<Sig> + SignatureAlgorithm,
///     Sig: SignatureEncoding,
/// {
///     Ok(s.try_sign(signature_payload)
///         .map_err(Error::Signing)?
///         .to_vec())
/// }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedCoseSign1 {
    cose_sign1: MaybeTagged<CoseSign1>,
    #[serde(with = "serde_bytes")] // This optimizes (de)serialization of byte vectors
    signature_payload: Vec<u8>,
}

/// Errors that can occur when building, signing or verifying a COSE_Sign1.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the COSE_Sign1 has an attached payload but an detached payload was provided")]
    DoublePayload,
    #[error("the COSE_Sign1 has a detached payload which was not provided")]
    NoPayload,
    #[error("signature did not match the structure expected by the verifier: {0}")]
    MalformedSignature(signature::Error),
    #[error("signature is already present")]
    AlreadySigned,
    #[error("error occurred when signing COSE_Sign1: {0}")]
    Signing(signature::Error),
    #[error("unable to set ClaimsSet: {0}")]
    UnableToDeserializeIntoClaimsSet(CoseError),
}

/// Result with error type: [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Result for verification of a COSE_Sign1.
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

impl PreparedCoseSign1 {
    pub fn new(
        builder: coset::CoseSign1Builder,
        detached_payload: Option<&[u8]>,
        aad: Option<&[u8]>,
        tagged: bool,
    ) -> Result<Self> {
        let cose_sign1 = builder.build();

        // Check if the payload is present and if it is attached or detached.
        // Needs to be exclusively attached or detached.
        let payload = match (cose_sign1.payload.as_ref(), detached_payload) {
            (Some(_), Some(_)) => return Err(Error::DoublePayload),
            (None, None) => return Err(Error::NoPayload),
            (Some(payload), None) => payload.clone(),
            (None, Some(payload)) => payload.to_vec(),
        };
        // Create the signature payload ot be used later on signing.
        let signature_payload = sig_structure_data(
            SignatureContext::CoseSign1,
            cose_sign1.protected.clone(),
            None,
            aad.unwrap_or_default(),
            &payload,
        );

        Ok(Self {
            cose_sign1: MaybeTagged::new(tagged, cose_sign1),
            signature_payload,
        })
    }

    /// Returns the signature payload that needs to be used to sign.
    pub fn signature_payload(&self) -> &[u8] {
        &self.signature_payload
    }

    /// Finalize the COSE_Sign1 by adding the signature.
    pub fn finalize(self, signature: Vec<u8>) -> MaybeTagged<CoseSign1> {
        let mut cose_sign1 = self.cose_sign1;
        cose_sign1.inner.signature = signature;
        cose_sign1
    }
}

impl MaybeTagged<CoseSign1> {
    /// Verify that the signature of a COSE_Sign1 is authentic.
    pub fn verify<'a, V, S>(
        &'a self,
        verifier: &V,
        detached_payload: Option<&[u8]>,
        external_aad: Option<&[u8]>,
    ) -> VerificationResult
    where
        V: Verifier<S> + SignatureAlgorithm,
        S: TryFrom<&'a [u8]>,
        S::Error: Into<signature::Error>,
    {
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

        let signature = match S::try_from(self.inner.signature.as_ref())
            .map_err(Into::into)
            .map_err(Error::MalformedSignature)
        {
            Ok(sig) => sig,
            Err(e) => return VerificationResult::Error(e),
        };

        let signature_payload = sig_structure_data(
            SignatureContext::CoseSign1,
            self.inner.protected.clone(),
            None,
            external_aad.unwrap_or_default(),
            payload,
        );

        match verifier.verify(&signature_payload, &signature) {
            Ok(()) => VerificationResult::Success,
            Err(e) => VerificationResult::Failure(format!("signature is not authentic: {}", e)),
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

mod p256 {
    use coset::iana;
    use p256::ecdsa::{SigningKey, VerifyingKey};

    use crate::cose::SignatureAlgorithm;

    impl SignatureAlgorithm for SigningKey {
        fn algorithm(&self) -> iana::Algorithm {
            iana::Algorithm::ES256
        }
    }

    impl SignatureAlgorithm for VerifyingKey {
        fn algorithm(&self) -> iana::Algorithm {
            iana::Algorithm::ES256
        }
    }
}

mod p384 {
    use coset::iana;
    use p384::ecdsa::{SigningKey, VerifyingKey};

    use crate::cose::SignatureAlgorithm;

    impl SignatureAlgorithm for SigningKey {
        fn algorithm(&self) -> iana::Algorithm {
            iana::Algorithm::ES384
        }
    }

    impl SignatureAlgorithm for VerifyingKey {
        fn algorithm(&self) -> iana::Algorithm {
            iana::Algorithm::ES384
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cbor;
    use crate::cose::sign1::{CoseSign1, Error, PreparedCoseSign1};
    use crate::cose::{MaybeTagged, SignatureAlgorithm};
    use coset::cwt::{ClaimsSet, Timestamp};
    use coset::{iana, CborSerializable, Header};
    use hex::FromHex;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use p256::SecretKey;
    use signature::{SignatureEncoding, Signer};

    static COSE_SIGN1: &str = include_str!("../../test/definitions/cose/sign1/serialized.cbor");
    static COSE_KEY: &str = include_str!("../../test/definitions/cose/sign1/secret_key");

    const RFC8392_KEY: &str = "6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19";
    const RFC8392_COSE_SIGN1: &str = "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30";

    #[test]
    fn roundtrip() {
        let bytes = Vec::<u8>::from_hex(COSE_SIGN1).unwrap();
        let parsed: MaybeTagged<CoseSign1> =
            cbor::from_slice(&bytes).expect("failed to parse COSE_Sign1 from bytes");
        let roundtripped = cbor::to_vec(&parsed).expect("failed to serialize COSE_Sign1 to bytes");
        assert_eq!(
            bytes, roundtripped,
            "original bytes and roundtripped bytes do not match"
        );
    }

    #[test]
    fn roundtrip_ciborium() {
        let bytes = Vec::<u8>::from_hex(COSE_SIGN1).unwrap();
        let parsed: MaybeTagged<CoseSign1> =
            cbor::from_slice(&bytes).expect("failed to parse COSE_MAC0 from bytes");
        let roundtripped = cbor::to_vec(&parsed).expect("failed to serialize COSE_Sign1 to bytes");
        println!("bytes: {:?}", hex::encode(&bytes));
        println!("roundtripped: {:?}", hex::encode(&roundtripped));
        assert_eq!(
            bytes, roundtripped,
            "original bytes and roundtripped bytes do not match"
        );
    }

    #[test]
    fn signing() {
        let key = Vec::<u8>::from_hex(COSE_KEY).unwrap();
        let signer: SigningKey = SecretKey::from_slice(&key).unwrap().into();
        let protected = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build();
        let unprotected = coset::HeaderBuilder::new().key_id(b"11".to_vec()).build();
        let builder = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(b"This is the content.".to_vec());
        let prepared = PreparedCoseSign1::new(builder, None, None, false).unwrap();
        let signature_payload = prepared.signature_payload();
        let signature = sign::<SigningKey, Signature>(signature_payload, &signer).unwrap();
        let cose_sign1 = prepared.finalize(signature);
        let serialized =
            cbor::to_vec(&cose_sign1).expect("failed to serialize COSE_Sign1 to bytes");

        let expected = Vec::<u8>::from_hex(COSE_SIGN1).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_Sign1 and signed data do not match"
        );
    }

    fn sign<S, Sig>(signature_payload: &[u8], s: &S) -> anyhow::Result<Vec<u8>>
    where
        S: Signer<Sig> + SignatureAlgorithm,
        Sig: SignatureEncoding,
    {
        Ok(s.try_sign(signature_payload)
            .map_err(Error::Signing)?
            .to_vec())
    }

    #[test]
    fn verifying() {
        let key = Vec::<u8>::from_hex(COSE_KEY).unwrap();
        let signer: SigningKey = SecretKey::from_slice(&key).unwrap().into();
        let verifier: VerifyingKey = (&signer).into();

        let cose_sign1_bytes = Vec::<u8>::from_hex(COSE_SIGN1).unwrap();
        let cose_sign1: MaybeTagged<CoseSign1> =
            cbor::from_slice(&cose_sign1_bytes).expect("failed to parse COSE_Sign1 from bytes");

        cose_sign1
            .verify::<VerifyingKey, Signature>(&verifier, None, None)
            .into_result()
            .expect("COSE_Sign1 could not be verified")
    }

    #[test]
    fn remote_signed() {
        let key = Vec::<u8>::from_hex(COSE_KEY).unwrap();
        let signer: SigningKey = SecretKey::from_slice(&key).unwrap().into();
        let protected = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build();
        let unprotected = coset::HeaderBuilder::new().key_id(b"11".to_vec()).build();
        let builder = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(b"This is the content.".to_vec());
        let prepared = PreparedCoseSign1::new(builder, None, None, false).unwrap();
        let signature_payload = prepared.signature_payload();
        let signature = sign::<SigningKey, Signature>(signature_payload, &signer).unwrap();
        let cose_sign1 = prepared.finalize(signature);

        let serialized =
            cbor::to_vec(&cose_sign1.clone()).expect("failed to serialize COSE_Sign1 to bytes");

        let expected = Vec::<u8>::from_hex(COSE_SIGN1).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_Sign1 and signed data do not match"
        );

        let verifier: VerifyingKey = (&signer).into();
        cose_sign1
            .verify::<VerifyingKey, Signature>(&verifier, None, None)
            .into_result()
            .expect("COSE_Sign1 could not be verified")
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
    fn signing_cwt() {
        // Using key from RFC8392 example
        let key = hex::decode(RFC8392_KEY).unwrap();
        let signer: SigningKey = SecretKey::from_slice(&key).unwrap().into();
        let (protected, unprotected, claims_set) = rfc8392_example_inputs();
        let builder = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(claims_set.to_vec().expect("failed to set claims set"));
        let prepared = PreparedCoseSign1::new(builder, None, None, true).unwrap();
        let signature_payload = prepared.signature_payload();
        let signature =
            sign::<SigningKey, Signature>(signature_payload, &signer).expect("failed to sign CWT");
        let cose_sign1 = prepared.finalize(signature);
        let serialized =
            cbor::to_vec(&cose_sign1).expect("failed to serialize COSE_Sign1 to bytes");
        let expected = hex::decode(RFC8392_COSE_SIGN1).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_Sign1 and signed CWT do not match"
        );
    }

    #[test]
    fn deserializing_signed_cwt() {
        let cose_sign1_bytes = hex::decode(RFC8392_COSE_SIGN1).unwrap();
        let cose_sign1: MaybeTagged<CoseSign1> =
            cbor::from_slice(&cose_sign1_bytes).expect("failed to parse COSE_Sign1 from bytes");
        let parsed_claims_set = cose_sign1
            .claims_set()
            .expect("failed to parse claims set from payload")
            .expect("retrieved empty claims set");
        let (_, _, expected_claims_set) = rfc8392_example_inputs();
        assert_eq!(parsed_claims_set, expected_claims_set);
    }

    #[test]
    fn tag_coset_tagged_roundtrip() {
        // this is tagged
        let bytes = hex::decode(RFC8392_COSE_SIGN1).unwrap();

        // can parse tagged value
        let parsed: MaybeTagged<CoseSign1> = cbor::from_slice(&bytes).unwrap();
        assert!(parsed.is_tagged());
        println!("successfully deserialized Value from tagged bytes");

        let roundtrip = cbor::to_vec(&parsed).unwrap();
        assert_eq!(bytes, roundtrip);
    }
}
