use asn1_rs::{FromDer, Sequence};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::{Any, Decode, SliceReader};
use signature::Verifier;
use x509_cert::{
    crl::{CertificateList, RevokedCert, TbsCertList},
    ext::pkix::{
        name::{DistributionPointName, GeneralName},
        CrlDistributionPoints, CrlReason,
    },
    spki::AlgorithmIdentifierOwned,
    TbsCertificate,
};

#[derive(Debug)]
pub enum Error {
    CertRevoked(Option<CrlReason>),

    UnableToParseCrlExtension(der::Error),
    UnableToParseCrlCertList(der::Error),
    UnableToParseCurveKindExt(der::Error),
    DistributionPointMalformed(&'static str),
    FetchingCrl(reqwest::Error),
    UnableToReachDistributionPoint,
    IssuerMismatchBetweenCertAndCrl,
    UnknownSignatureAlgorithm(Box<AlgorithmIdentifierOwned>),
    SignatureTypeMismatch(Box<AlgorithmIdentifierOwned>, Box<AlgorithmIdentifierOwned>),
    ExtractCrlSequenceSignature(asn1_rs::Err<asn1_rs::Error>),
    UnableToParseCrlReason(der::Error),
    MissingCurve,
    UnknownCurveExt(ObjectIdentifier),
    MissingPublicKey,
    SignatureCheckOfCrlFailed,
    InvalidPublicKeyFormat,
    MissingSignature,
    SignatureInWrongFormat,
}

pub const OID_EC_CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
pub const OID_EC_CURVE_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
pub const OID_PUBLIC_KEY_ELLIPTIC_CURVE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

const OID_EXTENSION_REASON_CODE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.21");

/// Given a cert, download and verify the associated crl listed in the cert, and verify the cert
/// against the crl
pub async fn fetch_and_validate_crl(cert: &TbsCertificate) -> Result<(), Error> {
    let distribution_points = match read_distribution_points(cert)? {
        None => return Ok(()),
        Some(distribution_points) => distribution_points,
    };

    for distribution_point in distribution_points.0.iter() {
        let distribution_point_name = distribution_point.distribution_point.as_ref().ok_or(
            Error::DistributionPointMalformed("missing distributionPoint name"),
        )?;

        let urls = distribution_point_urls(distribution_point_name)?;

        for url in urls.iter() {
            let crl_bytes = fetch_crl(url).await?;

            let tbs_cert_list = validate_crl(cert, &crl_bytes)?;

            check_cert_against_cert_list(cert, &tbs_cert_list)?;
        }
    }

    Ok(())
}

fn distribution_point_urls(name: &DistributionPointName) -> Result<Vec<String>, Error> {
    match name {
        DistributionPointName::FullName(uris) => {
            let uris: Result<Vec<String>, Error> = uris
                .iter()
                .map(|general_name| match general_name {
                    GeneralName::UniformResourceIdentifier(s) => Ok(s.to_string()),
                    _ => Err(Error::DistributionPointMalformed(
                        "distribution point name something other than URI",
                    )),
                })
                .collect();

            uris
        }
        DistributionPointName::NameRelativeToCRLIssuer(_) => Err(
            Error::DistributionPointMalformed("contained relative to issuer name"),
        ),
    }
}

async fn fetch_crl(url: &str) -> Result<Vec<u8>, Error> {
    let bytes = reqwest::get(url)
        .await
        .map_err(Error::FetchingCrl)?
        .bytes()
        .await
        .map_err(Error::FetchingCrl)?;

    Ok(bytes.to_vec())
}

fn read_distribution_points(cert: &TbsCertificate) -> Result<Option<CrlDistributionPoints>, Error> {
    let extensions = match cert.extensions.as_ref() {
        None => return Ok(None),
        Some(extensions) => extensions,
    };

    let crl_extension = match extensions
        .iter()
        .find(|ext| ext.extn_id == CrlDistributionPoints::OID)
    {
        None => return Ok(None),
        Some(crl_extension) => crl_extension,
    };

    let mut der_reader = SliceReader::new(crl_extension.extn_value.as_bytes())
        .map_err(Error::UnableToParseCrlExtension)?;

    let distribution_points =
        CrlDistributionPoints::decode(&mut der_reader).map_err(Error::UnableToParseCrlExtension)?;

    Ok(Some(distribution_points))
}

fn validate_crl(cert: &TbsCertificate, crl_bytes: &[u8]) -> Result<TbsCertList, Error> {
    let (crl_raw, crl) = decode_cert_list(crl_bytes)?;

    if cert.subject_public_key_info.algorithm != crl.signature_algorithm {
        return Err(Error::SignatureTypeMismatch(
            Box::new(cert.subject_public_key_info.algorithm.clone()),
            Box::new(crl.signature_algorithm),
        ));
    }

    match crl.signature_algorithm.oid {
        // OID_SIGNATURE_SHA1WITHRSA => signature_components.verify_sha1_with_rsa(pub_key),
        OID_PUBLIC_KEY_ELLIPTIC_CURVE => {
            let curve =
                CurveKind::try_from(cert.subject_public_key_info.algorithm.parameters.as_ref())?;

            let public_key = cert
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .ok_or(Error::MissingPublicKey)?;

            let mut sec1_public_key = vec![0x01];
            sec1_public_key.extend_from_slice(public_key);

            let signature = crl.signature.as_bytes().ok_or(Error::MissingSignature)?;

            match curve {
                CurveKind::P256 => {
                    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1_public_key)
                        .map_err(|_| Error::InvalidPublicKeyFormat)?;

                    let signature = p256::ecdsa::Signature::from_slice(signature)
                        .map_err(|_| Error::SignatureInWrongFormat)?;

                    key.verify(&crl_raw, &signature)
                        .map_err(|_| Error::SignatureCheckOfCrlFailed)?;

                    Ok(crl.tbs_cert_list)
                }
                CurveKind::P384 => {
                    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1_public_key)
                        .map_err(|_| Error::InvalidPublicKeyFormat)?;

                    let signature = p384::ecdsa::Signature::from_slice(signature)
                        .map_err(|_| Error::SignatureInWrongFormat)?;

                    key.verify(&crl_raw, &signature)
                        .map_err(|_| Error::SignatureCheckOfCrlFailed)?;

                    Ok(crl.tbs_cert_list)
                }
            }
        }
        _ => Err(Error::UnknownSignatureAlgorithm(Box::new(
            crl.signature_algorithm,
        ))),
    }
}

fn decode_cert_list(bytes: &[u8]) -> Result<(Vec<u8>, CertificateList), Error> {
    let (_, top_sequence) =
        Sequence::from_der(bytes).map_err(Error::ExtractCrlSequenceSignature)?;

    let top_sequence_content = top_sequence.into_content();
    let top_sequence_bytes = top_sequence_content.as_ref();

    let (_, cert_list_sequence) =
        Sequence::from_der(top_sequence_bytes).map_err(Error::ExtractCrlSequenceSignature)?;

    let cert_list_content = cert_list_sequence.into_content();
    let cert_list_bytes = cert_list_content.as_ref();

    let cert_list = CertificateList::from_der(bytes).map_err(Error::UnableToParseCrlCertList)?;

    Ok((cert_list_bytes.to_vec(), cert_list))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurveKind {
    P256,
    P384,
}

impl TryFrom<Option<&Any>> for CurveKind {
    type Error = Error;

    fn try_from(ext_bit_string: Option<&Any>) -> Result<Self, Self::Error> {
        let ext_any = ext_bit_string.ok_or(Error::MissingCurve)?;
        let obj_id = ObjectIdentifier::from_der(ext_any.value())
            .map_err(Error::UnableToParseCurveKindExt)?;

        let curve = match obj_id {
            OID_EC_CURVE_P256 => Self::P256,
            OID_EC_CURVE_P384 => Self::P384,
            other => return Err(Error::UnknownCurveExt(other)),
        };

        Ok(curve)
    }
}

fn check_cert_against_cert_list(
    cert: &TbsCertificate,
    cert_list: &TbsCertList,
) -> Result<(), Error> {
    if cert.issuer != cert_list.issuer {
        return Err(Error::IssuerMismatchBetweenCertAndCrl);
    }

    let revoked_certs = match cert_list.revoked_certificates.as_ref() {
        Some(revoked) => revoked,
        None => return Ok(()),
    };

    for revoked_cert in revoked_certs {
        if revoked_cert.serial_number == cert.serial_number {
            let reason = find_reason_code(revoked_cert)?;

            let reason = match reason {
                Some(CrlReason::Unspecified) => None,
                Some(reason) => Some(reason),
                None => None,
            };

            return Err(Error::CertRevoked(reason));
        }
    }

    Ok(())
}

fn find_reason_code(revoked_cert: &RevokedCert) -> Result<Option<CrlReason>, Error> {
    if let Some(exts) = revoked_cert.crl_entry_extensions.as_ref() {
        if let Some(reason_code_ext) = exts
            .iter()
            .find(|ext| ext.extn_id == OID_EXTENSION_REASON_CODE)
        {
            let reason = CrlReason::from_der(reason_code_ext.extn_value.as_bytes())
                .map_err(Error::UnableToParseCrlReason)?;

            return Ok(Some(reason));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CRL_DER: &[u8] = include_bytes!("./crl/testcrl.der");

    #[test]
    fn parse_crl_signature_components() {
        let (raw, cert_list) = decode_cert_list(TEST_CRL_DER).unwrap();

        assert_eq!(3219, raw.len());
        assert_eq!(
            88,
            cert_list
                .tbs_cert_list
                .revoked_certificates
                .as_ref()
                .unwrap()
                .len()
        );
    }
}
