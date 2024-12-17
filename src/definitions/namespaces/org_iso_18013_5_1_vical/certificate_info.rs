use std::collections::BTreeMap;
use std::str::FromStr;
use crate::{
    definitions::{
        helpers::ByteStr,
        namespaces::{
            latin1::Latin1,
            org_iso_18013_5_1::{Alpha2, TDate},
            org_iso_18013_5_1_vical::{Extensions, certificate_profile::CertificateProfiles, doc_type::DocTypes}},
        traits::ToCbor},
    macros::{FromJson, ToCbor},
};
//CertificateInfo = {
// "certificate" : bstr
// "serialNumber" : biguint
// "ski" : bstr
// "docType" : [+ DocType] ; DocType for which the certificate may be used as a trust point
// ? "certificateProfile" : [+ CertificateProfile] ; Type of certificate
// ? "issuingAuthority" : tstr ; Name of the certificate issuing authority
// ? "issuingCountry" : tstr ; ISO3166-1 or ISO3166-2 depending on the issuing authority
// ? "stateOrProvinceName" : tstr ; State or province name of the certificate issuing authority
// ? "issuer" : bstr ; DER-encoded Issuer field of the certificate (i.e. the complete Name structure)
// ? "subject" : bstr ; DER-encoded Subject field of the certificate (i.e. the complete Name structure)
// ? "notBefore" : tdate
// ? "notAfter" : tdate
// ? "extensions" : Extensions
// * tstr => any ;
// }
#[derive(Clone, Debug, FromJson)]
#[isomdl(crate = "crate")]
pub struct CertificateInfos(Vec<CertificateInfo>);

impl CertificateInfos {
    pub fn new(infos: Vec<CertificateInfo>) -> Self {
        Self(infos)
    }
}

impl From<CertificateInfos> for ciborium::Value {
    fn from(ci: CertificateInfos) -> ciborium::Value {
        ciborium::Value::Array(ci.0.into_iter().map(|value| value.to_cbor()).collect())
    }
}

#[derive(Debug, Clone, FromJson, ToCbor)]
#[isomdl(crate = "crate")]
pub struct CertificateInfo {
    pub certificate: ByteStr,
    pub serial_number: ByteStr,
    pub ski: ByteStr,
    pub doc_type: DocTypes,
    pub certificate_profile: Option<CertificateProfiles>,
    pub issuing_authority: Option<Latin1>,
    pub issuing_country: Option<Alpha2>,
    pub state_or_province_name: Option<Latin1>,
    pub issuer: Option<ByteStr>,
    pub subject: Option<ByteStr>,
    pub not_before: Option<TDate>,
    pub extensions: Option<Extensions>
}

pub struct CertificateInfoBuilder {
    pub certificate: Vec<u8>,
    pub serial_number: Vec<u8>,
    pub ski: Vec<u8>,
    pub doc_type: Vec<String>,
    pub certificate_profile: Option<Vec<String>>,
    pub issuing_authority: Option<String>,
    pub issuing_country: Option<String>,
    pub state_or_province_name: Option<String>,
    pub issuer: Option<Vec<u8>>,
    pub subject: Option<Vec<u8>>,
    pub not_before: Option<String>,
    pub extensions: Option<BTreeMap<String, Vec<u8>>>,
}
impl CertificateInfoBuilder {
    pub fn new(certificate: Vec<u8>, serial_number: Vec<u8>, ski: Vec<u8>, doc_type: Vec<String>) -> Self {
        CertificateInfoBuilder {
            certificate,
            serial_number,
            ski,
            doc_type,
            certificate_profile: None,
            issuing_authority: None,
            issuing_country: None,
            state_or_province_name: None,
            issuer: None,
            subject: None,
            not_before: None,
            extensions: None,
        }
    }
    pub fn certificate_profile(mut self, profiles: Vec<String>) -> Self {
        self.certificate_profile = Some(profiles);
        self
    }
    pub fn issuing_authority(mut self, authority: String) -> Self {
        self.issuing_authority = Some(authority);
        self
    }
    pub fn issuing_country(mut self, country: String) -> Self {
        self.issuing_country = Some(country);
        self
    }
    pub fn state_or_province_name(mut self, state_or_province_name: String) -> Self {
        self.state_or_province_name = Some(state_or_province_name);
        self
    }
    pub fn issuer(mut self, issuer: Vec<u8>) -> Self {
        self.issuer = Some(issuer);
        self
    }
    pub fn subject(mut self, subject: Vec<u8>) -> Self {
        self.subject = Some(subject);
        self
    }
    pub fn not_before(mut self, not_before: String) -> Self {
        self.not_before = Some(not_before);
        self
    }
    pub fn extensions(mut self, extensions: BTreeMap<String, Vec<u8>>) -> Self {
        self.extensions = Some(extensions);
        self
    }
    pub fn build(self) -> CertificateInfo {
        CertificateInfo {
            certificate: ByteStr::from(self.certificate),
            serial_number: ByteStr::from(self.serial_number),
            ski: ByteStr::from(self.ski),
            doc_type: DocTypes::new(self.doc_type),
            certificate_profile: match self.certificate_profile {
                Some(p) => Some(CertificateProfiles::new(p)),
                None => None,
            },
            issuing_authority: match self.issuing_authority {
                Some(s) => Some(Latin1::from_str(s.as_str()).unwrap()),
                None => None
            },
            issuing_country: self.issuing_country.map(|c| Alpha2::from_str(c.as_str()).unwrap()),
            state_or_province_name: self.state_or_province_name.map(|s| Latin1::from_str(s.as_str()).unwrap()),
            issuer: self.issuer.map(ByteStr::from),
            subject: self.subject.map(ByteStr::from),
            not_before: match self.not_before {
                Some(s) => Some(TDate::from_str(s.as_str()).unwrap()),
                None => None,
            },
            extensions: match self.extensions {
                Some(s) => Some(Extensions::new(s)),
                None => None,
            },
        }
    }
}