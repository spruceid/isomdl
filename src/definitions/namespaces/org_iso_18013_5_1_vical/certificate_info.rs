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

impl From<CertificateInfos> for ciborium::Value {
    fn from(ci: CertificateInfos) -> ciborium::Value {
        ciborium::Value::Array(ci.0.into_iter().map(|value| value.to_cbor()).collect())
    }
}

#[derive(Debug, Clone, FromJson, ToCbor)]
#[isomdl(crate = "crate")]
pub struct CertificateInfo {
    pub certificate: ByteStr,
    //TODO: check if 20 byte serial number best fits to ByteStr, or the size is correct at all
    pub serial_number: ByteStr,
    pub ski: ByteStr,
    pub doc_type: DocTypes,
    pub certificate_profile: Option<CertificateProfiles>,
    pub issuing_authority: Option<Latin1>,
    //TODO: check for actual country code format: ISO3166-1 or ISO3166-2 depending on the issuing
    pub issuing_country: Option<Alpha2>,
    pub state_or_province_name: Option<Latin1>,
    pub issuer: Option<ByteStr>,
    pub subject: Option<ByteStr>,
    pub not_before: Option<TDate>,
    pub extensions: Option<Extensions>
}