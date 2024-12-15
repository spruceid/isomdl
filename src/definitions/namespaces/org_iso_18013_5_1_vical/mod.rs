mod certificate_info;
mod extension;
mod certificate_profile;
mod doc_type;
mod vical_cose_sign1;

pub use certificate_info::CertificateInfos;
pub use extension::Extensions;
pub use super::latin1::Latin1;
pub use super::org_iso_18013_5_1::TDate;
use crate::macros::{FromJson, ToCbor};

//VICAL = {
// "version" : tstr
// "vicalProvider" : tstr
// "date" : tdate
// ? "vicalIssueID" : uint unique and monotonically increasing
// ? "nextUpdate" : tdate date-time
// "certificateInfos" : [*CertificateInfo]
// ? "extensions" : Extensions * tstr => any

#[derive(Debug, Clone, FromJson, ToCbor)]
#[isomdl(crate = "crate")]
pub struct OrgIso1901351Vical {
    pub version: Latin1,
    pub vical_provider: Latin1,
    pub date: TDate,
    pub vical_issue_id: Option<u32>,
    pub next_update: Option<TDate>,
    pub certificate_infos: CertificateInfos,
    pub extensions: Option<Extensions>,
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::definitions::traits::FromJson;

    static JSON_VICAL: &str = include_str!("../../../../test/definitions/namespaces/org_iso_18013_5_1_vical/vical.json");
    #[test]
    fn all() {
        let json_vical: serde_json::Value = serde_json::from_str(JSON_VICAL).unwrap();
        let vical = OrgIso1901351Vical::from_json(&json_vical).unwrap();
        assert!(vical.vical_issue_id.is_some());
        assert!(vical.next_update.is_some());
    }
}