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
    #[test]
    fn all() {
        let json = serde_json::json!({
            "version": "1.0.0",
            "vical_provider": "Spruce",
            "date": "2024-12-31T12:00:00Z",
            "vical_issue_id": 1,
            "next_update": "2022-03-21T13:30:00Z",
            "certificate_infos": [
                {
                    "certificate": "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3",
                    "serial_number": "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3",
                    "ski": "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3",
                    "doc_type": ["somedoc"],
                    "certificate_profile": ["profile"],
                    "extensions": {"extension_name": "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3"},
                }
            ]
        });

        let ns = OrgIso1901351Vical::from_json(&json).unwrap();

        assert!(ns.vical_issue_id.is_some());
        assert!(ns.next_update.is_some());
    }
}