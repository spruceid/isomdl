mod certificate_info;
mod extension;
mod certificate_profile;
mod doc_type;
mod vical_cose_sign1;

use std::collections::BTreeMap;
use std::str::FromStr;
pub use certificate_info::{CertificateInfos, CertificateInfo};
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

pub struct VicalBuilder {
    version: String,
    vical_provider: String,
    date: String,
    certificate_infos: Vec<CertificateInfo>,
    vical_issue_id: Option<u32>,
    next_update: Option<String>,
    extensions: Option<BTreeMap<String, Vec<u8>>>,
}

impl VicalBuilder {
    pub fn new(version: String, vical_provider: String, date: String) -> Self {
        VicalBuilder {
            version,
            vical_provider,
            date,
            certificate_infos: Vec::new(),//TODO: should be a part of a struct constructor
            vical_issue_id: None,
            next_update: None,
            extensions: None,
        }
    }
    pub fn vical_issue_id(mut self, vical_issue_id: u32) -> Self {
        self.vical_issue_id = Some(vical_issue_id);
        self
    }
    pub fn next_update(mut self, next_update: String) -> Self {
        self.next_update = next_update.into();
        self
    }
    pub fn certificate_infos(mut self, certificate_infos: Vec<CertificateInfo>) -> Self {
        self.certificate_infos = certificate_infos;
        self
    }
    pub fn extensions(mut self, extensions: BTreeMap<String, Vec<u8>>) -> Self {
        self.extensions = Some(extensions);
        self
    }
    pub fn build(self) -> OrgIso1901351Vical {
        OrgIso1901351Vical {
            version: Latin1::from_str(self.version.as_str()).unwrap(),
            vical_provider: Latin1::from_str(self.vical_provider.as_str()).unwrap(),
            date: TDate::from_str(self.date.as_str()).unwrap(),
            vical_issue_id: self.vical_issue_id,
            certificate_infos: CertificateInfos::new(self.certificate_infos),
            extensions: match self.extensions {
                Some(s) => Some(Extensions::new(s)),
                None => None,
            },
            next_update: match self.next_update {
                Some(s) => Some(TDate::from_str(s.as_str()).unwrap()),
                None => None,
            },
        }
    }
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