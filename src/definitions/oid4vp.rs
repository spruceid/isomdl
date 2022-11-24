use crate::definitions::{device_response::Document as StandardDoc, DeviceSigned, IssuerSigned};
use crate::presentation::Stringify;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    pub doc_type: String,
    pub issuer_signed: IssuerSigned,
    pub device_signed: DeviceSigned,
}

impl From<StandardDoc> for Document {
    fn from(doc: StandardDoc) -> Document {
        let StandardDoc {
            doc_type,
            issuer_signed,
            device_signed,
            ..
        } = doc;
        Document {
            doc_type,
            issuer_signed,
            device_signed,
        }
    }
}

impl Stringify for Document {}
