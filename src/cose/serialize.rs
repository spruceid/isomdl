use ciborium::Value;
use serde::{ser, Serialize};
use serde_cbor::tags::Tagged;

pub(crate) fn serialize<S: ser::Serializer>(
    value: &Value,
    tag: Option<u64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if tag.is_some() {
        Tagged::new(tag, value).serialize(serializer)
    } else {
        value.serialize(serializer)
    }
}
