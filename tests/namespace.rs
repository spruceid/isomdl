use isomdl::{
    definitions::traits::FromJson,
    macros::{FromJson, ToCbor},
};

#[derive(FromJson, ToCbor)]
pub struct NewNamespace {
    field: String,
}

#[test]
fn new_namespace() {
    let json = serde_json::json!({
        "field": "value"
    });

    NewNamespace::from_json(&json).unwrap();
}
