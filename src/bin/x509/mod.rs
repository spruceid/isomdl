use anyhow::anyhow;
use isomdl::definitions::x509::{
    error::Error as X509Error,
    trust_anchor::{RuleSetType, TrustAnchor, TrustAnchorRegistry, ValidationRuleSet},
    x5chain::X509,
    X5Chain,
};

use crate::RuleSet;

pub fn validate(
    rules: RuleSet,
    signer: &[u8],
    root: &[u8],
) -> Result<Vec<X509Error>, anyhow::Error> {
    let root_bytes = pem_rfc7468::decode_vec(root)
        .map_err(|e| anyhow!("unable to parse pem: {}", e))?
        .1;

    let ruleset = ValidationRuleSet {
        distinguished_names: vec!["2.5.4.6".to_string(), "2.5.4.8".to_string()],
        typ: match rules {
            RuleSet::Iaca => RuleSetType::IACA,
            RuleSet::Aamva => RuleSetType::AAMVA,
            RuleSet::NamesOnly => RuleSetType::NamesOnly,
        },
    };

    let trust_anchor = TrustAnchor::Custom(X509 { bytes: root_bytes }, ruleset);
    let trust_anchor_registry = TrustAnchorRegistry {
        certificates: vec![trust_anchor],
    };
    let bytes = pem_rfc7468::decode_vec(signer)
        .map_err(|e| anyhow!("unable to parse pem: {}", e))?
        .1;
    let x5chain_cbor: ciborium::Value = ciborium::Value::Bytes(bytes);

    let x5chain = X5Chain::from_cbor(x5chain_cbor)?;

    Ok(x5chain.validate(Some(trust_anchor_registry)))
}
