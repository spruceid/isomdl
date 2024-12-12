use anyhow::anyhow;
use der::DecodePem;
use isomdl::definitions::x509::{
    error::Error as X509Error,
    trust_anchor::{TrustAnchor, TrustAnchorRegistry},
    X5Chain,
};
use x509_cert::Certificate;

use crate::RuleSet;

pub fn validate(
    rules: RuleSet,
    signer: &[u8],
    root: &[u8],
) -> Result<Vec<X509Error>, anyhow::Error> {
    let root = Certificate::from_pem(root)?;

    let trust_anchor = match rules {
        RuleSet::Iaca => TrustAnchor::Iaca(root),
        RuleSet::Aamva => TrustAnchor::Aamva(root),
    };

    let trust_anchor_registry = TrustAnchorRegistry {
        certificates: vec![trust_anchor],
    };
    let bytes = pem_rfc7468::decode_vec(signer)
        .map_err(|e| anyhow!("unable to parse pem: {}", e))?
        .1;
    let x5chain_cbor: ciborium::Value = ciborium::Value::Bytes(bytes);

    let x5chain = X5Chain::from_cbor(x5chain_cbor)?;

    Ok(x5chain.validate(Some(&trust_anchor_registry)))
}
