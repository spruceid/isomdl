use der::DecodePem;
use isomdl::definitions::x509::{
    trust_anchor::{TrustAnchor, TrustAnchorRegistry, TrustPurpose},
    validation::ValidationRuleset,
    X5Chain,
};
use x509_cert::Certificate;

use crate::RuleSet;

pub async fn validate(
    rules: RuleSet,
    signer: &[u8],
    root: &[u8],
) -> Result<Vec<String>, anyhow::Error> {
    let root = Certificate::from_pem(root)?;

    let trust_anchor = TrustAnchor {
        certificate: root,
        purpose: TrustPurpose::Iaca,
    };

    let trust_anchor_registry = TrustAnchorRegistry {
        anchors: vec![trust_anchor],
    };

    let x5chain = X5Chain::builder().with_pem_certificate(signer)?.build()?;

    // Use () to skip CRL checks in CLI tool for now
    let outcome = match rules {
        RuleSet::Iaca => ValidationRuleset::Mdl,
        RuleSet::Aamva => ValidationRuleset::AamvaMdl,
    }
    .validate(&x5chain, &trust_anchor_registry, &())
    .await;

    Ok(outcome.errors)
}
