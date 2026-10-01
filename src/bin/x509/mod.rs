use der::DecodePem;
use isomdl::definitions::x509::{
    trust_anchor::{TrustAnchor, TrustAnchorRegistry, TrustPurpose},
    validation::MdocProfile,
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
    let profile = match rules {
        RuleSet::Iaca => MdocProfile::MDL.issuer,
        RuleSet::Aamva => MdocProfile::AAMVA_MDL.issuer,
    };
    let outcome = isomdl::definitions::x509::validation::validate(
        &profile,
        &x5chain,
        &trust_anchor_registry,
        &(),
    )
    .await;

    Ok(outcome.errors)
}
