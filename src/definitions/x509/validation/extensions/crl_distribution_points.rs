use const_oid::AssociatedOid;
use der::Decode;
use x509_cert::ext::{
    pkix::{
        name::{DistributionPointName, GeneralName},
        CrlDistributionPoints,
    },
    Extension,
};

use super::{Error, ExtensionValidator};

/// CRLDistributionPoints validation for all certificate profiles.
pub struct CrlDistributionPointsValidator;

impl CrlDistributionPointsValidator {
    fn check(crl_distribution_points: CrlDistributionPoints) -> Vec<Error> {
        if crl_distribution_points.0.is_empty() {
            return vec!["expected one or more distribution points".into()];
        }
        let mut errors = vec![];
        for point in crl_distribution_points.0.into_iter() {
            if point.crl_issuer.is_some() {
                errors.push(format!(
                    "crl_issuer cannot be set, but is set for: {point:?}"
                ))
            }

            if point.reasons.is_some() {
                errors.push(format!("reasons cannot be set, but is set for: {point:?}",))
            }

            if !point
                .distribution_point
                .as_ref()
                .is_some_and(|dpn| match dpn {
                    DistributionPointName::FullName(names) => names
                        .iter()
                        .any(|gn| matches!(gn, GeneralName::UniformResourceIdentifier(_))),
                    DistributionPointName::NameRelativeToCRLIssuer(_) => false,
                })
            {
                errors.push(format!("point is invalid: {point:?}",))
            }
        }
        errors
    }
}

impl ExtensionValidator for CrlDistributionPointsValidator {
    fn oid(&self) -> const_oid::ObjectIdentifier {
        CrlDistributionPoints::OID
    }

    fn ext_name(&self) -> &'static str {
        "CrlDistributionPoints"
    }

    fn validate(&self, extension: &Extension) -> Vec<Error> {
        let bytes = extension.extn_value.as_bytes();
        let crl_distribution_points = CrlDistributionPoints::from_der(bytes);
        match crl_distribution_points {
            Ok(crl_dps) => Self::check(crl_dps),
            Err(e) => vec![format!("failed to decode: {e}")],
        }
    }
}

#[cfg(test)]
use der::flagset::FlagSet;
#[cfg(test)]
use x509_cert::ext::pkix::crl::dp::DistributionPoint;

#[cfg(test)]
#[rstest::rstest]
#[case::ok(
    CrlDistributionPoints(
        vec![
            DistributionPoint {
                distribution_point: Some(
                    DistributionPointName::FullName(
                        vec![
                            GeneralName::UniformResourceIdentifier(
                                "http://example.com".to_string().try_into().unwrap()
                            )
                        ]
                    )
                ),
                reasons: None,
                crl_issuer: None,
            }
        ]
    ),
    true
)]
#[case::empty(CrlDistributionPoints(vec![]), false)]
#[case::one_good_one_bad(
    CrlDistributionPoints(
        vec![
            DistributionPoint {
                distribution_point: Some(
                    DistributionPointName::FullName(
                        vec![
                            GeneralName::UniformResourceIdentifier(
                                "http://example.com".to_string().try_into().unwrap()
                            )
                        ]
                    )
                ),
                reasons: None,
                crl_issuer: None,
            },
            DistributionPoint {
                distribution_point: None,
                reasons: None,
                crl_issuer: None,
            }
        ]
    ),
    false
)]
#[case::no_dp(
    CrlDistributionPoints(
        vec![
            DistributionPoint {
                distribution_point: None,
                reasons: None,
                crl_issuer: None,
            }
        ]
    ),
    false
)]
#[case::good_with_reasons(
    CrlDistributionPoints(
        vec![
            DistributionPoint {
                distribution_point: Some(
                    DistributionPointName::FullName(
                        vec![
                            GeneralName::UniformResourceIdentifier(
                                "http://example.com".to_string().try_into().unwrap()
                            )
                        ]
                    )
                ),
                reasons: Some(FlagSet::default()),
                crl_issuer: None,
            },
        ]
    ),
    false
)]
#[case::good_with_issuer(
    CrlDistributionPoints(
        vec![
            DistributionPoint {
                distribution_point: Some(
                    DistributionPointName::FullName(
                        vec![
                            GeneralName::UniformResourceIdentifier(
                                "http://example.com".to_string().try_into().unwrap()
                            )
                        ]
                    )
                ),
                reasons: None,
                crl_issuer: Some(vec![]),
            },
        ]
    ),
    false
)]
fn test(#[case] crl_dps: CrlDistributionPoints, #[case] valid: bool) {
    let outcome = CrlDistributionPointsValidator::check(crl_dps);
    assert_eq!(outcome.is_empty(), valid)
}
