use std::{collections::BTreeMap, fs::File, io::Read, path::PathBuf};

use anyhow::{Context, Error, Ok};
use clap::Parser;
use clap_stdin::MaybeStdin;
use isomdl::presentation::{device::Document, Stringify};

mod x509;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, clap::Subcommand)]
enum Action {
    /// Print the namespaces and element identifiers used in an mDL.
    GetNamespaces {
        /// Base64 encoded mDL in the format used in the issuance module of this crate.
        mdl: MaybeStdin<String>,
    },
    /// Validate a document signer cert against a possible root certificate.
    ValidateCerts {
        /// Validation rule set.
        rules: RuleSet,
        /// Path to PEM-encoded document signer cert.
        ds: PathBuf,
        /// Path to PEM-encoded IACA root cert.
        root: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum RuleSet {
    Iaca,
    Aamva,
    NamesOnly,
}

fn main() -> Result<(), Error> {
    match Args::parse().action {
        Action::GetNamespaces { mdl } => print_namespaces(mdl.to_string()),
        Action::ValidateCerts { rules, ds, root } => validate_certs(rules, ds, root),
    }
}

fn print_namespaces(mdl: String) -> Result<(), Error> {
    let claims = Document::parse(mdl)
        .context("could not parse mdl")?
        .namespaces
        .into_inner()
        .into_iter()
        .map(|(ns, inner)| (ns, inner.into_inner().into_keys().collect()))
        .collect::<BTreeMap<String, Vec<String>>>();
    println!("{}", serde_json::to_string_pretty(&claims)?);
    Ok(())
}

fn validate_certs(rules: RuleSet, ds: PathBuf, root: PathBuf) -> Result<(), Error> {
    let mut ds_bytes = vec![];
    File::open(ds)?.read_to_end(&mut ds_bytes)?;
    let mut root_bytes = vec![];
    File::open(root)?.read_to_end(&mut root_bytes)?;
    let validation_errors = x509::validate(rules, &ds_bytes, &root_bytes)?;
    if validation_errors.is_empty() {
        println!("Validated!");
    } else {
        println!(
            "Validation errors:\n{}",
            serde_json::to_string_pretty(&validation_errors)?
        )
    }
    Ok(())
}

#[cfg(test)]
mod test {
    #[test]
    fn print_namespaces() {
        super::print_namespaces(include_str!("../../test/stringified-mdl.txt").to_string()).unwrap()
    }
}
