use std::collections::BTreeMap;

use anyhow::{Context, Error};
use clap::Parser;
use clap_stdin::MaybeStdin;
use isomdl::presentation::{device::Document, Stringify};

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
}

fn main() -> Result<(), Error> {
    match Args::parse().action {
        Action::GetNamespaces { mdl } => print_namespaces(mdl.to_string()),
    }
}

fn print_namespaces(mdl: String) -> Result<(), Error> {
    let claims = Document::parse(mdl)
        .context("could not parse mdl")?
        .namespaces
        .into_inner()
        .into_iter()
        .map(|(ns, inner)| (ns, inner.into_inner().into_iter().map(|(k, _)| k).collect()))
        .collect::<BTreeMap<String, Vec<String>>>();
    println!("{}", serde_json::to_string_pretty(&claims)?);
    Ok(())
}

#[cfg(test)]
mod test {
    #[test]
    fn print_namespaces() {
        super::print_namespaces(include_str!("../test/stringified-mdl.txt").to_string()).unwrap()
    }
}
