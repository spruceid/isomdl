mod from_json;
mod to_cbor;

use proc_macro::{self, TokenStream};
use syn::{Attribute, Lit, Meta, NestedMeta, Type};

#[proc_macro_derive(FromJson, attributes(dynamic_parse, many, rename))]
pub fn derive_from_json(input: TokenStream) -> TokenStream {
    from_json::derive(input)
}

#[proc_macro_derive(ToCbor, attributes(many, rename))]
pub fn derive_to_cbor(input: TokenStream) -> TokenStream {
    to_cbor::derive(input)
}

fn is_dynamic_parse(attr: &Attribute) -> bool {
    let meta = match attr.parse_meta() {
        Ok(meta) => meta,
        _ => return false,
    };

    meta.path().is_ident("dynamic_parse") || meta.path().is_ident("many")
}

fn is_many(attr: &Attribute) -> bool {
    let meta = match attr.parse_meta() {
        Ok(meta) => meta,
        _ => return false,
    };

    meta.path().is_ident("many")
}

// If the type is an `Option<T>` return true.
fn is_optional(ty: &Type) -> bool {
    let p = if let Type::Path(p) = ty {
        p
    } else {
        return false;
    };

    match p.path.segments.last() {
        Some(last) => last.ident == "Option",
        None => false,
    }
}

fn rename(attr: &Attribute) -> Option<String> {
    match attr.parse_meta().ok()? {
        Meta::List(ml) => {
            if !ml.path.is_ident("rename") {
                return None;
            }
            let nested = ml.nested;
            if let NestedMeta::Lit(Lit::Str(s)) = nested.first()? {
                Some(s.value())
            } else {
                None
            }
        }
        _ => None,
    }
}
