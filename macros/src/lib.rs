mod from_json;
mod to_cbor;

use proc_macro::{self, TokenStream};
use syn::{Attribute, Lit, Meta, NestedMeta, Type};

#[proc_macro_derive(FromJson, attributes(isomdl))]
pub fn derive_from_json(input: TokenStream) -> TokenStream {
    from_json::derive(input)
}

#[proc_macro_derive(ToCbor, attributes(isomdl))]
pub fn derive_to_cbor(input: TokenStream) -> TokenStream {
    to_cbor::derive(input)
}

fn is_dynamic_parse(attr: &Attribute) -> bool {
    match get_isomdl_attributes(attr) {
        Some(ms) => ms,
        None => return false,
    }
    .any(|nested_meta| {
        let meta = match nested_meta {
            NestedMeta::Meta(meta) => meta,
            _ => return false,
        };
        meta.path().is_ident("dynamic_parse") || meta.path().is_ident("many")
    })
}

fn is_many(attr: &Attribute) -> bool {
    match get_isomdl_attributes(attr) {
        Some(ms) => ms,
        None => return false,
    }
    .any(|nested_meta| {
        let meta = match nested_meta {
            NestedMeta::Meta(meta) => meta,
            _ => return false,
        };
        meta.path().is_ident("many")
    })
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

// Attribute for setting the path to the isomdl crate, mostly for use
// internally in isomdl to refer to itself as 'crate'.
fn crate_path(attr: &Attribute) -> Option<String> {
    get_isomdl_attributes(attr)?
        .filter_map(|nested_meta| {
            let meta = match nested_meta {
                NestedMeta::Meta(meta) => meta,
                _ => return None,
            };
            match meta {
                Meta::NameValue(pair) => {
                    if !pair.path.is_ident("crate") {
                        return None;
                    }
                    if let Lit::Str(s) = pair.lit {
                        Some(s.value())
                    } else {
                        None
                    }
                }
                _ => None,
            }
        })
        .next()
}

fn rename(attr: &Attribute) -> Option<String> {
    get_isomdl_attributes(attr)?
        .filter_map(|nested_meta| {
            let meta = match nested_meta {
                NestedMeta::Meta(meta) => meta,
                _ => return None,
            };
            match meta {
                Meta::NameValue(pair) => {
                    if !pair.path.is_ident("rename") {
                        return None;
                    }
                    if let Lit::Str(s) = pair.lit {
                        Some(s.value())
                    } else {
                        None
                    }
                }
                _ => None,
            }
        })
        .next()
}

fn get_isomdl_attributes(attr: &Attribute) -> Option<syn::punctuated::IntoIter<NestedMeta>> {
    match attr.parse_meta().ok()? {
        Meta::List(ml) => {
            if !ml.path.is_ident("isomdl") {
                return None;
            }
            Some(ml.nested.into_iter())
        }
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use syn::{parse_str, Data, DeriveInput};

    #[test]
    fn is_optional() {
        let input: DeriveInput = parse_str(
            r#"
            struct S {
                field: Option<String>,
            }
        "#,
        )
        .unwrap();

        let ty = match input.data {
            Data::Struct(s) => s,
            _ => panic!("unexpected input"),
        }
        .fields
        .iter_mut()
        .next()
        .unwrap()
        .ty
        .clone();

        assert!(super::is_optional(&ty));

        let input: DeriveInput = parse_str(
            r#"
            struct S {
                field: Vec<Option<String>>,
            }
        "#,
        )
        .unwrap();

        let ty = match input.data {
            Data::Struct(s) => s,
            _ => panic!("unexpected input"),
        }
        .fields
        .iter_mut()
        .next()
        .unwrap()
        .ty
        .clone();

        assert!(!super::is_optional(&ty))
    }

    #[test]
    fn is_dynamic_parse() {
        let input: DeriveInput = parse_str(
            r#"
            struct S {
                #[isomdl(many)]
                field: String,
            }
        "#,
        )
        .unwrap();

        let attr = match input.data {
            Data::Struct(s) => s,
            _ => panic!("unexpected input"),
        }
        .fields
        .iter_mut()
        .next()
        .unwrap()
        .attrs
        .pop()
        .unwrap();

        assert!(super::is_dynamic_parse(&attr));

        let input: DeriveInput = parse_str(
            r#"
            struct S {
                #[isomdl(dynamic_parse)]
                field: String,
            }
        "#,
        )
        .unwrap();

        let attr = match input.data {
            Data::Struct(s) => s,
            _ => panic!("unexpected input"),
        }
        .fields
        .iter_mut()
        .next()
        .unwrap()
        .attrs
        .pop()
        .unwrap();

        assert!(super::is_dynamic_parse(&attr))
    }

    #[test]
    fn is_many() {
        let input: DeriveInput = parse_str(
            r#"
            struct S {
                #[isomdl(many)]
                field: String,
            }
        "#,
        )
        .unwrap();

        let attr = match input.data {
            Data::Struct(s) => s,
            _ => panic!("unexpected input"),
        }
        .fields
        .iter_mut()
        .next()
        .unwrap()
        .attrs
        .pop()
        .unwrap();

        assert!(super::is_many(&attr))
    }

    #[test]
    fn rename() {
        let input: DeriveInput = parse_str(
            r#"
            struct S {
                #[isomdl(rename = "test")]
                field: String,
            }
        "#,
        )
        .unwrap();

        let attr = match input.data {
            Data::Struct(s) => s,
            _ => panic!("unexpected input"),
        }
        .fields
        .iter_mut()
        .next()
        .unwrap()
        .attrs
        .pop()
        .unwrap();

        assert_eq!("test", super::rename(&attr).unwrap())
    }

    #[test]
    fn multiple() {
        let input: DeriveInput = parse_str(
            r#"
            struct S {
                #[isomdl(many, rename = "test")]
                field: String,
            }
        "#,
        )
        .unwrap();

        let attr = match input.data {
            Data::Struct(s) => s,
            _ => panic!("unexpected input"),
        }
        .fields
        .iter_mut()
        .next()
        .unwrap()
        .attrs
        .pop()
        .unwrap();

        assert_eq!("test", super::rename(&attr).unwrap());
        assert!(super::is_many(&attr));
        assert!(super::is_dynamic_parse(&attr))
    }
}
