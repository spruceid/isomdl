mod from_json;
mod to_cbor;

use proc_macro::{self, TokenStream};
use syn::{Attribute, Lit, Meta, NestedMeta, Type};

use quote::{format_ident, quote};
use syn::{parse_macro_input, DeriveInput, MetaList, MetaNameValue};

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

#[proc_macro_derive(FieldsNames)]
pub fn detect_field_names_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let mut methods = Vec::new();
    let mut rename_all_strategy: Option<String> = None;

    // Check for serde(rename_all = "...") at the struct level
    for attr in &input.attrs {
        if attr.path.is_ident("serde") {
            if let Ok(Meta::List(MetaList { nested, .. })) = attr.parse_meta() {
                for meta in nested {
                    if let NestedMeta::Meta(Meta::NameValue(MetaNameValue { path, lit, .. })) = meta
                    {
                        if path.is_ident("rename_all") {
                            if let Lit::Str(lit_str) = lit {
                                rename_all_strategy = Some(lit_str.value());
                            }
                        }
                    }
                }
            }
        }
    }

    // Process each field
    if let syn::Data::Struct(data_struct) = input.data {
        for field in data_struct.fields {
            let field_name = field.ident.as_ref().unwrap().to_string();
            let mut rename_value = field_name.clone();

            // Check for serde(rename = "...") at the field level
            for attr in &field.attrs {
                if attr.path.is_ident("serde") {
                    if let Ok(Meta::List(MetaList { nested, .. })) = attr.parse_meta() {
                        for meta in nested {
                            if let NestedMeta::Meta(Meta::NameValue(MetaNameValue {
                                path,
                                lit,
                                ..
                            })) = meta
                            {
                                if path.is_ident("rename") {
                                    if let Lit::Str(lit_str) = lit {
                                        rename_value = lit_str.value();
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Apply rename_all strategy if no specific rename is found
            if rename_value == field_name {
                if let Some(strategy) = &rename_all_strategy {
                    rename_value = apply_rename_all_strategy(&field_name, strategy);
                }
            }

            let method_name = format_ident!("{}", field_name);
            methods.push(quote! {
                impl #struct_name {
                    pub fn #method_name() -> &'static str {
                        #rename_value
                    }
                }
            });
        }
    }

    let expanded = quote! {
        #(#methods)*
    };

    TokenStream::from(expanded)
}

// Helper function to apply rename_all strategies
fn apply_rename_all_strategy(field_name: &str, strategy: &str) -> String {
    match strategy {
        "camelCase" => to_camel_case(field_name),
        "snake_case" => to_snake_case(field_name),
        "PascalCase" => to_pascal_case(field_name),
        _ => field_name.to_string(),
    }
}

// Convert to camelCase
fn to_camel_case(field_name: &str) -> String {
    let mut s = String::new();
    let mut capitalize = false;
    for c in field_name.chars() {
        if c == '_' {
            capitalize = true;
        } else if capitalize {
            s.push(c.to_ascii_uppercase());
            capitalize = false;
        } else {
            s.push(c);
        }
    }
    s
}

// Convert to snake_case (this is trivial because the field name is already in snake_case)
fn to_snake_case(field_name: &str) -> String {
    field_name.to_string()
}

// Convert to PascalCase
fn to_pascal_case(field_name: &str) -> String {
    let mut s = String::new();
    let mut capitalize = true;
    for c in field_name.chars() {
        if c == '_' {
            capitalize = true;
        } else if capitalize {
            s.push(c.to_ascii_uppercase());
            capitalize = false;
        } else {
            s.push(c);
        }
    }
    s
}
