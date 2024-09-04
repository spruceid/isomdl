use proc_macro::{self, TokenStream};

use syn::{Attribute, Lit, Meta, NestedMeta, Type};

use crate::cbor_serializable::cbor_serializable;
use crate::fields_names::fields_names;

mod cbor_serializable;
mod fields_names;
mod from_json;
mod to_cbor;

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

/// Add implementations for [coset::CborSerializable] and [coset::AsCborValue]
/// respecting the field names as defined by `rename` and `rename_all` `serde` args.
/// This macro can be derived for structs.
///
/// Example:
///
/// ```no_run
/// use coset::{AsCborValue, CborSerializable};
/// use isomdl_macros::{CborSerializable, FieldsNames};
/// use serde::{Deserialize, Serialize};
///
/// #[derive(CborSerializable, Serialize, Unserialize)]
/// #[isomdl::rename_all( "camelCase")]
/// struct MyStruct {
///     field_name: String,
///     #[isomdl(rename = "field_name3")]
///     field_name2: String,
/// }
///
/// let a = MyStruct {
///     field_name: "".to_string(),
///     field_name2: "".to_string(),
/// };
/// let b = a.to_cbor_value().unwrap();
/// let c = MyStruct::from_cbor_value(b).unwrap();
/// assert_eq!(a, c);
///
/// let a = MyStruct {
///     field_name: "".to_string(),
///     field_name2: "".to_string(),
/// };
/// let bytes = a.to_vec().unwrap();
/// let b = MyStruct::from_slice(&bytes).unwrap();
/// assert_eq!(a, b);
/// let bytes2 = b.to_vec().unwrap();
/// assert_eq!(bytes, bytes2);
/// ```
#[proc_macro_derive(CborSerializable, attributes(isomdl))]
pub fn cbor_serializable_derive(input: TokenStream) -> TokenStream {
    cbor_serializable(input)
}

/// Generates associated methods for each field in a struct or enum variant with the name as the field or variant and the
/// value as defined by `rename` and `rename_all` `serde` args.
///
/// Example:
///
/// ```no_run
/// use isomdl_macros::FieldsNames;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(FieldsNames, Serialize, Unserialize)]
/// #[isomdl::rename_all( "camelCase")]
/// struct MyStruct {
///     field_name: String,
///     #[isomdl(rename = "field_name3")]
///     field_name2: String,
/// }
///
/// assert!(MyStruct::field_name() == "fieldName");
/// assert!(MyStruct::field_name2() == "field_name3");
/// ```
#[proc_macro_derive(FieldsNames, attributes(isomdl))]
pub fn fields_names_derive(input: TokenStream) -> TokenStream {
    fields_names(input)
}

use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(CborSerializableFromCborValue)]
pub fn cbor_serializable_impl(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let input = parse_macro_input!(input as DeriveInput);

    // Get the name of the struct
    let name = &input.ident;

    // Generate the CborSerializable and AsCborValue implementation
    let expanded = quote! {
        impl coset::CborSerializable for #name {}

        impl coset::AsCborValue for #name {
            fn from_cbor_value(value: ciborium::Value) -> coset::Result<Self> {
                let cbor = CborValue::from(value);
                cbor.try_into().map_err(|_| {
                    coset::CoseError::DecodeFailed(ciborium::de::Error::Semantic(
                        None,
                        "invalid bytes".to_string(),
                    ))
                })
            }

            fn to_cbor_value(self) -> coset::Result<ciborium::Value> {
                let cbor: CborValue = self.into();
                Ok(cbor.into())
            }
        }
    };

    // Convert the generated code into a TokenStream and return it
    TokenStream::from(expanded)
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
