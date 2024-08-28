use proc_macro::{self, TokenStream};

use quote::{format_ident, quote};
use syn::{parse_macro_input, DeriveInput, MetaList};
use syn::{Attribute, Data, Fields, Lit, Meta, NestedMeta, Type, Variant};

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
/// #[serde(rename_all = "camelCase")]
/// struct MyStruct {
///     field_name: String,
///     #[serde(rename = "field_name3")]
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
#[proc_macro_derive(CborSerializable)]
pub fn cbor_serializable_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;

    let methods: Vec<proc_macro2::TokenStream> = Vec::new();

    let mut struct_rename_all_strategy: Option<String> = None;

    // Check for serde(rename_all = "...") at the struct level
    for attr in &input.attrs {
        if attr.path.is_ident("serde") {
            if let Ok(Meta::List(MetaList { nested, .. })) = attr.parse_meta() {
                for meta in nested {
                    if let NestedMeta::Meta(Meta::NameValue(meta_name_value)) = meta {
                        if meta_name_value.path.is_ident("rename_all") {
                            if let Lit::Str(lit_str) = meta_name_value.lit {
                                struct_rename_all_strategy = Some(lit_str.value());
                            }
                        }
                    }
                }
            }
        }
    }

    // enum FieldHandling {
    //     Named,
    //     Unnamed,
    // }
    // let mut struct_type = FieldHandling::Named;
    let field_handling = match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields_named) => {
                let field_deserialization = fields_named.named.iter().map(|f| {
                    let field_name = f.ident.as_ref().unwrap();
                    let field_name_str = field_name.to_string();
                    // let key = format!("{}::{}()", format_ident!("{struct_name}"), field_name_str);
                    let key = get_field_name(
                        field_name,
                        &f.attrs,
                        &struct_rename_all_strategy,
                    );
                    quote! {
                        #field_name: {
                            let value = fields.remove(&#key.to_string())
                                .ok_or_else(|| coset::CoseError::DecodeFailed(
                                    ciborium::de::Error::Semantic(None, format!("Missing field: {}", #field_name_str))
                                ))?;
                            <_ as coset::AsCborValue>::from_cbor_value(value)?
                        }
                    }
                });

                let field_serialization = fields_named.named.iter().map(|f| {
                    let field_name = f.ident.as_ref().unwrap();
                    let field_type = &f.ty;
                    let field_name_ts = quote!(self.#field_name);
                    let field_value = generate_field_serialization(field_type, field_name_ts);
                    // let field_name_str = field_name.to_string();
                    // let key = format!("{}::{}()", format_ident!("{struct_name}"), field_name_str);
                    let key = get_field_name(field_name, &f.attrs, &struct_rename_all_strategy);
                    quote! {
                        map.push((ciborium::Value::Text(#key.to_string()), #field_value));
                    }
                });

                (
                    quote! { #(#field_deserialization),* },
                    quote! { #(#field_serialization)* },
                )
            }
            Fields::Unnamed(fields_unnamed) => {
                // struct_type = FieldHandling::Unnamed;
                let field_deserialization = fields_unnamed.unnamed.iter().enumerate().map(|(i, _f)| {
                    let index = syn::Index::from(i);
                    quote! {
                        {
                            let value = fields.remove(&#index.to_string())
                                .ok_or_else(|| coset::CoseError::DecodeFailed(
                                    ciborium::de::Error::Semantic(None, format!("Missing field at index: {}", #index))
                                ))?;
                            <_ as coset::AsCborValue>::from_cbor_value(value)?
                        }
                    }
                });

                let field_serialization =
                    fields_unnamed.unnamed.iter().enumerate().map(|(i, f)| {
                        let index = syn::Index::from(i);
                        let field_type = &f.ty;
                        let field_value =
                            generate_field_serialization(field_type, quote!(self.#index));
                        quote! {
                            array.push(#field_value);
                        }
                    });

                (
                    quote! { #(#field_deserialization),* },
                    quote! { #(#field_serialization)* },
                )
            }
            _ => panic!("CborSerializable doesn't work for unit structs"),
        },
        _ => panic!("CborSerializable can only be derived for structs"),
    };

    let (field_deserialization, field_serialization) = field_handling;

    let expanded = quote! {
        #(#methods)*
        impl coset::CborSerializable for #struct_name {}
        impl coset::AsCborValue for #struct_name {
            fn from_cbor_value(value: ciborium::Value) -> coset::Result<Self> {
                let mut fields = value.into_map().map_err(|_| {
                    coset::CoseError::DecodeFailed(
                        ciborium::de::Error::Semantic(None, format!("{} is not a map", stringify!(#struct_name)))
                    )
                })?.into_iter().flat_map(|f| match f.0 {
                    ciborium::Value::Text(s) => Ok((s, f.1)),
                    _ => Err(coset::CoseError::UnexpectedItem(
                        "key",
                        "text for field",
                    )),
                }).collect::<std::collections::HashMap<String, ciborium::Value>>();
                Ok(Self {
                    #field_deserialization
                })
            }
            fn to_cbor_value(self) -> coset::Result<ciborium::Value> {
                let mut map = Vec::new();
                #field_serialization
                Ok(ciborium::Value::Map(map))
            }
        }
    };
    // let expanded = match struct_type {
    //     FieldHandling::Named => quote! {
    //         #(#methods)*
    //
    //         impl coset::CborSerializable for #struct_name {}
    //
    //         impl coset::AsCborValue for #struct_name {
    //             fn from_cbor_value(value: ciborium::Value) -> coset::Result<Self> {
    //                     let mut fields = value.into_map().map_err(|_| {
    //                         coset::CoseError::DecodeFailed(
    //                             ciborium::de::Error::Semantic(None, format!("{} is not a map", stringify!(#struct_name)))
    //                         )
    //                     })?.into_iter().flat_map(|f| match f.0 {
    //                         ciborium::Value::Text(s) => Ok((s, f.1)),
    //                         _ => Err(coset::CoseError::UnexpectedItem(
    //                             "key",
    //                             "text for field",
    //                         )),
    //                     }).collect::<std::collections::HashMap<String, ciborium::Value>>();
    //                     Ok(Self {
    //                         #field_deserialization
    //                     })
    //                 }
    //             }
    //
    //             fn to_cbor_value(self) -> coset::Result<ciborium::Value> {
    //                 let mut map = Vec::new();
    //                 #field_serialization
    //                 Ok(ciborium::Value::Array(map))
    //             }
    //     },
    //     FieldHandling::Unnamed => quote! {
    //         #(#methods)*
    //
    //         impl coset::CborSerializable for #struct_name {}
    //
    //         impl coset::AsCborValue for #struct_name {
    //             fn from_cbor_value(value: ciborium::Value) -> coset::Result<Self> {
    //                     let mut fields = value.into_array().map_err(|_| {
    //                         coset::CoseError::DecodeFailed(
    //                             ciborium::de::Error::Semantic(None, format!("{} is not an array", stringify!(#struct_name)))
    //                         )
    //                     })?.into_iter()
    //                     .collect::<Vec<ciborium::Value>>();
    //                     Ok(Self {
    //                         #field_deserialization
    //                     })
    //                 }
    //             }
    //
    //             fn to_cbor_value(self) -> coset::Result<ciborium::Value> {
    //                 let mut array = Vec::new();
    //                 #field_serialization
    //                 Ok(ciborium::Value::Array(array))
    //             }
    //     }
    // };

    TokenStream::from(expanded)
}

fn generate_field_serialization(
    field_type: &Type,
    field_access: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    match field_type {
        // Handling ciborium::Value directly
        Type::Path(type_path) if type_path.path.is_ident("ciborium::Value") => {
            quote! { #field_access }
        }

        // Handling integer types
        Type::Path(type_path)
            if type_path.path.is_ident("u8")
                || type_path.path.is_ident("u16")
                || type_path.path.is_ident("u32")
                || type_path.path.is_ident("u64")
                || type_path.path.is_ident("i8")
                || type_path.path.is_ident("i16")
                || type_path.path.is_ident("i32")
                || type_path.path.is_ident("i64") =>
        {
            quote! { ciborium::Value::Integer(#field_access as i128) }
        }

        // Handling Vec<u8>
        Type::Path(type_path) if type_path.path.is_ident("Vec<u8>") => {
            quote! { ciborium::Value::Bytes(#field_access) }
        }

        // Handling f64 (floating point numbers)
        Type::Path(type_path) if type_path.path.is_ident("f64") => {
            quote! { ciborium::Value::Float(#field_access) }
        }

        // Handling String
        Type::Path(type_path) if type_path.path.is_ident("String") => {
            quote! { ciborium::Value::Text(#field_access) }
        }

        // Handling boolean types
        Type::Path(type_path) if type_path.path.is_ident("bool") => {
            quote! { ciborium::Value::Bool(#field_access) }
        }

        // Handling Option (Null)
        Type::Path(type_path) if type_path.path.is_ident("Option") => {
            quote! { #field_access.map_or(ciborium::Value::Null, |v| v.to_cbor_value().unwrap()) }
        }

        // Handling Array of Values
        Type::Path(type_path) if type_path.path.is_ident("Vec") => {
            quote! { ciborium::Value::Array(#field_access.into_iter().map(|v| v.to_cbor_value().unwrap()).collect()) }
        }

        // Handling Maps of Values
        Type::Path(type_path) if type_path.path.is_ident("std::collections::HashMap") => {
            quote! { ciborium::Value::Map(#field_access.into_iter().map(|(k, v)| (k.to_cbor_value().unwrap(), v.to_cbor_value().unwrap())).collect()) }
        }

        // Default case to handle custom types
        _ => quote! { #field_access.to_cbor_value().unwrap() },
    }
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
/// #[serde(rename_all = "camelCase")]
/// struct MyStruct {
///     field_name: String,
///     #[serde(rename = "field_name3")]
///     field_name2: String,
/// }
///
/// assert!(MyStruct::field_name() == "fieldName");
/// assert!(MyStruct::field_name2() == "field_name3");
/// ```
#[proc_macro_derive(FieldsNames)]
pub fn fields_names_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let mut methods = Vec::new();
    let mut struct_rename_all_strategy: Option<String> = None;

    // Check for serde(rename_all = "...") at the struct level
    for attr in &input.attrs {
        if attr.path.is_ident("serde") {
            if let Ok(Meta::List(MetaList { nested, .. })) = attr.parse_meta() {
                for meta in nested {
                    if let NestedMeta::Meta(Meta::NameValue(meta_name_value)) = meta {
                        if meta_name_value.path.is_ident("rename_all") {
                            if let Lit::Str(lit_str) = meta_name_value.lit {
                                struct_rename_all_strategy = Some(lit_str.value());
                            }
                        }
                    }
                }
            }
        }
    }

    // Process each field or enum variant
    match &input.data {
        Data::Struct(data_struct) => {
            for field in &data_struct.fields {
                if let Some(field_name) = &field.ident {
                    get_field_name2(
                        field_name,
                        &field.attrs,
                        &mut methods,
                        struct_name,
                        &struct_rename_all_strategy,
                        None,
                    );
                }
            }
        }
        Data::Enum(data_enum) => {
            for variant in &data_enum.variants {
                process_enum_variant(
                    variant,
                    &mut methods,
                    struct_name,
                    &struct_rename_all_strategy,
                );
            }
        }
        _ => {}
    }

    let expanded = quote! {
        #(#methods)*
    };

    TokenStream::from(expanded)
}

fn process_enum_variant(
    variant: &Variant,
    methods: &mut Vec<proc_macro2::TokenStream>,
    enum_name: &syn::Ident,
    struct_rename_all_strategy: &Option<String>,
) {
    let variant_name = &variant.ident;
    let mut variant_rename_all_strategy = struct_rename_all_strategy.clone();

    // Check for serde(rename_all = "...") at the variant level
    for attr in &variant.attrs {
        if attr.path.is_ident("serde") {
            if let Ok(Meta::List(MetaList { nested, .. })) = attr.parse_meta() {
                for meta in nested {
                    if let NestedMeta::Meta(Meta::NameValue(meta_name_value)) = meta {
                        if meta_name_value.path.is_ident("rename_all") {
                            if let Lit::Str(lit_str) = meta_name_value.lit {
                                variant_rename_all_strategy = Some(lit_str.value());
                            }
                        }
                    }
                }
            }
        }
    }

    if let Fields::Named(fields_named) = &variant.fields {
        for field in &fields_named.named {
            if let Some(field_name) = &field.ident {
                let variant_method_name = format_ident!(
                    "{}_{}",
                    variant_name.to_string().to_lowercase(),
                    field_name.to_string()
                );
                get_field_name2(
                    field_name,
                    &field.attrs,
                    methods,
                    enum_name,
                    &variant_rename_all_strategy,
                    Some(variant_method_name),
                );
            }
        }
    }
}

fn get_field_name2(
    field_name: &syn::Ident,
    attrs: &[Attribute],
    _methods: &mut Vec<proc_macro2::TokenStream>,
    _struct_name: &syn::Ident,
    rename_all_strategy: &Option<String>,
    _method_name_override: Option<proc_macro2::Ident>,
) -> String {
    let field_name_str = field_name.to_string();
    let mut rename_value = field_name_str.clone();
    let mut field_rename_all_strategy = rename_all_strategy.clone();

    // Check for serde(rename = "...") and serde(rename_all = "...") at the field level
    for attr in attrs {
        if attr.path.is_ident("serde") {
            if let Ok(Meta::List(MetaList { nested, .. })) = attr.parse_meta() {
                for meta in nested {
                    if let NestedMeta::Meta(Meta::NameValue(meta_name_value)) = meta {
                        if meta_name_value.path.is_ident("rename") {
                            if let Lit::Str(lit_str) = meta_name_value.lit {
                                rename_value = lit_str.value();
                            }
                        } else if meta_name_value.path.is_ident("rename_all") {
                            if let Lit::Str(lit_str) = meta_name_value.lit {
                                field_rename_all_strategy = Some(lit_str.value());
                            }
                        }
                    }
                }
            }
        }
    }

    // Apply the rename_all strategy if no specific rename is found
    if rename_value == field_name_str {
        if let Some(strategy) = &field_rename_all_strategy {
            rename_value = apply_rename_all_strategy(&field_name_str, strategy);
        }
    }
    rename_value

    // let method_name_override = method_name_override.unwrap_or_else(|| format_ident!("{}", field_name_str));
    // methods.push(quote! {
    //     impl #struct_name {
    //         pub fn #method_name() -> &'static str {
    //             #rename_value
    //         }
    //     }
    // });
    // method_name_override.to_string()
}

fn get_field_name(
    field_name: &syn::Ident,
    attrs: &[Attribute],
    rename_all_strategy: &Option<String>,
) -> String {
    let field_name_str = field_name.to_string();
    let mut rename_value = field_name_str.clone();
    let mut field_rename_all_strategy = rename_all_strategy.clone();

    // Check for serde(rename = "...") and serde(rename_all = "...") at the field level
    for attr in attrs {
        if attr.path.is_ident("serde") {
            if let Ok(Meta::List(MetaList { nested, .. })) = attr.parse_meta() {
                for meta in nested {
                    if let NestedMeta::Meta(Meta::NameValue(meta_name_value)) = meta {
                        if meta_name_value.path.is_ident("rename") {
                            if let Lit::Str(lit_str) = meta_name_value.lit {
                                rename_value = lit_str.value();
                            }
                        } else if meta_name_value.path.is_ident("rename_all") {
                            if let Lit::Str(lit_str) = meta_name_value.lit {
                                field_rename_all_strategy = Some(lit_str.value());
                            }
                        }
                    }
                }
            }
        }
    }

    // Apply the rename_all strategy if no specific rename is found
    if rename_value == field_name_str {
        if let Some(strategy) = &field_rename_all_strategy {
            rename_value = apply_rename_all_strategy(&field_name_str, strategy);
        }
    }
    rename_value
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

// Convert to snake_case (field names are typically already in snake_case)
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
