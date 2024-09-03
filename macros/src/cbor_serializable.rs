use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, Attribute, Data, DeriveInput, Fields, Index, Lit, Meta, MetaList,
    NestedMeta, Type,
};

pub(crate) fn cbor_serializable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;

    let methods: Vec<proc_macro2::TokenStream> = Vec::new();

    let struct_rename_all_strategy = get_rename_all_strategy(&input);

    let field_handling = match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields_named) => {
                let field_deserialization = fields_named.named.iter().map(|f| {
                    let field_name = f.ident.as_ref().unwrap();
                    let field_name_str = field_name.to_string();
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
                    let skip_serializing_if_none =
                        skip_serializing_if_none(Some(field_name), None, &f.attrs);
                    if skip_serializing_if_none {
                        panic!("{}", field_name);
                    }
                    let field_value =
                        generate_field_serialization(field_type, field_name_ts.clone(), &f.attrs);
                    let key = get_field_name(field_name, &f.attrs, &struct_rename_all_strategy);
                    quote! {
                        // if #skip_serializing_if_none {
                        //     // if #field_name_ts.is_some() {
                        //         // map.push((ciborium::Value::Text(#key.to_string()), #field_value));
                        //     // }
                        // } else {
                            map.push((ciborium::Value::Text(#key.to_string()), #field_value));
                        // }
                    }
                });

                (
                    quote! { #(#field_deserialization),* },
                    quote! { #(#field_serialization)* },
                )
            }
            Fields::Unnamed(fields_unnamed) => {
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
                        let skip_serializing_if_none =
                            skip_serializing_if_none(None, Some(index.clone()), &f.attrs);
                        let field_value =
                            generate_field_serialization(field_type, quote!(self.#index), &f.attrs);
                        Some(quote! {
                            if #skip_serializing_if_none && self.#index.is_some() {
                                array.push(#field_value);
                            }
                        })
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

    TokenStream::from(expanded)
}

pub(crate) fn get_rename_all_strategy(input: &DeriveInput) -> Option<String> {
    let mut struct_rename_all_strategy: Option<String> = None;

    // Check for serde(rename_all = "...") at the struct level
    for attr in &input.attrs {
        if attr.path.is_ident("isomdl") {
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
    struct_rename_all_strategy
}

pub(crate) fn generate_field_serialization(
    field_type: &Type,
    field_access: proc_macro2::TokenStream,
    _attrs: &[Attribute],
) -> proc_macro2::TokenStream {
    match field_type {
        // Handling ciborium::Value directly
        Type::Path(type_path) if type_path.path.is_ident("ciborium::Value") => {
            quote! { #field_access }
        }
        // Handling CborValue directly
        Type::Path(type_path) if type_path.path.is_ident("CborValue") => {
            quote! { #field_access.into() }
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
            quote! { #field_access.map_or(ciborium::Value::Null, |v| v.into().into()).unwrap() }
        }

        // Handling Array of Values
        Type::Path(type_path) if type_path.path.is_ident("Vec") => {
            quote! { ciborium::Value::Array(#field_access.into_iter().map(|v| v.into().into()).collect()) }
        }

        // Handling Maps of Values
        Type::Path(type_path) if type_path.path.is_ident("std::collections::HashMap") => {
            quote! { ciborium::Value::Map(#field_access.into_iter().map(|(k, v)| (k.into().into(), v.into().into())).collect()) }
        }

        // Default case to handle custom types
        _ => {
            quote! { ciborium::Value::Text("".to_string()) }
        }
    }
}

pub(crate) fn _is_to_cbor(attrs: &[Attribute]) -> bool {
    // Check for isomdl(is_to_cbor)
    for attr in attrs {
        if attr.path.is_ident("isomdl") {
            if let Ok(Meta::List(MetaList { nested, .. })) = attr.parse_meta() {
                for meta in nested {
                    if let NestedMeta::Meta(Meta::NameValue(meta_name_value)) = meta {
                        if meta_name_value.path.is_ident("is_to_cbor") {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

pub(crate) fn _is_as_cbor_value(attrs: &[Attribute]) -> bool {
    // Check for isomdl(is_as_cbor_value)
    for attr in attrs {
        if attr.path.is_ident("isomdl") {
            if let Ok(Meta::List(MetaList { nested, .. })) = attr.parse_meta() {
                for meta in nested {
                    if let NestedMeta::Meta(Meta::NameValue(meta_name_value)) = meta {
                        if meta_name_value.path.is_ident("is_as_cbor_value") {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

pub(crate) fn skip_serializing_if_none(
    _field_name: Option<&syn::Ident>,
    _field_index: Option<Index>,
    attrs: &[Attribute],
) -> bool {
    // Check for isomdl(skip_serializing_if = "Option::is_none")
    for attr in attrs {
        if attr.path.is_ident("isomdl") {
            if let Ok(Meta::List(MetaList { nested, .. })) = attr.parse_meta() {
                for meta in nested {
                    if let NestedMeta::Meta(Meta::NameValue(meta_name_value)) = meta {
                        if meta_name_value.path.is_ident("skip_serializing_if") {
                            if let Lit::Str(lit_str) = meta_name_value.lit {
                                if lit_str.value() == "Option::is_none" {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

pub(crate) fn get_field_name(
    field_name: &syn::Ident,
    attrs: &[Attribute],
    rename_all_strategy: &Option<String>,
) -> String {
    let field_name_str = field_name.to_string();
    let mut rename_value = field_name_str.clone();
    let mut field_rename_all_strategy = rename_all_strategy.clone();

    // Check for isomdl(rename = "...") and isomdl(rename_all = "...") at the field level
    for attr in attrs {
        if attr.path.is_ident("isomdl") {
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
pub(crate) fn apply_rename_all_strategy(field_name: &str, strategy: &str) -> String {
    match strategy {
        "camelCase" => to_camel_case(field_name),
        "snake_case" => to_snake_case(field_name),
        "PascalCase" => to_pascal_case(field_name),
        _ => field_name.to_string(),
    }
}

// Convert to camelCase
pub(crate) fn to_camel_case(field_name: &str) -> String {
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
pub(crate) fn to_snake_case(field_name: &str) -> String {
    field_name.to_string()
}

// Convert to PascalCase
pub(crate) fn to_pascal_case(field_name: &str) -> String {
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
