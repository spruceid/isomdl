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

#[proc_macro_derive(CborSerializable)]
pub fn cbor_serializable_derive(input: TokenStream) -> TokenStream {
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

    let field_handling = match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields_named) => {
                let field_deserialization = fields_named.named.iter().map(|f| {
                    let field_name = f.ident.as_ref().unwrap();
                    let field_name_str = field_name.to_string();
                    process_field_or_variant(
                        field_name,
                        &f.attrs,
                        &mut methods,
                        struct_name,
                        &struct_rename_all_strategy,
                        None,
                    );
                    quote! {
                        #field_name: {
                            let value = fields.remove(#field_name_str)
                                .ok_or_else(|| coset::CoseError::DecodeFailed(
                                    ciborium::de::Error::Semantic(None, format!("Missing field: {}", #field_name_str))
                                ))?;
                            <_ as coset::AsCborValue>::from_cbor_value(value)?
                        }
                    }
                });

                let field_serialization = fields_named.named.iter().map(|f| {
                    let field_name = f.ident.as_ref().unwrap();
                    let field_name_str = field_name.to_string();
                    quote! {
                        map.push((ciborium::Value::Text(#field_name_str.to_string()), self.#field_name.to_cbor_value()?));
                    }
                });

                (
                    quote! { #(#field_deserialization),* },
                    quote! { #(#field_serialization)* },
                )
            }
            _ => panic!("CborSerializable can only be derived for structs with named fields"),
        },
        // Data::Enum(data_enum) => {
        //     for variant in &data_enum.variants {
        //         process_enum_variant(
        //             variant,
        //             &mut methods,
        //             struct_name,
        //             &struct_rename_all_strategy,
        //         );
        //     }
        // }
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
                    process_field_or_variant(
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
                process_field_or_variant(
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

fn process_field_or_variant(
    field_name: &syn::Ident,
    attrs: &[Attribute],
    methods: &mut Vec<proc_macro2::TokenStream>,
    struct_name: &syn::Ident,
    rename_all_strategy: &Option<String>,
    method_name_override: Option<proc_macro2::Ident>,
) {
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

    let method_name = method_name_override.unwrap_or_else(|| format_ident!("{}", field_name_str));
    methods.push(quote! {
        impl #struct_name {
            pub fn #method_name() -> &'static str {
                #rename_value
            }
        }
    });
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
