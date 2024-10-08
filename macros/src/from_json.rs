use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Field, Fields, FieldsNamed, FieldsUnnamed, Ident};

pub fn derive(input: TokenStream) -> TokenStream {
    let DeriveInput {
        ident, data, attrs, ..
    } = parse_macro_input!(input);
    let isomdl_path = Ident::new(
        &attrs
            .iter()
            .filter_map(super::crate_path)
            .next()
            .unwrap_or_else(|| "isomdl".to_owned()),
        Span::call_site(),
    );
    let struct_data = match data {
        Data::Struct(s) => s,
        Data::Enum(_) => {
            return quote! {
                compile_error!("cannot derive FromJson for enums");
            }
            .into()
        }
        Data::Union(_) => {
            return quote! {
                compile_error!("cannot derive FromJson for unions");
            }
            .into()
        }
    };

    match struct_data.fields {
        Fields::Named(f) => named_fields(isomdl_path, ident, f),
        Fields::Unnamed(f) => unnamed_fields(isomdl_path, ident, f),
        Fields::Unit => quote! {
            compile_error!("cannot derive FromJson for unit struct");
        }
        .into(),
    }
}

fn named_fields(isomdl_path: Ident, ident: Ident, input: FieldsNamed) -> TokenStream {
    let mut conversions = quote! {};
    let mut fields = quote! {};

    input.named.into_iter().for_each(
        |Field {
             ident, ty, attrs, ..
         }| {
            // Unwrap safety: this is a struct with named fields, so ident MUST be Some.
            let field = ident.unwrap();
            let mut field_str = field.to_string();
            let dynamic_fields = attrs.iter().any(super::is_dynamic_parse);
            if let Some(rename) = attrs.iter().filter_map(super::rename).next() {
                field_str = rename;
            }

            let conversion = if !dynamic_fields {
                quote! {
                    let value = map.get(#field_str);
                    let #field = match <#ty as FromJson>::from_json_opt(value) {
                        Ok(f) => Some(f),
                        Err(e) => { errors.push(FromJsonError::WithContext(#field_str, Box::new(e))); None },
                    };
                }
            } else {
                quote! {
                    let #field = match <#ty as FromJsonMap>::from_map(&map) {
                        Ok(f) => Some(f),
                        Err(e) => { errors.push(FromJsonError::WithContext(#field_str, Box::new(e))); None },
                    };
                }
            };
            conversions.extend([conversion]);

            // Unwrap safety: if this is None, then there are errors in which case the
            // `!errors.is_empty()` branch will run instead of returning the struct.
            let field = quote! {
                        #field: #field.unwrap(),
            };
            fields.extend([field])
        },
    );

    let mod_name = Ident::new(
        &(ident.to_string().to_lowercase() + "_from_json_impl"),
        Span::call_site(),
    );

    let output = quote! {
        mod #mod_name {
            use serde_json::Value;
            use super::*;
            use #isomdl_path::definitions::traits::{FromJson, FromJsonError, FromJsonMap};
            impl FromJson for #ident {
                fn from_json(value: &Value) -> Result<#ident, FromJsonError> {
                    let map = match value {
                        &Value::Object(_) => value.as_object().unwrap(),
                        &Value::Null => return Err(FromJsonError::UnexpectedType("null", "object")),
                        &Value::Bool(_) => return Err(FromJsonError::UnexpectedType("boolean", "object")),
                        &Value::Number(_) => return Err(FromJsonError::UnexpectedType("number", "object")),
                        &Value::String(_) => return Err(FromJsonError::UnexpectedType("string", "object")),
                        &Value::Array(_) => return Err(FromJsonError::UnexpectedType("array", "object")),
                    };

                    let mut errors = vec![];

                    #conversions

                    match errors.len() {
                        0 => Ok(#ident {
                                 #fields
                             }),
                        1 => Err(errors.pop().unwrap()),
                        _ => Err(FromJsonError::Multiple(errors)),
                    }

                }
            }
        }
    };

    output.into()
}

fn unnamed_fields(isomdl_path: Ident, ident: Ident, mut input: FieldsUnnamed) -> TokenStream {
    let field_type =
        match input.unnamed.pop() {
            Some(pair) => pair.into_value().ty,
            None => return quote! {
                compile_error!("cannot derive FromJson for tuple structs of less than one field");
            }
            .into(),
        };

    if input.unnamed.pop().is_some() {
        return quote! {
            compile_error!("cannot derive FromJson for tuple structs of more than one field");
        }
        .into();
    }

    let mod_name = Ident::new(
        &(ident.to_string().to_lowercase() + "_from_json_impl"),
        Span::call_site(),
    );

    let output = quote! {
        mod #mod_name {
            use super::*;
            use #isomdl_path::definitions::traits::{FromJson, FromJsonError};
            use serde_json::Value;
            impl FromJson for #ident {
                fn from_json(value: &Value) -> Result<#ident, FromJsonError> {
                    <#field_type as FromJson>::from_json(value)
                        .map(#ident)
                }
            }
        }
    };
    output.into()
}
