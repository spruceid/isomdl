use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{
    parse_macro_input, Attribute, Data, DeriveInput, Field, Fields, FieldsNamed, FieldsUnnamed,
    Ident,
};

#[proc_macro_derive(FromJson, attributes(dynamic_fields))]
pub fn derive(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, data, .. } = parse_macro_input!(input);
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
        Fields::Named(f) => named_fields(ident, f),
        Fields::Unnamed(f) => unnamed_fields(ident, f),
        Fields::Unit => {
            quote! {
                compile_error!("cannot derive FromJson for unit struct");
            }
            .into()
        }
    }
}

fn named_fields(ident: Ident, input: FieldsNamed) -> TokenStream {
    let mut conversions = quote! {};
    let mut fields = quote! {};

    input.named.into_iter().for_each(
        |Field {
             ident, ty, attrs, ..
         }| {
            // Unwrap safety: this is a struct with named fields, so ident MUST be Some.
            let field = ident.unwrap();
            let dynamic_fields = attrs.iter().any(is_dynamic_fields);

            let conversion = if !dynamic_fields {
                quote! {
                    let value = map.get("#field");
                    let #field = match <#ty as FJ>::from_json_opt(value) {
                        Ok(f) => Some(f),
                        Err(FromJsonError::Multiple(es)) => { errors.extend(es); None },
                        Err(e) => { errors.push(e); None },
                    };
                }
            } else {
                quote! {
                    let #field = match <#ty as FromMap>::from_map(&mut map) {
                        Ok(f) => Some(f),
                        Err(FromJsonError::Multiple(es)) => { errors.extend(es); None },
                        Err(e) => { errors.push(e); None },
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

    let output = quote! {
        {
            use serde_json::Value;
            use crate::definitions::traits::{FromJson as FJ, FromJsonError, FromMap};
            impl FJ for #ident {
                fn from_json(value: &Value) -> Result<#ident, FromJsonError> {
                    let map = match *value {
                        Value::Object(map) => map,
                        Value::Null => return Err(FromJsonError::UnexpectedType("null", "object")),
                        Value::Bool(_) => return Err(FromJsonError::UnexpectedType("boolean", "object")),
                        Value::Number(_) => return Err(FromJsonError::UnexpectedType("number", "object")),
                        Value::String(_) => return Err(FromJsonError::UnexpectedType("string", "object")),
                        Value::Array(_) => return Err(FromJsonError::UnexpectedType("array", "object")),
                    };

                    let mut errors = vec![];

                    #conversions

                    match errors[..] {
                        [] => return Ok(#ident {
                                    #fields
                              }),
                        [e] => return Err(e),
                        _ => return Err(FromJsonError::Multiple(errors)),
                    }

                }
            }
        }
    };

    output.into()
}

fn is_dynamic_fields(attr: &Attribute) -> bool {
    let meta = match attr.parse_meta() {
        Ok(meta) => meta,
        _ => return false,
    };

    meta.path().is_ident("dynamic_fields")
}

fn unnamed_fields(ident: Ident, mut input: FieldsUnnamed) -> TokenStream {
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

    let output = quote! {
        {
            use crate::definitions::traits::{FromJson as FJ, FromJsonError};
            use serde_json::Value;
            impl FJ for #ident {
                fn from_json(value: &Value) -> Result<#ident, FromJsonError> {
                    <#field_type as FJ>::from_json(value)
                        .map(#ident)
                }
            }
        }
    };
    output.into()
}
