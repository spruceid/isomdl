use proc_macro::{self, TokenStream};
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
                compile_error!("cannot derive ToCbor for enums");
            }
            .into()
        }
        Data::Union(_) => {
            return quote! {
                compile_error!("cannot derive ToCbor for unions");
            }
            .into()
        }
    };

    match struct_data.fields {
        Fields::Named(f) => named_fields(isomdl_path, ident, f),
        Fields::Unnamed(f) => unnamed_fields(isomdl_path, ident, f),
        Fields::Unit => quote! {
            compile_error!("cannot derive ToCbor for unit struct");
        }
        .into(),
    }
}

fn named_fields(isomdl_path: Ident, ident: Ident, input: FieldsNamed) -> TokenStream {
    let mut conversions = quote! {};

    input.named.into_iter().for_each(
        |Field {
             ident, ty, attrs, ..
         }| {
            // Unwrap safety: this is a struct with named fields, so ident MUST be Some.
            let field = ident.unwrap();
            let mut field_str = field.to_string();
            let many = attrs.iter().any(super::is_many);
            let optional = super::is_optional(&ty);
            if let Some(rename) = attrs.iter().filter_map(super::rename).next() {
                field_str = rename;
            }

            let conversion = if many {
                quote! {
                    let fs = <#ty as ToNamespaceMap>::to_ns_map(self.#field);
                    map.extend(fs);
                }
            } else if optional {
                quote! {
                    if let Some(i) = self.#field {
                        let v = ToCbor::to_cbor(i);
                        map.insert(#field_str.to_string(), v);
                    }
                }
            } else {
                quote! {
                    let v = ToCbor::to_cbor(self.#field);
                    map.insert(#field_str.to_string(), v);
                }
            };
            conversions.extend([conversion]);
        },
    );

    let mod_name = Ident::new(
        &(ident.to_string().to_lowercase() + "_to_cbor_impl"),
        Span::call_site(),
    );

    let output = quote! {
        mod #mod_name {
            use ciborium::Value;
            use super::*;
            use #isomdl_path::definitions::traits::{ToCbor, ToNamespaceMap};
            impl ToNamespaceMap for #ident {
                fn to_ns_map(self) -> std::collections::BTreeMap<String, Value> {
                    let mut map = std::collections::BTreeMap::default();

                    #conversions

                    map
                }
            }
            impl ToCbor for #ident {
                fn to_cbor(self) -> Value {
                    let map = self.to_ns_map()
                        .into_iter()
                        .map(|(k, v)| (Value::Text(k), v.try_into().unwrap()))
                        .collect();
                    Value::Map(map)
                }
            }
        }
    };

    output.into()
}

fn unnamed_fields(isomdl_path: Ident, ident: Ident, mut input: FieldsUnnamed) -> TokenStream {
    let field_type = match input.unnamed.pop() {
        Some(pair) => pair.into_value().ty,
        None => {
            return quote! {
                compile_error!("cannot derive ToCbor for tuple structs of less than one field");
            }
            .into()
        }
    };

    if input.unnamed.pop().is_some() {
        return quote! {
            compile_error!("cannot derive ToCbor for tuple structs of more than one field");
        }
        .into();
    }

    let mod_name = Ident::new(
        &(ident.to_string().to_lowercase() + "_to_cbor_impl"),
        Span::call_site(),
    );

    let output = quote! {
        mod #mod_name {
            use super::*;
            use #isomdl_path::definitions::traits::{ToCbor, ToCborError};
            impl ToCbor for #ident {
                fn to_cbor(self) -> ciborium::Value {
                    <#field_type as ToCbor>::to_cbor(self)
                }
            }
        }
    };
    output.into()
}
