use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

use crate::cbor_serializable::{get_field_name, get_rename_all_strategy, to_snake_case};

pub fn fields_names(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let rename_all_strategy = get_rename_all_strategy(&input);

    let mut methods = Vec::new();

    match &input.data {
        Data::Struct(data_struct) => {
            // Iterate over struct fields
            for field in &data_struct.fields {
                if let Some(ident) = &field.ident {
                    let prefixed_method_name =
                        format!("fn_{}", to_snake_case(ident.to_string().as_str()));
                    let method_ident = syn::Ident::new(&prefixed_method_name, ident.span());
                    generate_method(
                        &mut methods,
                        name,
                        &method_ident,
                        &get_field_name(ident, &field.attrs, &rename_all_strategy),
                    );
                }
            }
        }
        Data::Enum(data_enum) => {
            // Iterate over enum variants and their fields
            for variant in &data_enum.variants {
                let variant_name = &variant.ident;
                match &variant.fields {
                    Fields::Named(fields_named) => {
                        for field in &fields_named.named {
                            if let Some(ident) = &field.ident {
                                let prefixed_method_name = format!(
                                    "fn_{}",
                                    to_snake_case(variant_name.to_string().as_str())
                                );
                                let method_ident =
                                    syn::Ident::new(&prefixed_method_name, ident.span());
                                generate_method(
                                    &mut methods,
                                    name,
                                    &method_ident,
                                    &get_field_name(ident, &field.attrs, &rename_all_strategy),
                                );
                            }
                        }
                    }
                    Fields::Unnamed(fields_unnamed) => {
                        for (index, _field) in fields_unnamed.unnamed.iter().enumerate() {
                            let prefixed_method_name =
                                format!("fn_{}", to_snake_case(variant_name.to_string().as_str()));
                            let method_ident =
                                syn::Ident::new(&prefixed_method_name, variant_name.span());
                            generate_method(
                                &mut methods,
                                name,
                                &method_ident,
                                &format!("{}_{}", variant_name, index),
                            );
                        }
                    }
                    Fields::Unit => {
                        let prefixed_method_name =
                            format!("fn_{}", to_snake_case(variant_name.to_string().as_str()));
                        let method_ident =
                            syn::Ident::new(&prefixed_method_name, variant_name.span());
                        generate_method(
                            &mut methods,
                            name,
                            &method_ident,
                            &variant_name.to_string(),
                        );
                    }
                }
            }
        }
        _ => {}
    }

    let expanded = quote! {
        #(#methods)*
    };

    TokenStream::from(expanded)
}

fn generate_method(
    methods: &mut Vec<proc_macro2::TokenStream>,
    name: &syn::Ident,
    method_name: &syn::Ident,
    field_name: &str,
) {
    methods.push(quote! {
        impl #name {
            pub fn #method_name() -> &'static str {
                #field_name
            }
        }
    });
}
