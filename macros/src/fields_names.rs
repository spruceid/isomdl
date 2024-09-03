use proc_macro::TokenStream;

use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput};

use crate::cbor_serializable::{get_field_name, get_rename_all_strategy};

pub fn fields_names(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;

    let struct_rename_all_strategy = get_rename_all_strategy(&input);

    let methods: Vec<_> = if let Data::Struct(data_struct) = &input.data {
        data_struct
            .fields
            .iter()
            .map(|field| {
                if let Some(ident) = &field.ident {
                    let method_name = ident.clone();
                    let field_name = field.ident.as_ref().unwrap();

                    let field_name_final =
                        get_field_name(field_name, &field.attrs, &struct_rename_all_strategy);

                    // Generate the method
                    quote! {
                        impl #name {
                            pub fn #method_name() -> &'static str {
                                #field_name_final
                            }
                        }
                    }
                } else {
                    quote!()
                }
            })
            .collect()
    } else {
        vec![quote!()].into_iter().collect()
    };

    let expanded = quote! {
        #(#methods)*
    };

    TokenStream::from(expanded)
}
