use crate::cbor_serializable;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Lit, Meta, NestedMeta};

pub fn fields_names(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;

    // Flags to detect `rename_all` and `rename` using `isomdl`
    let mut rename_all_camel_case = false;

    if let Some(attrs) = input.attrs.iter().find(|attr| attr.path.is_ident("isomdl")) {
        if let Ok(meta) = attrs.parse_meta() {
            if let Meta::List(meta_list) = meta {
                for nested in meta_list.nested {
                    if let NestedMeta::Meta(Meta::NameValue(nv)) = nested {
                        if nv.path.is_ident("rename_field_all") {
                            if let syn::Lit::Str(ref lit_str) = nv.lit {
                                if lit_str.value() == "camelCase" {
                                    rename_all_camel_case = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let methods: Vec<_> = if let Data::Struct(data_struct) = &input.data {
        data_struct
            .fields
            .iter()
            .map(|field| {
                if let Some(ident) = &field.ident {
                    let method_name = ident.clone();
                    let mut field_name = ident.to_string();

                    // Check for field-level `rename` attribute using `isomdl`
                    let mut renamed_field = false;
                    if let Some(attrs) =
                        field.attrs.iter().find(|attr| attr.path.is_ident("isomdl"))
                    {
                        if let Ok(meta) = attrs.parse_meta() {
                            if let Meta::List(meta_list) = meta {
                                for nested in meta_list.nested {
                                    if let NestedMeta::Meta(Meta::NameValue(nv)) = nested {
                                        if nv.path.is_ident("rename_field") {
                                            if let Lit::Str(ref lit_str) = nv.lit {
                                                field_name = lit_str.value();
                                                renamed_field = true; // Mark as renamed
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Apply camelCase transformation if `rename_all` is set and field is not explicitly renamed
                    let field_name_final = if !renamed_field && rename_all_camel_case {
                        cbor_serializable::to_camel_case(&field_name)
                    } else {
                        field_name
                    };

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
