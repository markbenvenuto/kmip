//! Derive `Serialize` and `Deserialize` that delegates to the underlying repr
//! of a C-like enum.
//!
//! # Examples
//!


#![recursion_limit = "128"]

extern crate proc_macro;

mod parse;

use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;

use crate::parse::Input;

use std::iter;

#[proc_macro_derive(Serialize_enum)]
pub fn derive_serialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as Input);
    let ident = input.ident;
    let repr = input.repr;

    let match_variants = input.variants.iter().map(|variant| {
        let variant = &variant.ident;
        quote! {
            #ident::#variant => #ident::#variant as #repr,
        }
    });

    let enum_name = format!("my_enum|{}", ident);
    TokenStream::from(quote! {
        impl serde::Serialize for #ident {
            fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer
            {
                let value: #repr = match *self {
                    #(#match_variants)*
                };
                serializer.serialize_newtype_struct(#enum_name, &value)
                //serde::Serialize::serialize(&value, serializer)
            }
        }
    })
}

#[proc_macro_derive(Deserialize_enum, attributes(serde))]
pub fn derive_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as Input);
    let ident = input.ident;
    let repr = input.repr;
    let variants = input.variants.iter().map(|variant| &variant.ident);

    let declare_discriminants = input.variants.iter().map(|variant| {
        let variant = &variant.ident;
        quote! {
            #[allow(non_upper_case_globals)]
            const #variant: #repr = #ident::#variant as #repr;
        }
    });

    let match_discriminants = input.variants.iter().map(|variant| {
        let variant = &variant.ident;
        quote! {
            discriminant::#variant => core::result::Result::Ok(#ident::#variant),
        }
    });

    let error_format = match input.variants.len() {
        1 => "invalid value: {}, expected {}".to_owned(),
        2 => "invalid value: {}, expected {} or {}".to_owned(),
        n => {
            "invalid value: {}, expected one of: {}".to_owned()
                + &iter::repeat(", {}").take(n - 1).collect::<String>()
        }
    };

    let other_arm = match input.default_variant {
        Some(variant) => {
            let variant = &variant.ident;
            quote! {
                core::result::Result::Ok(#ident::#variant)
            }
        }
        None => quote! {
            core::result::Result::Err(serde::de::Error::custom(
                format_args!(#error_format, other #(, discriminant::#variants)*)
            ))
        },
    };

    TokenStream::from(quote! {
        impl<'de> serde::Deserialize<'de> for #ident {
            fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct discriminant;

                impl discriminant {
                    #(#declare_discriminants)*
                }

                match <#repr as serde::Deserialize>::deserialize(deserializer)? {
                    #(#match_discriminants)*
                    other => #other_arm,
                }
            }
        }
    })
}
