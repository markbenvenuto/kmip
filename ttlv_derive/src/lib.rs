use heck::ToPascalCase;
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Data, DeriveInput, Fields, GenericArgument, PathArguments, Type, parse_macro_input,
    spanned::Spanned,
};

#[proc_macro_derive(TtlvDeserialize, attributes(ttlv))]
pub fn derive_ttlv_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_impl(input).unwrap_or_else(|e| e.to_compile_error().into())
}

#[proc_macro_derive(TtlvEnumDeserialize, attributes(ttlv))]
pub fn derive_ttlv_enum_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_enum_impl(input).unwrap_or_else(|e| e.to_compile_error().into())
}

fn derive_enum_impl(input: DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;

    match &input.data {
        Data::Enum(_) => {}
        _ => {
            return Err(syn::Error::new_spanned(
                name,
                "TtlvEnumDeserialize can only be derived for enums",
            ));
        }
    }

    let enum_tag = struct_tag_tokens(&input)?;

    let expanded = quote! {
        impl ::ttlv::__private::TtlvDeserialize for #name {
            fn parse(reader: &mut ::ttlv::__private::Reader<'_>) -> ::core::result::Result<Self, ::ttlv::__private::TTLVError> {
                let token = reader.read().ok_or(::ttlv::__private::TTLVError::EndOfTokenStream)??;
                let expected = #enum_tag;
                if token.tag != expected {
                    return ::core::result::Result::Err(::ttlv::__private::TTLVError::UnexpectedTag {
                        expected,
                        actual: token.tag,
                    });
                }
                match token.value {
                    ::ttlv::__private::ValueType::Enumeration(v) => {
                        ::num::FromPrimitive::from_u32(v).ok_or(
                            ::ttlv::__private::TTLVError::InvalidEnumValue {
                                tag: expected,
                                value: v,
                            },
                        )
                    }
                    _ => ::core::result::Result::Err(::ttlv::__private::TTLVError::WrongValueType { tag: token.tag }),
                }
            }
        }
    };

    Ok(expanded.into())
}

#[proc_macro_derive(TtlvTaggedEnumDeserialize, attributes(ttlv))]
pub fn derive_ttlv_tagged_enum_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_tagged_enum_impl(input).unwrap_or_else(|e| e.to_compile_error().into())
}

fn derive_tagged_enum_impl(input: DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;

    let variants = match &input.data {
        Data::Enum(e) => &e.variants,
        _ => {
            return Err(syn::Error::new_spanned(
                name,
                "TtlvTaggedEnumDeserialize can only be derived for enums",
            ));
        }
    };

    let struct_tag = struct_tag_tokens(&input)?;

    let disc_tag_str = find_ttlv_str_attr(&input.attrs, "discriminator_tag")?.ok_or_else(|| {
        syn::Error::new_spanned(
            name,
            "TtlvTaggedEnumDeserialize requires #[ttlv(discriminator_tag = \"...\")]",
        )
    })?;
    let disc_tag_ident = syn::Ident::new(&disc_tag_str, name.span());
    let disc_tag = quote! { ::ttlv::__private::Tag::#disc_tag_ident };

    let match_arms: Vec<proc_macro2::TokenStream> = variants
        .iter()
        .map(variant_match_arm)
        .collect::<syn::Result<_>>()?;

    let expanded = quote! {
        impl ::ttlv::__private::TtlvDeserialize for #name {
            fn parse(
                reader: &mut ::ttlv::__private::Reader<'_>,
            ) -> ::core::result::Result<Self, ::ttlv::__private::TTLVError> {
                ::ttlv::__private::expect_structure_begin(reader, #struct_tag)?;
                let disc = ::ttlv::__private::expect_enumeration(reader, #disc_tag)?;
                let result = match disc {
                    #(#match_arms,)*
                    v => return ::core::result::Result::Err(
                        ::ttlv::__private::TTLVError::InvalidEnumValue {
                            tag: #disc_tag,
                            value: v,
                        }
                    ),
                };
                ::ttlv::__private::expect_structure_end(reader, #struct_tag)?;
                ::core::result::Result::Ok(result)
            }
        }
    };

    Ok(expanded.into())
}

fn variant_match_arm(variant: &syn::Variant) -> syn::Result<proc_macro2::TokenStream> {
    let variant_name = &variant.ident;

    let inner_ty = match &variant.fields {
        syn::Fields::Unnamed(f) if f.unnamed.len() == 1 => &f.unnamed[0].ty,
        _ => {
            return Err(syn::Error::new_spanned(
                variant_name,
                "TtlvTaggedEnumDeserialize variants must have exactly one unnamed field",
            ));
        }
    };

    let disc_expr = find_ttlv_expr_attr(&variant.attrs, "discriminator")?.ok_or_else(|| {
        syn::Error::new_spanned(
            variant_name,
            "TtlvTaggedEnumDeserialize variants must have #[ttlv(discriminator = ...)]",
        )
    })?;

    let value_tag = if let Some(tag_str) = find_ttlv_str_attr(&variant.attrs, "value_tag")? {
        let ident = syn::Ident::new(&tag_str, variant_name.span());
        quote! { ::ttlv::__private::Tag::#ident }
    } else {
        let ident = syn::Ident::new(&variant_name.to_string(), variant_name.span());
        quote! { ::ttlv::__private::Tag::#ident }
    };

    let val_expr = value_expr(inner_ty, &value_tag)?;

    Ok(quote! {
        d if d == (#disc_expr) as u32 => Self::#variant_name(#val_expr)
    })
}

fn derive_impl(input: DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;

    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(f) => &f.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    name,
                    "TtlvDeserialize requires named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                name,
                "TtlvDeserialize can only be derived for structs",
            ));
        }
    };

    let struct_tag = struct_tag_tokens(&input)?;

    let field_stmts: Vec<proc_macro2::TokenStream> = fields
        .iter()
        .map(field_statement)
        .collect::<syn::Result<_>>()?;

    let field_names: Vec<&syn::Ident> = fields.iter().map(|f| f.ident.as_ref().unwrap()).collect();

    let expanded = quote! {
        impl ::ttlv::__private::TtlvDeserialize for #name {
            fn parse(reader: &mut ::ttlv::__private::Reader<'_>) -> ::core::result::Result<Self, ::ttlv::__private::TTLVError> {
                ::ttlv::__private::expect_structure_begin(reader, #struct_tag)?;
                #(#field_stmts)*
                ::ttlv::__private::expect_structure_end(reader, #struct_tag)?;
                ::core::result::Result::Ok(Self { #(#field_names),* })
            }
        }
    };

    Ok(expanded.into())
}

// ── tag derivation ────────────────────────────────────────────────────────────

fn struct_tag_tokens(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    if let Some(tag_str) = find_ttlv_tag_attr(&input.attrs)? {
        let ident = syn::Ident::new(&tag_str, input.ident.span());
        return Ok(quote! { ::ttlv::__private::Tag::#ident });
    }
    let ident = &input.ident;
    Ok(quote! { ::ttlv::__private::Tag::#ident })
}

fn field_tag_tokens(field: &syn::Field) -> syn::Result<proc_macro2::TokenStream> {
    if let Some(tag_str) = find_ttlv_tag_attr(&field.attrs)? {
        let ident = syn::Ident::new(&tag_str, field.span());
        return Ok(quote! { ::ttlv::__private::Tag::#ident });
    }
    let field_name = field.ident.as_ref().unwrap().to_string();
    let pascal = field_name.to_pascal_case();
    let ident = syn::Ident::new(&pascal, field.ident.as_ref().unwrap().span());
    Ok(quote! { ::ttlv::__private::Tag::#ident })
}

fn find_ttlv_tag_attr(attrs: &[syn::Attribute]) -> syn::Result<Option<String>> {
    find_ttlv_str_attr(attrs, "tag")
}

fn find_ttlv_str_attr(attrs: &[syn::Attribute], key: &str) -> syn::Result<Option<String>> {
    for attr in attrs {
        if !attr.path().is_ident("ttlv") {
            continue;
        }
        let nv: syn::MetaNameValue = attr.parse_args()?;
        if nv.path.is_ident(key) {
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) = nv.value
            {
                return Ok(Some(s.value()));
            }
        }
    }
    Ok(None)
}

fn find_ttlv_expr_attr(attrs: &[syn::Attribute], key: &str) -> syn::Result<Option<syn::Expr>> {
    for attr in attrs {
        if !attr.path().is_ident("ttlv") {
            continue;
        }
        let nv: syn::MetaNameValue = attr.parse_args()?;
        if nv.path.is_ident(key) {
            return Ok(Some(nv.value));
        }
    }
    Ok(None)
}

// ── field code generation ─────────────────────────────────────────────────────

fn field_statement(field: &syn::Field) -> syn::Result<proc_macro2::TokenStream> {
    let name = field.ident.as_ref().unwrap();
    let ty = &field.ty;
    let tag = field_tag_tokens(field)?;

    // Option<T>
    if let Some(inner) = option_inner(ty) {
        // Option<Vec<u8>> → single optional byte string
        if let Some(elem) = vec_inner(inner) {
            if is_named(elem, "u8") {
                return Ok(quote! {
                    let #name = if reader.peek_tag() == ::core::option::Option::Some(#tag) {
                        ::core::option::Option::Some(::ttlv::__private::expect_byte_string(reader, #tag)?)
                    } else {
                        ::core::option::Option::None
                    };
                });
            } else {
                // Vec<T> where T != u8 → repeated field
                let elem_expr = value_expr(elem, &tag)?;
                return Ok(quote! {
                    let #name = if reader.peek_tag() == ::core::option::Option::Some(#tag) {
                        let mut #name = ::std::vec::Vec::new();
                        while reader.peek_tag() == ::core::option::Option::Some(#tag) {
                            #name.push(#elem_expr);
                        }
                        ::core::option::Option::Some(#name)
                    } else {
                        ::core::option::Option::None
                    };
                });
            }
        }
        let inner_expr = value_expr(inner, &tag)?;
        return Ok(quote! {
            let #name = if reader.peek_tag() == ::core::option::Option::Some(#tag) {
                ::core::option::Option::Some(#inner_expr)
            } else {
                ::core::option::Option::None
            };
        });
    }

    // Vec<u8> → single byte string (checked before Vec<T>)
    if let Some(elem) = vec_inner(ty) {
        if is_named(elem, "u8") {
            return Ok(quote! {
                let #name = ::ttlv::__private::expect_byte_string(reader, #tag)?;
            });
        }
        // Vec<T> where T != u8 → repeated field
        let elem_expr = value_expr(elem, &tag)?;
        return Ok(quote! {
            let mut #name = ::std::vec::Vec::new();
            while reader.peek_tag() == ::core::option::Option::Some(#tag) {
                #name.push(#elem_expr);
            }
        });
    }

    // Primitive / nested struct
    let expr = value_expr(ty, &tag)?;
    Ok(quote! { let #name = #expr; })
}

/// Generates the expression that reads a single value of the given type.
/// Does not handle Option or Vec — those are resolved by field_statement.
fn value_expr(ty: &Type, tag: &proc_macro2::TokenStream) -> syn::Result<proc_macro2::TokenStream> {
    if is_named(ty, "i32") {
        Ok(quote! { ::ttlv::__private::expect_integer(reader, #tag)? })
    } else if is_named(ty, "i64") {
        Ok(quote! { ::ttlv::__private::expect_long_integer(reader, #tag)? })
    } else if is_named(ty, "bool") {
        Ok(quote! { ::ttlv::__private::expect_boolean(reader, #tag)? })
    } else if is_named(ty, "u32") {
        Ok(quote! { ::ttlv::__private::expect_enumeration(reader, #tag)? })
    } else if is_named(ty, "String") {
        Ok(quote! { ::ttlv::__private::expect_text_string(reader, #tag)? })
    } else if is_named(ty, "DateTime") {
        Ok(quote! { ::ttlv::__private::expect_datetime(reader, #tag)? })
    } else {
        // Assume T: TtlvDeserialize (nested struct)
        Ok(quote! { <#ty as ::ttlv::__private::TtlvDeserialize>::parse(reader)? })
    }
}

// ── type inspection helpers ───────────────────────────────────────────────────

/// Returns true if `ty` is a plain path whose last segment matches `name` with no generics.
fn is_named(ty: &Type, name: &str) -> bool {
    if let Type::Path(tp) = ty {
        if tp.qself.is_none() {
            if let Some(seg) = tp.path.segments.last() {
                // eprintln!("mcb name {:?}", seg.ident);
                // return seg.ident == name && matches!(seg.arguments, PathArguments::None);
                return seg.ident == name;
            }
        }
    }
    false
}

/// If `ty` is `Option<T>`, returns `Some(T)`; otherwise `None`.
fn option_inner(ty: &Type) -> Option<&Type> {
    angle_generic_of(ty, "Option")
}

/// If `ty` is `Vec<T>`, returns `Some(T)`; otherwise `None`.
fn vec_inner(ty: &Type) -> Option<&Type> {
    angle_generic_of(ty, "Vec")
}

fn angle_generic_of<'a>(ty: &'a Type, wrapper: &str) -> Option<&'a Type> {
    if let Type::Path(tp) = ty {
        if tp.qself.is_none() {
            if let Some(seg) = tp.path.segments.last() {
                if seg.ident == wrapper {
                    if let PathArguments::AngleBracketed(args) = &seg.arguments {
                        if let Some(GenericArgument::Type(inner)) = args.args.first() {
                            return Some(inner);
                        }
                    }
                }
            }
        }
    }
    None
}
