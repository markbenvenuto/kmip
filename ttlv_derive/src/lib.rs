use heck::ToPascalCase;
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Data, DeriveInput, Fields, GenericArgument, PathArguments, Type, parse_macro_input,
    spanned::Spanned,
};

#[proc_macro_derive(TtlvSerialize, attributes(ttlv))]
pub fn derive_ttlv_serialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    serialize_impl(input).unwrap_or_else(|e| e.to_compile_error().into())
}

#[proc_macro_derive(TtlvDeserialize, attributes(ttlv))]
pub fn derive_ttlv_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_impl(input).unwrap_or_else(|e| e.to_compile_error().into())
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
    for attr in attrs {
        if !attr.path().is_ident("ttlv") {
            continue;
        }
        let nv: syn::MetaNameValue = attr.parse_args()?;
        if nv.path.is_ident("tag") {
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

// ── TtlvSerialize implementation ──────────────────────────────────────────────

fn serialize_impl(input: DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;

    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(f) => &f.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    name,
                    "TtlvSerialize requires named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                name,
                "TtlvSerialize can only be derived for structs",
            ));
        }
    };

    let struct_tag = struct_tag_tokens(&input)?;

    let field_stmts: Vec<proc_macro2::TokenStream> = fields
        .iter()
        .map(serialize_field_statement)
        .collect::<syn::Result<_>>()?;

    let expanded = quote! {
        impl ::ttlv::__private::TtlvSerialize for #name {
            fn serialize(
                &self,
                writer: &mut dyn ::ttlv::__private::EncodedWriter,
            ) -> ::core::result::Result<(), ::ttlv::__private::TTLVError> {
                ::ttlv::__private::ser_write_structure_begin(writer, #struct_tag)?;
                #(#field_stmts)*
                ::ttlv::__private::ser_write_structure_end(writer)?;
                ::core::result::Result::Ok(())
            }
        }
    };

    Ok(expanded.into())
}

fn is_copy_type(ty: &Type) -> bool {
    is_named(ty, "i32") || is_named(ty, "i64") || is_named(ty, "u32") || is_named(ty, "bool")
}

/// Value token to use when iterating `for v in &self.field` (v is `&T`).
fn vec_elem_value(ty: &Type) -> proc_macro2::TokenStream {
    if is_copy_type(ty) { quote! { *v } } else { quote! { v } }
}

/// Value token to use in `if let Some(ref v)` arm (v is `&T`).
fn option_elem_value(ty: &Type) -> proc_macro2::TokenStream {
    if is_copy_type(ty) { quote! { *v } } else { quote! { v } }
}

/// Value token for a direct owned field `self.name`.
/// DateTime and nested structs need `&self.name`; everything else is passed by value.
fn direct_field_value(ty: &Type, name: &syn::Ident) -> proc_macro2::TokenStream {
    if is_named(ty, "DateTime") || (!is_copy_type(ty) && !is_named(ty, "String")) {
        quote! { &self.#name }
    } else {
        quote! { self.#name }
    }
}

fn serialize_field_statement(field: &syn::Field) -> syn::Result<proc_macro2::TokenStream> {
    let name = field.ident.as_ref().unwrap();
    let ty = &field.ty;
    let tag = field_tag_tokens(field)?;

    // Option<T>
    if let Some(inner) = option_inner(ty) {
        // Option<Vec<u8>> → optional byte string
        if let Some(elem) = vec_inner(inner) {
            if is_named(elem, "u8") {
                return Ok(quote! {
                    if let ::core::option::Option::Some(ref v) = self.#name {
                        ::ttlv::__private::ser_write_byte_string(writer, #tag, v.as_slice())?;
                    }
                });
            }
        }
        let val = option_elem_value(inner);
        let expr = write_expr(inner, &tag, val)?;
        return Ok(quote! {
            if let ::core::option::Option::Some(ref v) = self.#name {
                #expr
            }
        });
    }

    // Vec<u8> → single byte string
    if let Some(elem) = vec_inner(ty) {
        if is_named(elem, "u8") {
            return Ok(quote! {
                ::ttlv::__private::ser_write_byte_string(writer, #tag, &self.#name)?;
            });
        }
        // Vec<T> where T != u8 → repeated field
        let val = vec_elem_value(elem);
        let expr = write_expr(elem, &tag, val)?;
        return Ok(quote! {
            for v in &self.#name {
                #expr
            }
        });
    }

    // Primitive / nested struct — direct owned access
    let val = direct_field_value(ty, name);
    let expr = write_expr(ty, &tag, val)?;
    Ok(quote! { #expr })
}

/// Generates the expression that writes a single value of the given type.
/// Callers must pass the right form for `value`:
/// - copy types (`i32`, `i64`, `u32`, `bool`): the value itself
/// - `String`: owned `String` or `&String` (`.as_str()` is appended here)
/// - `DateTime`: `&DateTime<Utc>`
/// - nested `T: TtlvSerialize`: `&T`
fn write_expr(
    ty: &Type,
    tag: &proc_macro2::TokenStream,
    value: proc_macro2::TokenStream,
) -> syn::Result<proc_macro2::TokenStream> {
    if is_named(ty, "i32") {
        Ok(quote! { ::ttlv::__private::ser_write_integer(writer, #tag, #value)?; })
    } else if is_named(ty, "i64") {
        Ok(quote! { ::ttlv::__private::ser_write_long_integer(writer, #tag, #value)?; })
    } else if is_named(ty, "u32") {
        Ok(quote! { ::ttlv::__private::ser_write_enumeration(writer, #tag, #value)?; })
    } else if is_named(ty, "bool") {
        Ok(quote! { ::ttlv::__private::ser_write_boolean(writer, #tag, #value)?; })
    } else if is_named(ty, "String") {
        Ok(quote! { ::ttlv::__private::ser_write_text_string(writer, #tag, #value.as_str())?; })
    } else if is_named(ty, "DateTime") {
        // value is already &DateTime<Utc>
        Ok(quote! { ::ttlv::__private::ser_write_datetime(writer, #tag, #value)?; })
    } else {
        // Assume T: TtlvSerialize — value is already &T
        Ok(quote! { ::ttlv::__private::TtlvSerialize::serialize(#value, writer)?; })
    }
}
