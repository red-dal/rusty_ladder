/**********************************************************************

Copyright (C) 2021 by reddal

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

**********************************************************************/

use proc_macro::TokenStream;
use quote::quote;
use syn::{
	parse_macro_input, parse_quote, visit::Visit, visit_mut::VisitMut, Arm, Attribute, ExprMatch,
	Fields, FnArg, Ident, ImplItem, Item, ItemEnum, ItemImpl, ItemMod, Pat, Signature, Stmt, Type,
	Variant,
};

const ATTR_IMPLEMENT: &str = "implement";

// Tabs here should be fine.
#[allow(clippy::tabs_in_doc_comments)]
/**
Auto implement traits for a enum.

Credit to [NyxCode/proxy-enum](https://github.com/NyxCode/proxy-enum).

# Example
```
mod test {

	pub trait Yell {
		fn yell(&self, at: &str) -> String;
	}

	// Cat

	pub struct Cat;

	impl Cat {
		pub fn name(&self) -> std::io::Result<&'static str> {
			Ok("cat")
		}
	}

	impl Yell for Cat {
		fn yell(&self, at: &str) -> String {
			format!("cat meow: {}", at)
		}
	}

	// Dog

	pub struct Dog;

	impl Dog {
		pub fn name(&self) -> std::io::Result<String> {
			Ok("dog".to_string())
		}
	}

	impl Yell for Dog {
		fn yell(&self, at: &str) -> String {
			format!("dog bark: {}", at)
		}
	}

	// Chicken but only enabled with feature
	#[cfg(feature = "chicken")]
	pub struct Chicken;

	#[cfg(feature = "chicken")]
	impl Chicken {
		pub fn name(&self) -> std::io::Result<String> {
			Ok("chicken".to_string())
		}
	}

	#[cfg(feature = "chicken")]
	impl Yell for Chicken {
		fn yell(&self, at: &str) -> String {
			format!("chicken noises: {}", at)
		}
	}

	// Put name of the enum here
	#[ladder_lib_macro::impl_variants(Animal)]
	pub mod animal {
		use super::*;
		use std::borrow::Cow;

		pub enum Animal {
			Cat(super::Cat),
			Dog(super::Dog),
			#[cfg(feature = "chicken")]
			Chicken(super::Chicken),
		}

		// Simply proxy function to each variant.
		// Each branch's attributes will be copied from its variant.
		impl Yell for Animal {
			#[implement]
			fn yell(&self, at: &str) -> String {
				// This will be expanded to:
				/*
				match self {
					Self::Cat(cat) => cat.yell(at),
					Self::Dog(dog) => dog.yell(at),
					#[cfg(feature = "chicken")]
					Self::Chicken(chicken) => chicken.yell(at),
				}
				*/
			}
		}

		impl Animal {
			// Using argument `map_into` will append `.map_into(Into::into)`
			// to each variant's method.
			// This is useful for converting different type of `Result`
			#[implement(map_into)]
			pub fn name(&self) -> std::io::Result<Cow<'static, str>> {
				// This will be expanded to:
				/*
				match self {
					Self::Cat(cat) => cat.foo().map_into(Into::into),
					Self::Dog(dog) => dog.foo().map_into(Into::into),
					#[cfg(feature = "chicken")]
					Self::Chicken(chicken) => chicken.foo().map_into(Into::into),
				}
				*/
			}
		}
	}
	pub use animal::Animal;
}

use test::*;
use std::borrow::Cow;

assert_eq!(Animal::Cat(Cat).name().unwrap(), Cow::Borrowed("cat"));
assert_eq!(Animal::Dog(Dog).name().unwrap(), Cow::<str>::Owned("dog".into()));
```
 */
#[proc_macro_attribute]
pub fn impl_variants(attr: TokenStream, item: TokenStream) -> TokenStream {
	let mut item_mod = parse_macro_input!(item as ItemMod);
	let target_enum = parse_macro_input!(attr as Ident);
	let target_type: Type = parse_quote! { #target_enum };

	let variants = {
		let mut visitor = Visitor {
			target_enum: &target_enum,
			variants: None,
		};
		syn::visit::visit_item_mod(&mut visitor, &item_mod);
		if let Some(variants) = visitor.variants {
			variants
		} else {
			panic!("cannot find enum '{}'", quote! { #target_enum });
		}
	};

	let mut mut_visit = MutVisitor {
		target_type: &target_type,
		variants: &variants,
	};
	syn::visit_mut::visit_item_mod_mut(&mut mut_visit, &mut item_mod);

	if let Some((_brace, content)) = &mut item_mod.content {
		// Generate 'impl From<...> for ...'
		if !variants.is_empty() {
			content.extend(make_from_variants(&target_type, variants.iter()).map(Item::Impl));
		}
	}
	quote! { #item_mod }.into()
}

/// Modifier for each variant's branch
/// Branch will be expanded into `var.func(args)` if not specified.
#[derive(Clone, Copy)]
enum Modifier {
	/// Expand into `var.func(args).map(Into::into)`
	///
	/// Useful for handling [`Result`] or [`Option`]
	MapInto,
	/// Expand into `var.func(args).map(|res| Arc::new(res).into())`
	///
	/// Useful for handling [`Result`] or [`Option`]
	MapArcInto,
	/// Expand only into `var.as_ref()`
	OnlyAsRef,
	/// Expand into `var.func(args).map(Into::into).map_err(Into::into)`
	///
	/// Useful for handling [`Result`]
	MapIntoMapErrInto,
}

impl Modifier {
	const MAP: &'static [(&'static str, Modifier)] = &[
		("map_into", Modifier::MapInto),
		("map_arc_into", Modifier::MapArcInto),
		("only_as_ref", Modifier::OnlyAsRef),
		("map_into_map_err_into", Modifier::MapIntoMapErrInto),
	];

	fn from_value(value: &Ident) -> Option<Self> {
		for (string_value, result) in Self::MAP {
			if value == string_value {
				return Some(*result);
			}
		}
		None
	}
}

struct VariantData {
	var: Variant,
	inner_type: Type,
}

struct MutVisitor<'a> {
	target_type: &'a Type,
	variants: &'a [VariantData],
}

impl VisitMut for MutVisitor<'_> {
	fn visit_item_impl_mut(&mut self, item_impl: &mut ItemImpl) {
		// Ignore any impl that's not for target_type
		if item_impl.self_ty.as_ref() != self.target_type {
			return;
		}

		let methods = item_impl.items.iter_mut().filter_map(|item| {
			if let ImplItem::Method(method) = item {
				Some(method)
			} else {
				None
			}
		});
		// Find methods with #[implement] attribute
		for method in methods {
			if let Some(index) = find_attr_index(&method.attrs, ATTR_IMPLEMENT) {
				// First remove the attribute
				let attr = method.attrs.remove(index);

				let modifier = attr
					.parse_args::<Ident>()
					.map(|m| {
						Modifier::from_value(&m)
							.unwrap_or_else(|| panic!("unknown modifier: {}", quote! { #m }))
					})
					.ok();

				// Then fill the implementation
				if !method.block.stmts.is_empty() {
					panic!(
						"method with #[implement] must be empty: {}",
						quote! { #method }
					);
				}
				let match_expr = make_match(
					&method.sig,
					self.variants.iter().map(|vd| &vd.var),
					modifier,
				);
				method.block.stmts.push(Stmt::Expr(match_expr.into()));
			}
		}
	}
}

// -------------------------------------------
//              Generate `From`
// -------------------------------------------

fn make_from_variants<'a>(
	target_type: &'a Type,
	variants: impl Iterator<Item = &'a VariantData> + 'a,
) -> impl Iterator<Item = ItemImpl> + 'a {
	variants.into_iter().map(move |vd| {
		let var_type = &vd.inner_type;
		let var_ident = &vd.var.ident;
		let mut item_impl: ItemImpl = parse_quote! {
			impl From<#var_type> for #target_type {
				fn from(value: #var_type) -> Self {
					Self::#var_ident(value)
				}
			}
		};
		item_impl.attrs = vd.var.attrs.clone();
		item_impl
	})
}

// -------------------------------------------
//       Generate Trait Implementations
// -------------------------------------------

fn make_match<'a>(
	method_sig: &Signature,
	variants: impl Iterator<Item = &'a Variant>,
	modifier: Option<Modifier>,
) -> ExprMatch {
	let function_ident = &method_sig.ident;
	let args = {
		let mut args_iter = method_sig.inputs.iter();
		// Checking arguments
		let first_arg = args_iter.next().unwrap_or_else(|| {
			panic!(
				"method must contains at least one arguments: {}",
				quote! { #method_sig }
			);
		});
		// Check if the first argument is not self
		if let FnArg::Typed(pat_type) = first_arg {
			if let Pat::Ident(pat) = pat_type.pat.as_ref() {
				if pat.ident != "self" {
					panic!(
						"method must have 'self' as the first argument: {}",
						quote! { #method_sig }
					)
				}
			}
		}
		// Extract identity from each argument
		args_iter.map(|arg| match arg {
			FnArg::Typed(arg) => {
				let arg_ident = match arg.pat.as_ref() {
					Pat::Ident(pat_ident) => pat_ident,
					other => panic!("unsupported pattern in parameter: {}", quote! { #other }),
				};
				arg_ident
			}
			_ => panic!("unsupported function arguments: {}", quote! { #arg }),
		})
	};

	let mut branch_expr = quote! { __var__.#function_ident(#(#args, )*) };
	if method_sig.asyncness.is_some() {
		branch_expr.extend(quote! { .await });
	}
	if let Some(modifier) = modifier {
		match modifier {
			Modifier::MapInto => branch_expr.extend(quote! { .map(Into::into) }),
			Modifier::MapArcInto => {
				branch_expr.extend(quote! { .map(|__value| std::sync::Arc::new(__value).into())})
			}
			Modifier::OnlyAsRef => branch_expr = quote! { __var__.as_ref() },
			Modifier::MapIntoMapErrInto => {
				branch_expr.extend(quote! { .map(Into::into).map_err(Into::into) })
			}
		}
	}

	let arms = variants.map(|var| {
		let vi = &var.ident;
		let mut arm: Arm = syn::parse2(quote! { Self::#vi(__var__) => { #branch_expr }  }).unwrap();
		arm.attrs = var.attrs.clone();
		arm
	});
	ExprMatch {
		attrs: Vec::new(),
		match_token: Default::default(),
		expr: Box::new(parse_quote! { self }),
		brace_token: Default::default(),
		arms: arms.collect(),
	}
}

struct Visitor<'ast> {
	target_enum: &'ast Ident,
	/// A list of variants of the target enum.
	variants: Option<Vec<VariantData>>,
}

impl<'ast> Visit<'ast> for Visitor<'ast> {
	fn visit_item_enum(&mut self, i: &'ast ItemEnum) {
		let target_enum = self.target_enum;
		if &i.ident != target_enum {
			return;
		}
		if self.variants.is_some() {
			panic!("contains more than one '{}'", quote! { #target_enum });
		}
		let variants = i
			.variants
			.iter()
			.map(|v| {
				let inner_type = if let Fields::Unnamed(f) = &v.fields {
					if f.unnamed.len() != 1 {
						panic!(
							"enum variant contains more than one unnamed fields: {}",
							quote! { #v }
						);
					}
					f.unnamed
						.first()
						.expect("enum variant contains no fields")
						.ty
						.clone()
				} else {
					panic!("enum variant contains named fields: {}", quote! { #v });
				};
				VariantData {
					var: v.clone(),
					inner_type,
				}
			})
			.collect();
		self.variants = Some(variants);
	}
}

fn find_attr_index(attrs: &[Attribute], ident: &str) -> Option<usize> {
	attrs.iter().enumerate().find_map(|(index, attr)| {
		if attr.path.is_ident(ident) {
			Some(index)
		} else {
			None
		}
	})
}
