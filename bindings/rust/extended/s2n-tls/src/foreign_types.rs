// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! s2n-tls uses a dual-type approach to represent ownership. One type represents
//! owned values, and the other type represents borrowed values. This is the same
//! approach used by the OpenSSL/[ForeignTypes](https://docs.rs/foreign-types/latest/foreign_types/)
//! crate.
//!
//! We don't directly use the `ForeignTypes` trait for this functionality because
//! we don't want consumers of the [s2n-tls] crate to be able to easily retrieve
//! the underlying pointers to s2n-tls-sys types.
//!
//! When using this pattern, prefer to implement functionality on the most general
//! type (the Ref type) and then add a `Deref` impl from the owned type to the ref
//! type.
//! ```no_compile
//! define_owned_type!(Dog, dog_ffi);
//!
//! impl Deref for Dog {
//!     type Target = DogRef;
//!
//!     fn deref(&self) -> &Self::Target {
//!         ...
//!     }
//! }
//! define_ref_type!(DogRef, dog_ffi);
//!
//! impl DogRef {
//!     fn bark(&self);
//! }
//! ```
//! In the above example, `bark` can be done by both `Dog` and `DogRef`, so we
//! prefer to implement the functionality on DogRef.

use std::{cell::UnsafeCell, marker::PhantomData};

/// Define a type that represents ownership of the underlying s2n-tls type.
///
/// For example, `define_owned_type!(ExternalPsk, s2n_psk)` will produce the
/// following struct.
/// ```
/// use std::ptr::NonNull;
///
/// #[derive(Debug)]
/// pub struct ExternalPsk {
///     ptr: NonNull<s2n_tls_sys::s2n_psk>
/// }
/// ```
/// Drop must be manually implemented on this type.
macro_rules! define_owned_type {
    ($(#[$meta:meta])* $vis:vis $struct_name:ident, $inner_type:ty) => {
        $(#[$meta])*
        #[derive(Debug)]
        $vis struct $struct_name {
            ptr: std::ptr::NonNull<$inner_type>,
        }

        unsafe impl Send for $struct_name {}
        unsafe impl Sync for $struct_name {}

        impl $struct_name {
            pub fn from_s2n_ptr(ptr: std::ptr::NonNull<$inner_type>) -> Self {
                Self { ptr }
            }

            /// Access the underlying `const` pointer.
            pub fn as_s2n_ptr(&self) -> *const $inner_type {
                self.ptr.as_ptr() as *const $inner_type
            }

            /// Access the underlying `mut` pointer.
            pub fn as_s2n_ptr_mut(&self) -> *mut $inner_type {
                self.ptr.as_ptr()
            }
        }
    };
}

// This opaque definition is borrowed from the foreign-types crate
// https://github.com/sfackler/foreign-types/blob/393f6ab5a5dc66b8a8e2d6d880b1ff80b6a7edc2/foreign-types-shared/src/lib.rs#L14
// This type acts as if it owns a mutable pointer to a zero sized type, where
// that type may implement un-synchronized interior mutability.
#[derive(Debug)]
pub(crate) struct Opaque(PhantomData<UnsafeCell<*mut ()>>);

/// Define a type that represents a reference to the underlying s2n-tls type. This
/// type should not have an associated drop implementation.
///
/// Ref Types can be used to ergonomically return a reference from a function.
/// The lifetime of the ref will automatically be tied to the lifetime of the
/// surrounding function.
macro_rules! define_ref_type {
    ($(#[$meta:meta])* $vis:vis $struct_name:ident, $inner_type:ty) => {
        $(#[$meta])*
        #[derive(Debug)]
        $vis struct $struct_name(crate::foreign_types::Opaque);

        impl crate::foreign_types::S2NRef for $struct_name {
            type ForeignType = $inner_type;
        }
    };
}

/// SAFETY: both Self and Self::ForeignType must be zero sized.
pub(crate) trait S2NRef: Sized {
    type ForeignType: Sized;

    fn from_s2n_ptr_mut<'a>(ptr: *mut Self::ForeignType) -> &'a mut Self {
        unsafe { &mut *(ptr as *mut Self) }
    }

    fn from_s2n_ptr<'a>(ptr: *const Self::ForeignType) -> &'a Self {
        unsafe { &*(ptr as *const Self) }
    }

    fn as_s2n_ptr_mut(&mut self) -> *mut Self::ForeignType {
        self.as_s2n_ptr() as *mut Self::ForeignType
    }

    fn as_s2n_ptr(&self) -> *const Self::ForeignType {
        self as *const Self as *const Self::ForeignType
    }
}

pub(crate) use {define_owned_type, define_ref_type};
