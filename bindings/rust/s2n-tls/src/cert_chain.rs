// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Fallible};
use s2n_tls_sys::*;
use std::{
    marker::PhantomData,
    ptr::{self, NonNull},
};

/// A CertificateChain represents a chain of X.509 certificates.
pub struct CertificateChain<'a> {
    ptr: NonNull<s2n_cert_chain_and_key>,
    is_owned: bool,
    _lifetime: PhantomData<&'a s2n_cert_chain_and_key>,
}

impl CertificateChain<'_> {
    /// This allocates a new certificate chain from s2n.
    pub(crate) fn new() -> Result<CertificateChain<'static>, Error> {
        unsafe {
            let ptr = s2n_cert_chain_and_key_new().into_result()?;
            Ok(CertificateChain {
                ptr,
                is_owned: true,
                _lifetime: PhantomData,
            })
        }
    }

    /// # Safety
    ///
    /// Caller must ensure ptr is a valid reference to a [`s2n_cert_chain_and_key`] object
    /// Caller must ensure they are not creating a duplicate CertificateChain (see Send safety note).
    pub(crate) unsafe fn from_ptr_reference<'a>(
        ptr: NonNull<s2n_cert_chain_and_key>,
    ) -> CertificateChain<'a> {
        CertificateChain {
            ptr,
            is_owned: false,
            _lifetime: PhantomData,
        }
    }

    pub fn iter(&self) -> CertificateChainIter<'_> {
        CertificateChainIter {
            idx: 0,
            // Cache the length as it's O(n) to compute it, the chain is stored as a linked list.
            // It shouldn't change while we have access to the iterator.
            len: self.len(),
            chain: self,
        }
    }

    /// Return the length of this certificate chain.
    ///
    /// Note that the underyling API currently traverses a linked list, so this is a relatively
    /// expensive API to call.
    pub fn len(&self) -> usize {
        let mut length: u32 = 0;
        let res =
            unsafe { s2n_cert_chain_get_length(self.ptr.as_ptr(), &mut length).into_result() };
        if res.is_err() {
            // Errors should only happen on empty chains (we guarantee that `ptr` is a valid chain).
            return 0;
        }
        // u32 should always fit into usize on the platforms we support.
        length.try_into().unwrap()
    }

    /// Check if the certificate chain has any certificates.
    ///
    /// Note that the underyling API currently traverses a linked list, so this is a relatively
    /// expensive API to call.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// # Safety
    ///
    /// Caller must ensure they are not creating the possibility of duplicate
    /// CertificateChain (see Send safety note).
    /// This should ONLY be used to pass the CertificateChain to C methods.
    pub(crate) unsafe fn as_mut_ptr(&mut self) -> NonNull<s2n_cert_chain_and_key> {
        self.ptr
    }
}

/// # Safety
///
/// NonNull / the raw s2n_cert_chain_and_key pointer isn't Send because its data
/// may be aliased (two pointers could point to the same raw memory). However,
/// the CertificateChain interface ensures that only one owned CertificateChain
/// can exist for each s2n_cert_chain_and_key C object.
/// Additionally, the CertificateChain is immutable once created.
///
/// No mechanism enforces this. Library developers MUST ensure that new methods
/// do not expose the raw s2n_cert_chain_and_key pointer, return owned CertificateChain objects,
/// or allow the creation of CertificateChains from raw pointers. Failing that,
/// no method should take a &mut CertificateChain argument.
unsafe impl Send for CertificateChain<'_> {}

/// # Safety
///
/// NonNull / the raw s2n_cert_chain_and_key pointer isn't Sync because it allows
/// access to mutable pointers even from immutable references. However, the CertificateChain
/// interface enforces that all mutating methods correctly require &mut self.
///
/// No mechanism enforces this. Library developers MUST ensure that new methods
/// correctly use either &self or &mut self depending on their behavior.
unsafe impl Sync for CertificateChain<'_> {}

impl Drop for CertificateChain<'_> {
    fn drop(&mut self) {
        if self.is_owned {
            // ignore failures since there's not much we can do about it
            unsafe {
                let _ = s2n_cert_chain_and_key_free(self.ptr.as_ptr()).into_result();
            }
        }
    }
}

pub struct CertificateChainIter<'a> {
    idx: u32,
    len: usize,
    chain: &'a CertificateChain<'a>,
}

impl<'a> Iterator for CertificateChainIter<'a> {
    type Item = Result<Certificate<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.idx;
        // u32 fits into usize on platforms we support.
        if usize::try_from(idx).unwrap() >= self.len {
            return None;
        }
        self.idx += 1;
        let mut out = ptr::null_mut();
        unsafe {
            if let Err(e) =
                s2n_cert_chain_get_cert(self.chain.ptr.as_ptr(), &mut out, idx).into_result()
            {
                return Some(Err(e));
            }
        }
        let out = match NonNull::new(out) {
            Some(out) => out,
            None => return Some(Err(Error::INVALID_INPUT)),
        };
        Some(Ok(Certificate {
            chain: PhantomData,
            certificate: out,
        }))
    }
}

pub struct Certificate<'a> {
    // The chain owns the memory for this certificate.
    chain: PhantomData<&'a CertificateChain<'a>>,

    certificate: NonNull<s2n_cert>,
}

impl<'a> Certificate<'a> {
    pub fn der(&self) -> Result<&[u8], Error> {
        unsafe {
            let mut buffer = ptr::null();
            let mut length = 0;
            s2n_cert_get_der(self.certificate.as_ptr(), &mut buffer, &mut length).into_result()?;
            let length = usize::try_from(length).map_err(|_| Error::INVALID_INPUT)?;

            Ok(std::slice::from_raw_parts(buffer, length))
        }
    }
}

/// # Safety
///
/// NonNull / the raw s2n_cert pointer isn't Send because its data
/// may be aliased (two pointers could point to the same raw memory). Multiple
/// Certificates can reference the same memory, since multiple iterators over
/// CertificateChain can exist at once. However, the Certificate is still Send
/// because it is immutable.
///
/// No mechanism enforces this. Library developers MUST ensure that the Certificate
/// is NEVER mutated. No method should take a &mut Certificate argument.
unsafe impl Send for Certificate<'_> {}

/// # Safety
///
/// NonNull / the raw s2n_cert pointer isn't Sync because it allows access
/// to mutable pointers even from immutable references. However, the Certificate is
/// still Sync because it is immutable.
///
/// No mechanism enforces this. Library developers MUST ensure that the Certificate
/// is NEVER mutated. No method should take a &mut Certificate argument.
unsafe impl Sync for Certificate<'_> {}
