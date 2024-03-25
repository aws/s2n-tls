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

    pub(crate) fn as_mut_ptr(&mut self) -> NonNull<s2n_cert_chain_and_key> {
        self.ptr
    }
}

// # Safety
//
// s2n_cert_chain_and_key objects can be sent across threads.
unsafe impl Send for CertificateChain<'_> {}

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

// # Safety
//
// Certificates just reference data in the chain, so share the Send-ness of the chain.
unsafe impl Send for Certificate<'_> {}
