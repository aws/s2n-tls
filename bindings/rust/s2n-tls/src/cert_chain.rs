// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Fallible};
use s2n_tls_sys::*;
use std::{
    ffi::{c_void, CString},
    marker::PhantomData,
    ptr::{self, NonNull},
    sync::atomic::{AtomicUsize, Ordering},
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
        crate::init::init();
        let ptr = unsafe { s2n_cert_chain_and_key_new().into_result()? };

        let context = Box::<CertificateChainContext>::default();
        let context = Box::into_raw(context) as *mut c_void;

        unsafe {
            s2n_cert_chain_and_key_set_ctx(ptr.as_ptr(), context)
                .into_result()
                .unwrap();
        }
        Ok(CertificateChain {
            ptr,
            is_owned: true,
            _lifetime: PhantomData,
        })
    }

    /// This CertificateChain is not owned and will not increment the reference count.
    /// When the rust instance is dropped it will not drop the pointer.
    pub(crate) unsafe fn from_ptr_reference<'a>(
        ptr: NonNull<s2n_cert_chain_and_key>,
    ) -> CertificateChain<'a> {
        CertificateChain {
            ptr,
            is_owned: false,
            _lifetime: PhantomData,
        }
    }

    /// # Safety
    ///
    /// This CertificateChain _MUST_ have been initialized with the constructor.
    /// Additionally, this does NOT increment the reference count,
    /// so consider cloning the result if the source pointer is still valid and usable afterwards.
    pub(crate) unsafe fn from_owned_ptr_reference<'a>(
        ptr: NonNull<s2n_cert_chain_and_key>,
    ) -> CertificateChain<'a> {
        let cert_chain = CertificateChain {
            ptr,
            is_owned: true,
            _lifetime: PhantomData,
        };

        // Check if the context can be retrieved.
        // If it can't, this is not an owned CertificateChain created through constructor.
        cert_chain.context();
        cert_chain
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

    /// Retrieve a reference to the [`CertificateChainContext`] stored on the CertificateChain.
    pub(crate) fn context(&self) -> &CertificateChainContext {
        unsafe {
            let ctx = s2n_cert_chain_and_key_get_ctx(self.ptr.as_ptr())
                .into_result()
                .unwrap();
            &*(ctx.as_ptr() as *const CertificateChainContext)
        }
    }

    /// Retrieve a mutable reference to the [`CertificateChainContext`] stored on the CertificateChain.
    pub(crate) fn context_mut(&mut self) -> &mut CertificateChainContext {
        unsafe {
            let ctx = s2n_cert_chain_and_key_get_ctx(self.ptr.as_ptr())
                .into_result()
                .unwrap();
            &mut *(ctx.as_ptr() as *mut CertificateChainContext)
        }
    }

    pub fn load_pem(&mut self, certificate: &[u8], private_key: &[u8]) -> Result<&mut Self, Error> {
        let certificate = CString::new(certificate).map_err(|_| Error::INVALID_INPUT)?;
        let private_key = CString::new(private_key).map_err(|_| Error::INVALID_INPUT)?;
        unsafe {
            s2n_cert_chain_and_key_load_pem(
                self.ptr.as_ptr(),
                certificate.as_ptr(),
                private_key.as_ptr(),
            )
            .into_result()
        }?;
        Ok(self)
    }

    pub fn set_ocsp_data(&mut self, data: &[u8]) -> Result<&mut Self, Error> {
        let size: u32 = data.len().try_into().map_err(|_| Error::INVALID_INPUT)?;
        unsafe {
            s2n_cert_chain_and_key_set_ocsp_data(self.ptr.as_ptr(), data.as_ptr(), size)
                .into_result()
        }?;
        Ok(self)
    }
}

impl Clone for CertificateChain<'_> {
    fn clone(&self) -> Self {
        let context = self.context();

        // Safety
        //
        // Using a relaxed ordering is alright here, as knowledge of the
        // original reference prevents other threads from erroneously deleting
        // the object.
        // https://github.com/rust-lang/rust/blob/e012a191d768adeda1ee36a99ef8b92d51920154/library/alloc/src/sync.rs#L1329
        let _count = context.refcount.fetch_add(1, Ordering::Relaxed);
        Self {
            ptr: self.ptr,
            is_owned: true, // clone only makes sense for owned
            _lifetime: PhantomData,
        }
    }
}

// # Safety
//
// s2n_cert_chain_and_key objects can be sent across threads.
unsafe impl Send for CertificateChain<'_> {}

/// # Safety
///
/// Safety: All C methods that mutate the s2n_cert_chain are wrapped
/// in Rust methods that require a mutable reference.
unsafe impl Sync for CertificateChain<'_> {}

impl Drop for CertificateChain<'_> {
    fn drop(&mut self) {
        if !self.is_owned {
            // not ours to cleanup
            return;
        }
        let context = self.context_mut();
        let count = context.refcount.fetch_sub(1, Ordering::Release);
        debug_assert!(count > 0, "refcount should not drop below 1 instance");

        // only free the cert if this is the last instance
        if count != 1 {
            return;
        }

        // Safety
        //
        // The use of Ordering and fence mirrors the `Arc` implementation in
        // the standard library.
        //
        // This fence is needed to prevent reordering of use of the data and
        // deletion of the data.  Because it is marked `Release`, the decreasing
        // of the reference count synchronizes with this `Acquire` fence. This
        // means that use of the data happens before decreasing the reference
        // count, which happens before this fence, which happens before the
        // deletion of the data.
        // https://github.com/rust-lang/rust/blob/e012a191d768adeda1ee36a99ef8b92d51920154/library/alloc/src/sync.rs#L1637
        std::sync::atomic::fence(Ordering::Acquire);

        unsafe {
            // This is the last instance so free the context.
            let context = Box::from_raw(context);
            drop(context);
            let _ = s2n_cert_chain_and_key_free(self.ptr.as_ptr()).into_result();
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

pub(crate) struct CertificateChainContext {
    refcount: AtomicUsize,
}

impl Default for CertificateChainContext {
    fn default() -> Self {
        // The AtomicUsize is used to manually track the reference count of the CertificateChain.
        // This mechanism is used to track when the CertificateChain object should be freed.
        Self {
            refcount: AtomicUsize::new(1),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_and_drop_update_ref_count() {
        let original_cert = CertificateChain::new().unwrap();
        assert_eq!(original_cert.context().refcount.load(Ordering::Relaxed), 1);

        let second_cert = original_cert.clone();
        assert_eq!(original_cert.context().refcount.load(Ordering::Relaxed), 2);

        drop(second_cert);
        assert_eq!(original_cert.context().refcount.load(Ordering::Relaxed), 1);
    }

    // ensure the config context is send and sync
    #[test]
    fn context_send_sync_test() {
        fn assert_send_sync<T: 'static + Send + Sync>() {}
        assert_send_sync::<CertificateChainContext>();
    }
}
