// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Fallible};
use s2n_tls_sys::*;
use std::{
    marker::PhantomData,
    ptr::{self, NonNull},
    sync::Arc,
};

/// Internal wrapper type used for a convenient drop implementation.
///
/// [CertificateChain] is internally reference counted. The reference counted `T`
/// must have a drop implementation.
struct CertificateChainHandle {
    cert: NonNull<s2n_cert_chain_and_key>,
    is_owned: bool,
}

// # Safety
//
// s2n_cert_chain_and_key objects can be sent across threads.
unsafe impl Send for CertificateChainHandle {}
unsafe impl Sync for CertificateChainHandle {}

impl CertificateChainHandle {
    fn from_owned(cert: NonNull<s2n_cert_chain_and_key>) -> Self {
        Self {
            cert,
            is_owned: true,
        }
    }

    fn from_reference(cert: NonNull<s2n_cert_chain_and_key>) -> Self {
        Self {
            cert,
            is_owned: false,
        }
    }
}

impl Drop for CertificateChainHandle {
    fn drop(&mut self) {
        // ignore failures since there's not much we can do about it
        if self.is_owned {
            unsafe {
                let _ = s2n_cert_chain_and_key_free(self.cert.as_ptr()).into_result();
            }
        }
    }
}

pub struct Builder {
    cert: CertificateChain<'static>,
}

impl Builder {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            cert: CertificateChain::allocate_owned()?,
        })
    }

    /// Corresponds to [s2n_cert_chain_and_key_load_pem_bytes]
    ///
    /// This can be used with [crate::config::Builder::load_chain] to share a
    /// single cert across multiple configs.
    pub fn load_pem(&mut self, chain: &[u8], key: &[u8]) -> Result<&mut Self, Error> {
        unsafe {
            // SAFETY: manual audit of load_pem_bytes shows that `chain_pem` and
            // `private_key_pem` are not modified.
            // https://github.com/aws/s2n-tls/issues/4140
            s2n_cert_chain_and_key_load_pem_bytes(
                self.cert.as_mut_ptr(),
                chain.as_ptr() as *mut _,
                chain.len() as u32,
                key.as_ptr() as *mut _,
                key.len() as u32,
            )
            .into_result()
        }?;

        Ok(self)
    }

    /// Corresponds to [s2n_cert_chain_and_key_load_public_pem_bytes].
    ///
    /// This method is only used when performing private-key offloading. For standard
    /// use-cases see [CertificateChain::from_pem].
    pub fn load_public_pem(&mut self, chain: &[u8]) -> Result<&mut Self, Error> {
        unsafe {
            // SAFETY: manual audit of load_public_pem_bytes shows that `chain_pem`
            // is not modified
            // https://github.com/aws/s2n-tls/issues/4140
            s2n_cert_chain_and_key_load_public_pem_bytes(
                self.cert.as_mut_ptr(),
                chain.as_ptr() as *mut _,
                chain.len() as u32,
            )
            .into_result()
        }?;

        Ok(self)
    }

    /// Corresponds to [s2n_cert_chain_and_key_set_ocsp_data].
    pub fn set_ocsp_data(&mut self, data: &[u8]) -> Result<&mut Self, Error> {
        unsafe {
            s2n_cert_chain_and_key_set_ocsp_data(
                self.cert.as_mut_ptr(),
                data.as_ptr(),
                data.len() as u32,
            )
            .into_result()
        }?;
        Ok(self)
    }

    /// Return an immutable, internally-reference counted CertificateChain.
    pub fn build(self) -> Result<CertificateChain<'static>, Error> {
        // This method is currently infalliable, but returning a result allows
        // us to add validation in the future.
        Ok(self.cert)
    }
}

/// A CertificateChain represents a chain of X.509 certificates.
///
/// Certificate chains are internally reference counted and are cheaply cloneable.
//
// SAFETY: it is important that no CertificateChain methods operate on mutable
// references. Because CertificateChains can be shared across threads, it is not
// safe to mutate CertificateChains.
#[derive(Clone)]
pub struct CertificateChain<'a> {
    ptr: Arc<CertificateChainHandle>,
    _lifetime: PhantomData<&'a s2n_cert_chain_and_key>,
}

impl CertificateChain<'_> {
    /// This allocates a new certificate chain from s2n.
    pub(crate) fn allocate_owned() -> Result<CertificateChain<'static>, Error> {
        crate::init::init();
        unsafe {
            let ptr = s2n_cert_chain_and_key_new().into_result()?;
            Ok(CertificateChain {
                ptr: Arc::new(CertificateChainHandle::from_owned(ptr)),
                _lifetime: PhantomData,
            })
        }
    }

    /// This is used to create a CertificateChain "reference" backed by memory
    /// on some external struct, where the external struct has some lifetime `'a`.
    pub(crate) unsafe fn from_ptr_reference<'a>(
        ptr: NonNull<s2n_cert_chain_and_key>,
    ) -> CertificateChain<'a> {
        let handle = Arc::new(CertificateChainHandle::from_reference(ptr));

        CertificateChain {
            ptr: handle,
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
        let res = unsafe { s2n_cert_chain_get_length(self.as_ptr(), &mut length).into_result() };
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

    /// SAFETY: Only one instance of `CertificateChain` may exist when this method
    /// is called. s2n_cert_chain_and_key is not thread-safe, so it is not safe
    /// to mutate the certificate chain if references are held across multiple  threads.
    pub(crate) unsafe fn as_mut_ptr(&mut self) -> *mut s2n_cert_chain_and_key {
        debug_assert_eq!(Arc::strong_count(&self.ptr), 1);
        self.ptr.cert.as_ptr()
    }

    pub(crate) fn as_ptr(&self) -> *const s2n_cert_chain_and_key {
        self.ptr.cert.as_ptr() as *const _
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
                s2n_cert_chain_get_cert(self.chain.as_ptr(), &mut out, idx).into_result()
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

impl Certificate<'_> {
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

#[cfg(test)]
mod tests {
    use crate::{
        config,
        error::{ErrorSource, ErrorType},
        security::DEFAULT_TLS13,
        testing::{InsecureAcceptAllCertificatesHandler, SniTestCerts, TestPair},
    };

    use super::*;

    /// Create a test pair using SNI certs
    /// * `certs`: takes references to already created cert chains. This is useful
    ///            to assert on expected reference counts.
    /// * `types`: Used to find the CA paths for the client configs
    fn sni_test_pair(
        certs: Vec<CertificateChain<'static>>,
        defaults: Option<Vec<CertificateChain<'static>>>,
        types: &[SniTestCerts],
    ) -> Result<TestPair, crate::error::Error> {
        let mut server_config = config::Builder::new();
        server_config
            .with_system_certs(false)?
            .set_security_policy(&DEFAULT_TLS13)?;
        for cert in certs.into_iter() {
            server_config.load_chain(cert)?;
        }
        if let Some(defaults) = defaults {
            server_config.set_default_chains(defaults)?;
        }

        let mut client_config = config::Builder::new();
        client_config
            .with_system_certs(false)?
            .set_security_policy(&DEFAULT_TLS13)?
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
        for t in types {
            client_config.trust_pem(t.get().cert())?;
        }
        Ok(TestPair::from_configs(
            &client_config.build()?,
            &server_config.build()?,
        ))
    }

    /// This is a useful (but inefficient) test utility to check if CertificateChain
    /// structs are equal. It does this by comparing the serialized `der` representation.
    fn cert_chains_are_equal(this: &CertificateChain<'_>, that: &CertificateChain<'_>) -> bool {
        let this: Vec<Vec<u8>> = this
            .iter()
            .map(|cert| cert.unwrap().der().unwrap().to_owned())
            .collect();
        let that: Vec<Vec<u8>> = that
            .iter()
            .map(|cert| cert.unwrap().der().unwrap().to_owned())
            .collect();
        this == that
    }

    #[test]
    fn reference_count_increment() -> Result<(), crate::error::Error> {
        let cert = SniTestCerts::AlligatorRsa.get().into_certificate_chain();
        assert_eq!(Arc::strong_count(&cert.ptr), 1);

        {
            let mut server = config::Builder::new();
            server.load_chain(cert.clone())?;

            // after being added, the reference count should have increased
            assert_eq!(Arc::strong_count(&cert.ptr), 2);
        }

        // after the config goes out of scope and is dropped, the ref count should
        // decrement
        assert_eq!(Arc::strong_count(&cert.ptr), 1);
        Ok(())
    }

    #[test]
    fn cert_is_dropped() {
        let weak_ref = {
            let cert = SniTestCerts::AlligatorEcdsa.get().into_certificate_chain();
            assert_eq!(Arc::strong_count(&cert.ptr), 1);
            Arc::downgrade(&cert.ptr)
        };
        assert_eq!(weak_ref.strong_count(), 0);
        assert!(weak_ref.upgrade().is_none());
    }

    // a cert can be successfully shared across multiple configs
    #[test]
    fn shared_certs() -> Result<(), crate::error::Error> {
        let test_key_pair = SniTestCerts::AlligatorRsa.get();
        let cert = test_key_pair.into_certificate_chain();

        let mut test_pair_1 =
            sni_test_pair(vec![cert.clone()], None, &[SniTestCerts::AlligatorRsa])?;
        let mut test_pair_2 =
            sni_test_pair(vec![cert.clone()], None, &[SniTestCerts::AlligatorRsa])?;

        assert_eq!(Arc::strong_count(&cert.ptr), 3);

        assert!(test_pair_1.handshake().is_ok());
        assert!(test_pair_2.handshake().is_ok());

        assert_eq!(Arc::strong_count(&cert.ptr), 3);

        drop(test_pair_1);
        assert_eq!(Arc::strong_count(&cert.ptr), 2);
        drop(test_pair_2);
        assert_eq!(Arc::strong_count(&cert.ptr), 1);
        Ok(())
    }

    #[test]
    fn too_many_certs_in_default() -> Result<(), crate::error::Error> {
        // 5 certs in the maximum allowed, 6 should error.
        const FAILING_NUMBER: usize = 6;
        let certs = vec![SniTestCerts::AlligatorRsa.get().into_certificate_chain(); FAILING_NUMBER];
        assert_eq!(Arc::strong_count(&certs[0].ptr), FAILING_NUMBER);

        let mut config = config::Builder::new();
        let err = config.set_default_chains(certs.clone()).err().unwrap();
        assert_eq!(err.kind(), ErrorType::UsageError);
        assert_eq!(err.source(), ErrorSource::Bindings);

        // The config should not hold a reference when the error was detected
        // in the bindings
        assert_eq!(Arc::strong_count(&certs[0].ptr), FAILING_NUMBER);

        Ok(())
    }

    #[test]
    fn default_selection() -> Result<(), crate::error::Error> {
        let alligator_cert = SniTestCerts::AlligatorRsa.get().into_certificate_chain();
        let beaver_cert = SniTestCerts::BeaverRsa.get().into_certificate_chain();

        // when no default is explicitly set, the first loaded cert is the default
        {
            let mut test_pair = sni_test_pair(
                vec![alligator_cert.clone(), beaver_cert.clone()],
                None,
                &[SniTestCerts::AlligatorRsa, SniTestCerts::BeaverRsa],
            )?;

            assert!(test_pair.handshake().is_ok());

            assert!(cert_chains_are_equal(
                &alligator_cert,
                &test_pair.client.peer_cert_chain().unwrap()
            ));

            assert_eq!(Arc::strong_count(&alligator_cert.ptr), 2);
            assert_eq!(Arc::strong_count(&beaver_cert.ptr), 2);
        }

        // set an explicit default
        {
            let mut test_pair = sni_test_pair(
                vec![alligator_cert.clone(), beaver_cert.clone()],
                Some(vec![beaver_cert.clone()]),
                &[SniTestCerts::AlligatorRsa, SniTestCerts::BeaverRsa],
            )?;

            assert!(test_pair.handshake().is_ok());

            assert!(cert_chains_are_equal(
                &beaver_cert,
                &test_pair.client.peer_cert_chain().unwrap()
            ));

            assert_eq!(Arc::strong_count(&alligator_cert.ptr), 2);
            // beaver has an additional reference because it was used in multiple
            // calls
            assert_eq!(Arc::strong_count(&beaver_cert.ptr), 3);
        }

        // set a default without adding it to the store
        {
            let mut test_pair = sni_test_pair(
                vec![alligator_cert.clone()],
                Some(vec![beaver_cert.clone()]),
                &[SniTestCerts::AlligatorRsa, SniTestCerts::BeaverRsa],
            )?;

            assert!(test_pair.handshake().is_ok());

            assert!(cert_chains_are_equal(
                &beaver_cert,
                &test_pair.client.peer_cert_chain().unwrap()
            ));

            assert_eq!(Arc::strong_count(&alligator_cert.ptr), 2);
            assert_eq!(Arc::strong_count(&beaver_cert.ptr), 2);
        }

        Ok(())
    }

    #[test]
    fn cert_ownership_error() -> Result<(), crate::error::Error> {
        let application_owned_cert = SniTestCerts::AlligatorRsa.get().into_certificate_chain();
        let cert_for_lib = SniTestCerts::BeaverRsa.get();

        let mut config = config::Builder::new();

        // library owned certs can not be used with application owned certs
        config.load_chain(application_owned_cert)?;
        let err = config
            .load_pem(cert_for_lib.cert(), cert_for_lib.key())
            .err()
            .unwrap();

        assert_eq!(err.kind(), ErrorType::UsageError);
        assert_eq!(err.name(), "S2N_ERR_CERT_OWNERSHIP");

        Ok(())
    }

    // ensure the certificates are send and sync
    #[test]
    fn certificate_send_sync_test() {
        fn assert_send_sync<T: 'static + Send + Sync>() {}
        assert_send_sync::<CertificateChain<'static>>();
    }
}
