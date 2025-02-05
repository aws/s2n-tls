// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    marker::PhantomData,
    ptr::{self, NonNull},
};

use s2n_tls_sys::*;

use crate::{
    connection::Connection,
    error::Fallible,
    foreign_types::{Opaque, S2NRef},
};

struct OfferedPsk<'callback> {
    ptr: NonNull<s2n_offered_psk>,
    // The `&[u8]` returned from `OfferedPsk::identity` is not owned by the OfferedPsk
    // struct, but instead is a reference to the "buffer" member of the OfferedPskListRef
    wire_input: PhantomData<&'callback [u8]>,
}

impl<'callback> OfferedPsk<'callback> {
    fn allocate() -> Result<Self, crate::error::Error> {
        let ptr = unsafe { s2n_offered_psk_new().into_result() }?;
        Ok(Self {
            ptr,
            wire_input: PhantomData,
        })
    }

    /// Return the identity associated with an offered PSK.
    pub fn identity(&self) -> Result<&'callback [u8], crate::error::Error> {
        let mut identity_buffer = ptr::null_mut::<u8>();
        let mut size = 0;
        unsafe {
            s2n_offered_psk_get_identity(self.ptr.as_ptr(), &mut identity_buffer, &mut size)
                .into_result()?
        };

        Ok(unsafe {
            // SAFETY: valid, aligned, non-null -> If the s2n-tls API didn't fail
            //         (which we check for) then data will be non-null, valid for
            //         reads, and aligned.
            // SAFETY: the memory is not mutated -> For the life of the PSK Selection
            //         callback, nothing else is mutating the wire buffer which
            //         is the backing memory of the identities.
            std::slice::from_raw_parts(identity_buffer, size as usize)
        })
    }
}

impl Drop for OfferedPsk<'_> {
    fn drop(&mut self) {
        let mut s2n_ptr = self.ptr.as_ptr();
        // ignore failures. There isn't anything to be done to handle them, but
        // allowing the program to continue is preferable to crashing.
        let _ = unsafe { s2n_offered_psk_free(&mut s2n_ptr).into_result() };
    }
}

pub struct OfferedPskListRef<'callback> {
    _ptr: Opaque,
    // s2n_offered_psk_list has a stuffer that refers to the wire_data from
    // the connection. This stuffer is valid for the lifetime of the callback.
    wire_input: PhantomData<&'callback [u8]>,
}

impl S2NRef for OfferedPskListRef<'_> {
    type ForeignType = s2n_offered_psk_list;
}

impl<'callback> OfferedPskListRef<'callback> {
    /// Return an iterator over the PSK identities offered by the client.
    //
    // Given an OfferedPskListRef which is valid for the lifetime of the wire_input,
    // return an IdentitySelector which borrows list for the lifetime of the selector,
    // but which can return identities valid for the lifetime of the wire_input.
    pub fn identities(&mut self) -> Result<IdentitySelector<'_, 'callback>, crate::error::Error> {
        self.reread()?;
        Ok(IdentitySelector {
            psk: OfferedPsk::allocate()?,
            list: self,
        })
    }

    // Return a selector over the OfferedPsks that the client has
    // sent.
    // We write tests for this workflow to ensure that it could be made public
    // in the future if additional fields of OfferedPsk are exposed.
    #[cfg(test)]
    fn offered_psks(&mut self) -> Result<OfferedPskSelector<'_, 'callback>, crate::error::Error> {
        self.reread()?;
        Ok(OfferedPskSelector {
            psk: OfferedPsk::allocate()?,
            list: self,
        })
    }

    fn has_next(&self) -> bool {
        // SAFETY: *mut cast - s2n-tls does not treat the pointer as mutable.
        unsafe { s2n_offered_psk_list_has_next(self.as_s2n_ptr() as *mut _) }
    }

    fn next(&mut self, psk: &mut OfferedPsk) -> Result<(), crate::error::Error> {
        let psk_ptr = psk.ptr.as_ptr();
        unsafe { s2n_offered_psk_list_next(self.as_s2n_ptr_mut(), psk_ptr).into_result() }?;
        Ok(())
    }

    fn choose_psk(&mut self, psk: &OfferedPsk) -> Result<(), crate::error::Error> {
        let mut_psk = psk.ptr.as_ptr();
        unsafe { s2n_offered_psk_list_choose_psk(self.as_s2n_ptr_mut(), mut_psk).into_result()? };
        Ok(())
    }

    fn reread(&mut self) -> Result<(), crate::error::Error> {
        unsafe { s2n_offered_psk_list_reread(self.as_s2n_ptr_mut()).into_result() }?;
        Ok(())
    }
}

pub struct IdentitySelector<'selector, 'callback> {
    psk: OfferedPsk<'callback>,
    // it is necessary for 'callback to outlive 'selector, because we want to be able
    // to create multiple 'selector within the scope of a single 'callback.
    list: &'selector mut OfferedPskListRef<'callback>,
}

impl IdentitySelector<'_, '_> {
    /// Choose the PSK returned from the last call to `next()` to negotiate with.
    ///
    /// If no offered PSK is acceptable, implementors can return from the callback
    /// without calling this function to reject the connection.
    pub fn choose_current_psk(&mut self) -> Result<(), crate::error::Error> {
        self.list.choose_psk(&self.psk)
    }
}

impl<'callback> Iterator for IdentitySelector<'_, 'callback> {
    type Item = Result<&'callback [u8], crate::error::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.list.has_next() {
            if let Err(e) = self.list.next(&mut self.psk) {
                return Some(Err(e));
            }
            Some(self.psk.identity())
        } else {
            None
        }
    }
}

#[cfg(test)]
struct OfferedPskSelector<'selector, 'callback> {
    psk: OfferedPsk<'callback>,
    list: &'selector mut OfferedPskListRef<'callback>,
}

#[cfg(test)]
impl OfferedPskSelector<'_, '_> {
    /// Advance the cursor, returning the currently selected PSK.
    fn advance(&mut self) -> Result<Option<&OfferedPsk>, crate::error::Error> {
        if !self.list.has_next() {
            Ok(None)
        } else {
            self.list.next(&mut self.psk)?;
            Ok(Some(&self.psk))
        }
    }

    /// Choose the currently selected PSK to negotiate with.
    ///
    /// If no offered PSK is acceptable, implementors can return from the callback
    /// without calling this function to reject the connection.
    fn choose_current_psk(&mut self) -> Result<(), crate::error::Error> {
        self.list.choose_psk(&self.psk)
    }

    /// Reset the cursor, allowing the list to be reread.
    fn reset(&mut self) -> Result<(), crate::error::Error> {
        self.list.reread()?;
        Ok(())
    }
}

/// A trait used by the server to select an external PSK given a client's offered
/// list of external PSK identities.
///
/// If working with small numbers of PSKs, consider just directly using [Connection::append_psk].
///
/// Used in conjunction with [crate::config::Builder::set_psk_selection_callback].
pub trait PskSelectionCallback: 'static + Send + Sync {
    /// Select a psk using the [OfferedPskListRef].
    ///
    /// Use [`OfferedPskListRef::identities`] to retrieve an iterator over the
    /// identities that the client has offered.
    ///
    /// Before calling [`IdentitySelector::choose_current_psk`], implementors must
    /// first append the corresponding [`crate::external_psk::ExternalPsk`] to the
    /// connection using [`Connection::append_psk`].
    fn select_psk(&self, connection: &mut Connection, psk_list: &mut OfferedPskListRef);
}

#[cfg(test)]
mod tests {
    use std::{
        ops::Deref,
        sync::{
            atomic::{self, AtomicBool},
            Arc,
        },
    };

    use crate::error::Error as S2NError;

    use crate::{
        config::Config,
        error::{ErrorSource, ErrorType},
        external_psk::ExternalPsk,
        security::DEFAULT_TLS13,
        testing::TestPair,
    };

    use super::*;

    type Identity = [u8; 8];

    #[derive(Clone)]
    struct TestPskStore {
        store: Arc<Vec<ExternalPsk>>,
        invoked: Arc<AtomicBool>,
    }

    impl TestPskStore {
        const SIZE: u8 = 200;
        const ID_LEN: usize = 8;

        fn psk_identity(id: u8) -> Identity {
            [id; Self::ID_LEN]
        }

        fn test_psk(id: u8) -> Result<ExternalPsk, S2NError> {
            let mut psk = ExternalPsk::builder()?;
            psk.with_identity(&Self::psk_identity(id))?
                .with_secret(&[id + 1; 16])?
                .with_hmac(crate::enums::PskHmac::SHA384)?;
            psk.build()
        }

        pub fn new() -> Result<Self, S2NError> {
            let store = (0..Self::SIZE)
                .map(Self::test_psk)
                .filter_map(Result::ok)
                .collect();
            Ok(Self {
                store: Arc::new(store),
                invoked: Arc::new(AtomicBool::new(false)),
            })
        }

        pub fn get_by_identity(&self, identity: &[u8]) -> Option<&ExternalPsk> {
            let index = identity[0];
            self.store.get(index as usize)
        }
    }

    impl PskSelectionCallback for TestPskStore {
        fn select_psk(&self, connection: &mut Connection, psk_list: &mut OfferedPskListRef) {
            self.invoked.store(true, atomic::Ordering::Relaxed);

            let identities: Vec<&[u8]> = psk_list
                .identities()
                .unwrap()
                .map(|psk| psk.unwrap())
                .collect();

            // identities are successfully read
            for (i, identity) in identities.iter().enumerate() {
                assert_eq!(&[i as u8; TestPskStore::ID_LEN], *identity);
            }

            // reset (called internally by OfferedPskListRef::identities) yields
            // the same identities again
            let identities_again: Vec<&[u8]> = psk_list
                .identities()
                .unwrap()
                .map(|psk| psk.unwrap())
                .collect();

            assert_eq!(identities.len(), Self::SIZE as usize);
            assert_eq!(identities, identities_again);

            let mut identity_selector = psk_list.identities().unwrap();
            let chosen = identity_selector.next().unwrap().unwrap();

            let chosen_external = self.get_by_identity(chosen).unwrap();
            connection.append_psk(chosen_external).unwrap();
            identity_selector.choose_current_psk().unwrap();
        }
    }

    #[test]
    fn psk_handshake_with_callback() -> Result<(), S2NError> {
        let psk_store = TestPskStore::new()?;
        let client_psks = psk_store.clone();

        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.set_psk_selection_callback(psk_store)?;

        let config = config.build()?;
        let mut test_pair = TestPair::from_config(&config);
        for psk in client_psks.store.iter() {
            test_pair.client.append_psk(psk)?;
        }
        assert!(test_pair.handshake().is_ok());
        assert!(client_psks.invoked.load(atomic::Ordering::Relaxed));
        Ok(())
    }

    #[test]
    // If choose_current_psk is called when there isn't a current psk, s2n-tls
    // should return a well formed error.
    fn choose_without_current_psk() -> Result<(), crate::error::Error> {
        #[derive(Clone)]
        struct ImmediateSelect {
            invoked: Arc<AtomicBool>,
        }

        impl PskSelectionCallback for ImmediateSelect {
            fn select_psk(&self, _connection: &mut Connection, psk_list: &mut OfferedPskListRef) {
                self.invoked.store(true, atomic::Ordering::Relaxed);

                let err = psk_list
                    .identities()
                    .unwrap()
                    .choose_current_psk()
                    .unwrap_err();
                assert_eq!(err.kind(), ErrorType::InternalError);
                assert_eq!(err.source(), ErrorSource::Library);
            }
        }

        let selector = ImmediateSelect {
            invoked: Arc::new(AtomicBool::new(false)),
        };
        let selector_handle = selector.clone();
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.set_psk_selection_callback(selector)?;

        let mut test_pair = TestPair::from_config(&config.build()?);
        test_pair.client.append_psk(&TestPskStore::test_psk(1)?)?;
        assert!(test_pair.handshake().is_err());
        assert!(selector_handle.invoked.load(atomic::Ordering::Relaxed));
        Ok(())
    }

    #[test]
    // If choose_current_psk isn't called, then the handshake should fail gracefully.
    fn no_chosen_psk() -> Result<(), crate::error::Error> {
        #[derive(Clone)]
        struct NeverSelect(Arc<AtomicBool>);

        impl PskSelectionCallback for NeverSelect {
            fn select_psk(
                &self,
                _connection: &mut Connection,
                _psk_cursor: &mut OfferedPskListRef,
            ) {
                self.0.store(true, atomic::Ordering::Relaxed);
                // return without calling cursor.choose_current_psk
            }
        }

        let selector = NeverSelect(Arc::new(AtomicBool::new(false)));
        let selector_handle = selector.clone();
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.set_psk_selection_callback(selector)?;

        let mut test_pair = TestPair::from_config(&config.build()?);
        test_pair.client.append_psk(&TestPskStore::test_psk(1)?)?;

        let err = test_pair.handshake().unwrap_err();
        assert_eq!(err.kind(), ErrorType::ProtocolError);
        assert_eq!(err.source(), ErrorSource::Library);
        assert!(selector_handle.0.load(atomic::Ordering::Relaxed));
        Ok(())
    }

    #[test]
    fn offered_psk_selector_workflow() -> Result<(), S2NError> {
        struct UseOfferedPskSelector(TestPskStore);
        impl Deref for UseOfferedPskSelector {
            type Target = TestPskStore;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl PskSelectionCallback for UseOfferedPskSelector {
            fn select_psk(&self, connection: &mut Connection, psk_list: &mut OfferedPskListRef) {
                self.invoked.store(true, atomic::Ordering::Relaxed);

                let identities: Vec<&[u8]> = psk_list
                    .identities()
                    .unwrap()
                    .map(|psk| psk.unwrap())
                    .collect();

                let mut identities_from_offered_psk = Vec::new();
                let mut offered_psks = psk_list.offered_psks().unwrap();
                while let Some(psk) = offered_psks.advance().unwrap() {
                    // `psk.identity()` can not outlive `psk``, so use to_owned()
                    identities_from_offered_psk.push(psk.identity().unwrap().to_owned());
                }

                // the identities from the iterators should be the same
                assert_eq!(identities, identities_from_offered_psk);

                offered_psks.reset().unwrap();
                let psk = offered_psks.advance().unwrap().unwrap();
                let identity = psk.identity().unwrap();
                let psk = self.get_by_identity(identity).unwrap();
                connection.append_psk(psk).unwrap();
                offered_psks.choose_current_psk().unwrap();
            }
        }

        let selector = UseOfferedPskSelector(TestPskStore::new()?);
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.set_psk_selection_callback(selector)?;

        let mut test_pair = TestPair::from_config(&config.build()?);
        test_pair.client.append_psk(&TestPskStore::test_psk(1)?)?;
        assert!(test_pair.handshake().is_ok());

        Ok(())
    }
}
