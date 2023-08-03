// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use s2n_tls_sys::*;

use crate::{
    connection::Connection,
    error::{Error, Fallible},
};

/// A trait to retrieve session tickets from the connection
pub trait SessionTicketCallback: Send + Sync + 'static {
    fn on_session_ticket(&self, connection: &mut Connection, session_ticket: &SessionTicket);
}

pub struct SessionTicket(s2n_session_ticket);

impl SessionTicket {
    pub(crate) fn from_ptr(ticket: &s2n_session_ticket) -> &Self {
        unsafe { &*(ticket as *const s2n_session_ticket as *const SessionTicket) }
    }

    // SAFETY: casting *const s2n_session_ticket -> *mut s2n_session_ticket: This is
    // safe as long as the data is not actually mutated. As authors of s2n-tls,
    // we know that the get_lifetime and get_data methods do not mutate the
    // data, and use mut pointers as a matter of convention because it makes
    // working with s2n_stuffers and s2n_blobs easier.
    pub(crate) fn deref_mut_ptr(&self) -> *mut s2n_session_ticket {
        &self.0 as *const s2n_session_ticket as *mut s2n_session_ticket
    }

    pub fn lifetime(&self) -> Result<Duration, Error> {
        let mut lifetime = 0;
        unsafe {
            s2n_session_ticket_get_lifetime(self.deref_mut_ptr(), &mut lifetime).into_result()?
        };
        Ok(Duration::new(lifetime.into(), 0))
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> Result<usize, Error> {
        let mut data_len = 0;
        unsafe {
            s2n_session_ticket_get_data_len(self.deref_mut_ptr(), &mut data_len).into_result()?
        };
        Ok(data_len)
    }

    pub fn data(&self, output: &mut [u8]) -> Result<(), Error> {
        unsafe {
            s2n_session_ticket_get_data(self.deref_mut_ptr(), output.len(), output.as_mut_ptr())
                .into_result()?
        };
        Ok(())
    }
}
