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
    fn on_session_ticket(&self, connection: &mut Connection, session_ticket: SessionTicket);
}

pub struct SessionTicket(s2n_session_ticket);

impl SessionTicket {
    pub(crate) fn from_raw(ticket: s2n_session_ticket) -> Self {
        SessionTicket(ticket)
    }

    // SAFETY: casting *const s2n_session_ticket -> *mut s2n_session_ticket: This is
    // safe as long as the data is not actually mutated. As authors of s2n-tls,
    // we know that the get_lifetime and get_data methods do not mutate the
    // data, and use mut pointers as a matter of convention because it makes
    // working with s2n_stuffers and s2n_blobs easier.
    pub(crate) fn as_mut_ptr(&self) -> *mut s2n_session_ticket {
        &self.0 as *const s2n_session_ticket as *mut s2n_session_ticket
    }

    pub fn session_lifetime(&self) -> Result<Duration, Error> {
        let mut lifetime = 0;
        unsafe { s2n_session_ticket_get_lifetime(self.as_mut_ptr(), &mut lifetime).into_result()? };
        Ok(Duration::new(lifetime.into(), 0))
    }

    ///`output` will be extended if necessary to store the session data
    pub fn session_data(&self, output: &mut Vec<u8>) -> Result<(), Error> {
        let mut data_len = 0;
        unsafe { s2n_session_ticket_get_data_len(self.as_mut_ptr(), &mut data_len).into_result()? };

        if output.capacity() < data_len {
            output.reserve_exact(data_len - output.len());
        }

        unsafe {
            s2n_session_ticket_get_data(self.as_mut_ptr(), data_len, output.as_mut_ptr())
                .into_result()?
        };
        Ok(())
    }
}
