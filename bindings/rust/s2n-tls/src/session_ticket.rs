// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::ptr::NonNull;

use s2n_tls_sys::*;

use crate::{
    connection::Connection,
    error::{Error, Fallible},
};

/// A trait to retrieve session tickets from the connection
pub trait SessionTicketCallback {
    fn on_session_ticket(&self, connection: &mut Connection, session_ticket: SessionTicket);
}

/// Wrapper around a session ticket struct
#[derive(Debug)]
pub struct SessionTicket {
    data: Vec<u8>,
    lifetime: u32,
}

impl SessionTicket {
    pub fn from_raw(ticket: NonNull<s2n_session_ticket>) -> Result<Self, Error> {
        let mut lifetime = 0;
        unsafe { s2n_session_ticket_get_lifetime(ticket.as_ptr(), &mut lifetime).into_result()? };
        let mut data_len = 0;
        unsafe { s2n_session_ticket_get_data_len(ticket.as_ptr(), &mut data_len).into_result()? };
        let mut data = vec![0; data_len];
        unsafe {
            s2n_session_ticket_get_data(ticket.as_ptr(), data_len, data.as_mut_ptr())
                .into_result()?
        };

        Ok(Self { lifetime, data })
    }
    pub fn session_lifetime(&self) -> u32 {
        self.lifetime
    }

    pub fn session_data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn new(data: Vec<u8>) -> Self {
        Self { data, lifetime: 0 }
    }
}
