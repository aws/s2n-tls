// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::raw::{config, connection::Connection, enums::Mode, error::Error};

/// Produces new, un-negotiated connections.
pub trait Config {
    fn create(&self, mode: Mode) -> Result<Connection, Error>;
}

/// Produces new, un-negotiated connections with the given Config set.
impl Config for config::Config {
    fn create(&self, mode: Mode) -> Result<Connection, Error> {
        let mut conn = Connection::new(mode);
        conn.set_config(self.clone())?;
        Ok(conn)
    }
}

/// Produces new, un-negotiated connections.
/// Useful for ad-hoc customization of connection creation.
impl<F> Config for F
where
    F: Fn(Mode) -> Result<Connection, Error>,
{
    fn create(&self, mode: Mode) -> Result<Connection, Error> {
        (self)(mode)
    }
}

/// Produces new, un-negotiated connections with the given Config set
/// and allows the connections to be modified after creation.
#[derive(Clone)]
pub struct ConnConfig<F>
where
    F: Fn(&mut Connection) -> Result<&mut Connection, Error>,
{
    config: config::Config,
    modifier: F,
}

impl<F> ConnConfig<F>
where
    F: Fn(&mut Connection) -> Result<&mut Connection, Error>,
{
    pub fn new(config: config::Config, modifier: F) -> Self {
        ConnConfig { config, modifier }
    }
}

impl<F> Config for ConnConfig<F>
where
    F: Fn(&mut Connection) -> Result<&mut Connection, Error>,
{
    fn create(&self, mode: Mode) -> Result<Connection, Error> {
        let mut conn = self.config.create(mode)?;
        (self.modifier)(&mut conn)?;
        Ok(conn)
    }
}
