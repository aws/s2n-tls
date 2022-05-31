// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::raw::{config::Config, connection::Connection, enums::Mode, error::Error};

/// A trait indicating that a structure can produce connections.
pub trait Builder: Clone {
    type Output: AsMut<Connection> + AsRef<Connection>;
    fn build(&self, mode: Mode) -> Result<Self::Output, Error>;
}

/// Produces new connections with the given Config set.
impl Builder for Config {
    type Output = Connection;
    fn build(&self, mode: Mode) -> Result<Self::Output, Error> {
        let mut conn = Connection::new(mode);
        conn.set_config(self.clone())?;
        Ok(conn)
    }
}

/// Produces new connections from a builder, then modifies them.
///
/// Can be used to apply connection-level config.
#[derive(Clone)]
pub struct ModifiedBuilder<F, B: Builder>
where
    F: Fn(&mut Connection) -> Result<&mut Connection, Error> + Clone,
{
    builder: B,
    modifier: F,
}

impl<F, B: Builder> ModifiedBuilder<F, B>
where
    F: Fn(&mut Connection) -> Result<&mut Connection, Error> + Clone,
{
    pub fn new(builder: B, modifier: F) -> Self {
        Self { builder, modifier }
    }
}

impl<F, B: Builder> Builder for ModifiedBuilder<F, B>
where
    F: Fn(&mut Connection) -> Result<&mut Connection, Error> + Clone,
{
    type Output = B::Output;
    fn build(&self, mode: Mode) -> Result<Self::Output, Error> {
        let mut conn = self.builder.build(mode)?;
        (self.modifier)(conn.as_mut())?;
        Ok(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_builder() -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::default();
        let conn = config.build(Mode::Server)?;
        assert_eq!(conn.config(), Some(config));
        Ok(())
    }

    #[test]
    fn modified_builder() -> Result<(), Box<dyn std::error::Error>> {
        let config_a = Config::default();
        let config_b = Config::default();
        assert!(config_a != config_b);

        let builder =
            ModifiedBuilder::new(config_a.clone(), |conn| conn.set_config(config_b.clone()));

        let conn = builder.build(Mode::Server)?;
        assert!(conn.config() != Some(config_a));
        assert_eq!(conn.config(), Some(config_b));
        Ok(())
    }
}
