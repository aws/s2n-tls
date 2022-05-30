// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Utilities to handle reusing connections.
//!
//! Creating a single new connection requires significant
//! memory allocations (about 50-60 KB, according to some tests).
//! Instead of allocating memory for a new connection, existing
//! memory can be reused by calling
//! [Connection::wipe()](`s2n_tls::raw::connection::Connection::wipe()).
//!
//! The [`Pool`] trait allows applications to define an
//! [Object pool](https://en.wikipedia.org/wiki/Object_pool_pattern) that
//! wipes and stores connections after they are dropped.
//!
//! We also provide a basic Pool implementation, [`ConfigPool`], that
//! implements the pool as a [VecDeque](`std::collections::VecDeque`)
//! with a fixed maximum size.

use crate::raw::{
    config::Config,
    connection::Connection,
    enums::Mode,
    error::Error,
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use crate::raw::connection::Builder;

/// A connection produced by a [`Pool`].
///
/// When dropped, returns ownership of the connection to
/// the pool that produced it by calling [`Pool::reclaim()`].
#[derive(Debug)]
pub struct PooledConnection<T: Pool> {
    pool: T,
    conn: Option<Connection>,
}

impl<T: Pool> AsRef<Connection> for PooledConnection<T> {
    fn as_ref(&self) -> &Connection {
        self.conn.as_ref().map(|c| c.as_ref()).unwrap()
    }
}

impl<T: Pool> AsMut<Connection> for PooledConnection<T> {
    fn as_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().map(|c| c.as_mut()).unwrap()
    }
}

impl<T: Pool> Drop for PooledConnection<T> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.give(conn);
        }
    }
}

impl<T: Pool> PooledConnection<T> {
    pub fn new(pool: &T) -> Result<PooledConnection<T>, Error> {
        pool.take().map(|conn| {
            let conn = Some(conn);
            let pool = pool.clone();
            Self { pool, conn }
        })
    }
}

/// An object pool for wiping and reusing connection memory.
///
/// Minimally, an implementation should call [`Connection::wipe()`]
/// during [`reclaim()`].
pub trait Pool: Clone {
    fn mode(&self) -> Mode;
    fn take(&self) -> Result<Connection, Error>;
    fn give(&self, conn: Connection);
}

struct ConfigPoolState {
    mode: Mode,
    config: Config,
    pool: Mutex<VecDeque<Connection>>,
    max_pool_size: usize,
}

/// Builder for [`ConfigPool`].
pub struct ConfigPoolBuilder(ConfigPoolState);
impl ConfigPoolBuilder {
    pub fn new(mode: Mode, config: Config) -> Self {
        Self(ConfigPoolState {
            mode,
            config,
            pool: Mutex::new(VecDeque::new()),
            max_pool_size: usize::MAX,
        })
    }

    pub fn set_pool(&mut self, pool: VecDeque<Connection>) -> &mut Self {
        self.0.pool = Mutex::new(pool);
        self
    }

    /// The maximum size of the underlying [`VecDeque`].
    ///
    /// This is NOT the maximum connections that can be created.
    /// When the number of connections created exceeds the `max_pool_size`,
    /// excess reclaimed connections are dropped instead of stored
    /// in the pool.
    pub fn set_max_pool_size(&mut self, max_pool_size: usize) -> &mut Self {
        self.0.max_pool_size = max_pool_size;
        self
    }

    pub fn build(self) -> ConfigPool {
        ConfigPool(Arc::new(self.0))
    }
}

#[derive(Clone)]
pub struct ConfigPool(Arc<ConfigPoolState>);

impl ConfigPool {
    pub fn pool_size(&self) -> usize {
        self.0.pool.lock().map(|pool| pool.len()).unwrap_or(0)
    }

    pub fn is_poisoned(&self) -> bool {
        self.0.pool.is_poisoned()
    }
}

impl Pool for ConfigPool {
    fn mode(&self) -> Mode {
        self.0.mode
    }

    /// Get a connection.
    ///
    /// If connections are available in the pool, one will
    /// be returned. Otherwise, a new connection will be created.
    fn take(&self) -> Result<Connection, Error> {
        let inner = &self.0;
        let from_pool = match inner.pool.lock() {
            Ok(mut pool) => pool.pop_front(),
            Err(_) => None,
        };
        let conn = match from_pool {
            // Wiping a connection doesn't wipe the config,
            // so we don't need to reset the config.
            Some(conn) => conn,
            // Create a new connection with the stored config.
            None => inner.config.build_connection(inner.mode)?
        };
        Ok(conn)
    }

    /// Recycle a connection.
    ///
    /// The connection is wiped and returned to the pool
    /// if space is available.
    fn give(&self, mut conn: Connection) {
        let inner = &self.0;
        let wiped = conn.wipe().is_ok();
        if let Ok(mut pool) = inner.pool.lock() {
            if pool.len() < inner.max_pool_size && wiped {
                pool.push_back(conn);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::config::Config;

    #[test]
    fn simple_pool_single_connection() -> Result<(), Box<dyn std::error::Error>> {
        let pool = ConfigPoolBuilder::new(Mode::Server, Config::default()).build();

        // Repeatedly checkout the same connection
        assert_eq!(pool.pool_size(), 0);
        for _ in 0..5 {
            let _conn = PooledConnection::new(&pool)?;
            assert_eq!(pool.pool_size(), 0);
        }
        assert_eq!(pool.pool_size(), 1);
        Ok(())
    }

    #[test]
    fn simple_pool_multiple_connections() -> Result<(), Box<dyn std::error::Error>> {
        let pool = ConfigPoolBuilder::new(Mode::Server, Config::default()).build();

        // We need to hold onto connections so that they're not
        // immediately reclaimed by the pool.
        let mut conns = VecDeque::new();

        // Checkout multiple connections
        const COUNT: usize = 25;
        for _ in 0..COUNT {
            conns.push_back(PooledConnection::new(&pool)?);
            assert_eq!(pool.pool_size(), 0);
        }
        assert_eq!(conns.len(), COUNT);

        // Drop all outstanding connections, returning them to the pool
        conns.clear();
        assert_eq!(pool.pool_size(), COUNT);

        // Reuse a subset of the connections
        const SUBSET_COUNT: usize = COUNT / 2;
        for i in 1..=SUBSET_COUNT {
            conns.push_back(PooledConnection::new(&pool)?);
            // The pool should drain as we reuse connections.
            assert_eq!(pool.pool_size(), COUNT - i);
        }
        assert_eq!(conns.len(), SUBSET_COUNT);
        assert_eq!(pool.pool_size(), COUNT - SUBSET_COUNT);

        // Drop all outstanding connections, returning them to the pool
        conns.clear();
        assert_eq!(pool.pool_size(), COUNT);

        Ok(())
    }

    #[test]
    fn simple_pool_with_max_size() -> Result<(), Box<dyn std::error::Error>> {
        const POOL_MAX_SIZE: usize = 11;
        let mut pool = ConfigPoolBuilder::new(Mode::Server, Config::default());
        pool.set_max_pool_size(POOL_MAX_SIZE);
        let pool = pool.build();

        // We need to hold onto connections so that they're not
        // immediately reclaimed by the pool.
        let mut conns = VecDeque::new();

        // Create more connections than the pools can hold
        const COUNT: usize = 25;
        for _ in 0..COUNT {
            conns.push_back(PooledConnection::new(&pool)?);
        }
        assert_eq!(conns.len(), COUNT);

        // Drop all outstanding connections, returning them to the pools
        // The pool should now hold its maximum.
        conns.clear();
        assert_eq!(pool.pool_size(), POOL_MAX_SIZE);

        Ok(())
    }
}
