// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::read_to_string;

pub fn read_to_bytes(path: &str) -> Vec<u8> {
    read_to_string(path).unwrap().into_bytes()
}

pub enum Mode {
    Client,
    Server,
}

pub trait TlsBenchHarness {
    /// Initialize buffers, configs, and connections (pre-handshake)
    fn new() -> Self;

    /// Run handshake on initialized connection
    /// Returns error if handshake already happened
    fn handshake(&mut self) -> Result<(), &str>;

    /// Checks if handshake is finished for both client and server
    fn handshake_completed(&self) -> bool;
}
