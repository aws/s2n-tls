// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls_sys::*;

fn main() {
    unsafe {
        s2n_init();
        let conn = s2n_connection_new(s2n_mode::SERVER);

        if !conn.is_null() {
            s2n_connection_free(conn);
        }
    }
}
