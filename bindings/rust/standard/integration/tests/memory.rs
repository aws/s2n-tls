// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;
#[cfg(not(feature = "no-sensitive-tests"))]
mod memory_test {
    // dhat can only be run in a single thread, so we use a single test case in an
    // "integration" test (tests/*) to fulfill those conditions.

    use s2n_tls::{
        error::Error as S2NError,
        security::Policy,
        testing::{self, TestPair},
    };
    use std::task::Poll;

    /// Return an estimation of the memory size of the IO buffers
    ///
    /// This isn't totally accurate because it doesn't account for any indirection that
    /// may be present.
    fn test_pair_io_size(pair: &TestPair) -> usize {
        pair.io.client_tx_stream.borrow().capacity() + pair.io.server_tx_stream.borrow().capacity()
    }

    fn fuzzy_equals(actual: usize, expected: usize) -> bool {
        const TOLERANCE: usize = 100;

        println!("actual: {actual}, expected: {expected}");
        actual < expected + TOLERANCE && actual > expected - TOLERANCE
    }

    mod memory_callbacks {
        use std::alloc::Layout;

        /// A tagged allocator which prefixes each blob with the length of the allocation.
        ///
        /// ```text
        ///          size            public allocation
        ///  v---------------------  v---------
        /// [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ... ]
        ///  ^                      
        ///  allocation                      
        ///  
        /// ```
        ///
        /// This is necessary because the [`std::alloc::dealloc`] requires the length of
        /// the blob to be deallocated, but the AWS-LC memory `free` callback does not
        /// return the length.
        struct TaggedAllocation {
            /// the private view
            allocation: *mut u8,
            /// allocation size including the prefix
            size: usize,
        }

        impl TaggedAllocation {
            const ALIGNMENT: usize = size_of::<usize>();
            const USIZE_WIDTH: usize = size_of::<usize>();

            pub fn public_allocation(&self) -> *mut u8 {
                unsafe { self.allocation.add(Self::USIZE_WIDTH) }
            }
        }

        impl TaggedAllocation {
            /// Return an allocation of `size` bytes
            ///
            /// Internally allocates extra bytes to also store the size of the allocation.
            unsafe fn alloc(public_size: usize) -> Self {
                let needed_size = public_size + Self::USIZE_WIDTH;
                let layout = Layout::from_size_align(needed_size, Self::ALIGNMENT).unwrap();

                let allocation = std::alloc::alloc(layout);
                (allocation as *mut usize).write(needed_size);

                Self {
                    allocation,
                    size: needed_size,
                }
            }

            unsafe fn from_public_view(public_view: *mut u8) -> Self {
                let alloc_start = (public_view as *mut usize).sub(1);
                let size = (alloc_start as *mut usize).read();
                Self {
                    allocation: alloc_start as *mut u8,
                    size,
                }
            }

            unsafe fn realloc(&mut self, new_public_size: usize) {
                let new_size = new_public_size + Self::USIZE_WIDTH;
                let old_layout = Layout::from_size_align(self.size, Self::ALIGNMENT).unwrap();

                let allocation = std::alloc::realloc(self.allocation, old_layout, new_size);
                (allocation as *mut usize).write(new_size);

                self.allocation = allocation;
                self.size = new_size;
            }

            unsafe fn free(self) {
                let layout = Layout::from_size_align(self.size, Self::ALIGNMENT).unwrap();
                std::alloc::dealloc(self.allocation, layout);
            }
        }

        pub unsafe extern "C" fn malloc_cb(
            num: usize,
            _file: *const std::ffi::c_char,
            _line: i32,
        ) -> *mut std::ffi::c_void {
            let allocation = TaggedAllocation::alloc(num);
            allocation.public_allocation() as *mut _
        }

        pub unsafe extern "C" fn realloc_cb(
            addr: *mut std::ffi::c_void,
            num: usize,
            _file: *const std::ffi::c_char,
            _line: i32,
        ) -> *mut std::ffi::c_void {
            let mut allocation = TaggedAllocation::from_public_view(addr as *mut _);
            allocation.realloc(num);
            allocation.public_allocation() as *mut _
        }

        pub unsafe extern "C" fn free_cb(
            addr: *mut std::ffi::c_void,
            _file: *const std::ffi::c_char,
            _line: i32,
        ) {
            let allocation = TaggedAllocation::from_public_view(addr as *mut _);
            allocation.free();
        }
    }

    /// The dhat-rs memory profiler can only measure memory allocated from the rust
    /// global allocator.
    ///
    /// The s2n-tls rust bindings set the s2n-tls memory callbacks to use the rust
    /// allocator, and we use `CRYPTO_set_mem_functions` to force aws-lc to use the
    /// rust system allocator.
    ///
    /// It's important to keep allocations to a minimal amount in this test to give
    /// as accurate a picture as possible into s2n-tls memory usage at various stages
    /// in the connection lifecycle. We should limit this to
    /// - config
    /// - client connection
    /// - server connection
    /// - TestPair io buffers
    #[test]
    fn memory_consumption() -> Result<(), S2NError> {
        const CLIENT_MESSAGE: &[u8] = b"from client";
        const SERVER_MESSAGE: &[u8] = b"from server";

        let _profiler = dhat::Profiler::new_heap();

        unsafe {
            aws_lc_sys::CRYPTO_set_mem_functions(
                Some(memory_callbacks::malloc_cb),
                Some(memory_callbacks::realloc_cb),
                Some(memory_callbacks::free_cb),
            )
        };

        // s2n-tls allocates memory for the default configs. This includes the system
        // trust store, which is often a significant amount of memory (~1 MB). This
        // is system specific, so we don't actually assert on this value.
        s2n_tls::init::init();
        let static_memory = dhat::HeapStats::get().curr_bytes;

        let config = testing::build_config(&Policy::from_version("default_tls13")?).unwrap();
        let config_memory = dhat::HeapStats::get().curr_bytes;

        let mut pair = TestPair::from_config(&config);
        let connection_init = dhat::HeapStats::get().curr_bytes - test_pair_io_size(&pair);

        // manually drive the handshake forward to get a measurement while the handshake
        // is in flight
        assert!(matches!(pair.client.poll_negotiate(), Poll::Pending));
        assert!(matches!(pair.server.poll_negotiate(), Poll::Pending));

        let handshake_in_progress = dhat::HeapStats::get().curr_bytes - test_pair_io_size(&pair);

        pair.handshake()?;
        let handshake_complete = dhat::HeapStats::get().curr_bytes - test_pair_io_size(&pair);

        let _ = pair.client.poll_send(CLIENT_MESSAGE);
        let _ = pair.server.poll_send(SERVER_MESSAGE);
        let _ = pair.client.poll_recv(&mut [0; SERVER_MESSAGE.len()]);
        let _ = pair.server.poll_recv(&mut [0; CLIENT_MESSAGE.len()]);
        let application_data = dhat::HeapStats::get().curr_bytes - test_pair_io_size(&pair);

        // cost of connection in various states
        let connection_init = connection_init - config_memory;
        let handshake_in_progress = handshake_in_progress - config_memory;
        let handshake_complete = handshake_complete - config_memory;
        let application_data = application_data - config_memory;

        // cost of config
        let config_init = config_memory - static_memory;

        println!("static memory: {static_memory}");
        println!("config: {config_init}");
        println!("connection_init: {connection_init}");
        println!("handshake in progress: {handshake_in_progress}");
        println!("handshake complete: {handshake_complete}");
        println!("application data: {application_data}");
        println!("max usage: {}", dhat::HeapStats::get().max_bytes - static_memory);

        assert!(fuzzy_equals(config_init, 19_259));
        assert!(fuzzy_equals(connection_init, 61_482));
        assert!(fuzzy_equals(handshake_in_progress, 112_505));
        assert!(fuzzy_equals(handshake_complete, 86_399));
        assert!(fuzzy_equals(application_data, 86_399));
        assert!(fuzzy_equals(
            dhat::HeapStats::get().max_bytes - static_memory,
            150_378
        ));

        Ok(())
    }
}
