// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use tabled::Tabled;
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
    use std::{collections::BTreeMap, task::Poll};
    use tabled::{Table, Tabled, settings::Style};

    /// Return an estimation of the memory size of the IO buffers
    ///
    /// This isn't totally accurate because it doesn't account for any indirection that
    /// may be present.
    fn test_pair_io_size(pair: &TestPair) -> usize {
        pair.io.client_tx_stream.borrow().capacity() + pair.io.server_tx_stream.borrow().capacity()
    }

    fn fuzzy_equals(actual: usize, expected: usize) -> bool {
        const TOLERANCE: usize = 0;

        println!("actual: {actual}, expected: {expected}");
        actual <= expected + TOLERANCE && actual >= expected - TOLERANCE
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

    /// lifted from dhat-rs so that we can implement "Tabled" on it
    #[derive(Clone, Debug, PartialEq, Eq, Tabled)]
    #[non_exhaustive]
    pub struct S2NHeapStats {
        /// Number of blocks (a.k.a. allocations) allocated over the entire run.
        pub total_blocks: u64,

        /// Number of bytes allocated over the entire run.
        pub total_bytes: u64,

        /// Number of blocks (a.k.a. allocations) currently allocated.
        pub curr_blocks: usize,

        /// Number of bytes currently allocated.
        pub curr_bytes: usize,

        /// Number of blocks (a.k.a. allocations) allocated at the global peak,
        /// i.e. when `curr_bytes` peaked.
        pub max_blocks: usize,

        /// Number of bytes allocated at the global peak, i.e. when `curr_bytes`
        /// peaked.
        pub max_bytes: usize,
    }

    #[derive(Debug, Clone, Tabled)]
    pub struct ResultRow {
        stage: String,
        #[tabled(inline)]
        measurement: S2NHeapStats,
        test_pair_size: usize,
    }

    impl S2NHeapStats {
        /// Return a "diff" against some earlier baseline. This is useful when
        /// there were big allocations earlier in the program lifecycle that you
        /// want to ignore
        fn against_baseline(&self, baseline: &S2NHeapStats) -> S2NHeapStats {
            // dbg!(self);
            // dbg!(baseline);
            let mut diff = self.clone();
            diff.total_blocks -= baseline.total_blocks;
            diff.total_bytes -= baseline.total_bytes;
            diff.curr_blocks -= baseline.curr_blocks;
            diff.curr_bytes -= baseline.curr_bytes;
            diff.max_blocks -= baseline.max_blocks;
            diff.max_bytes -= baseline.max_bytes;
            diff
        }
    }

    impl From<dhat::HeapStats> for S2NHeapStats {
        fn from(value: dhat::HeapStats) -> Self {
            Self {
                total_blocks: value.total_blocks,
                total_bytes: value.total_bytes,
                curr_blocks: value.curr_blocks,
                curr_bytes: value.curr_bytes,
                max_blocks: value.max_blocks,
                max_bytes: value.max_bytes,
            }
        }
    }

    #[derive(Debug, PartialEq, PartialOrd, Ord, Eq)]
    enum Lifecycle {
        ConnectionInit,
        AfterClientHello,
        AfterServerHello,
        AfterClientFinished,
        HandshakeComplete,
        ApplicationData,
    }

    impl Lifecycle {
        pub fn all_stages() -> Vec<Lifecycle> {
            vec![
                Lifecycle::ConnectionInit,
                Lifecycle::AfterClientHello,
                Lifecycle::AfterServerHello,
                Lifecycle::AfterClientFinished,
                Lifecycle::HandshakeComplete,
                Lifecycle::ApplicationData,
            ]
        }
    }

    struct MemoryRecorder {
        /// measurement after s2n_init
        /// 
        /// Currently unused but we should be emitted a metric for this
        _static_memory: S2NHeapStats,
        /// measurement after config initialization
        config_memory: S2NHeapStats,
        measurements: BTreeMap<Lifecycle, (S2NHeapStats, usize)>,
    }

    impl MemoryRecorder {
        fn measure(&mut self, lifecycle: Lifecycle, pair: &TestPair) {
            self.measurements.insert(
                lifecycle,
                (dhat::HeapStats::get().into(), test_pair_io_size(pair)),
            );
        }

        fn measurements_complete(&self) -> bool {
            Lifecycle::all_stages()
                .into_iter()
                .all(|stage| self.measurements.contains_key(&stage))
        }

        /// return a table showing the measurements at various lifecycle points,
        /// measured against the config creation baseline.
        fn measurement_table(&self) -> Table {
            assert!(self.measurements_complete());
            let table: Vec<ResultRow> = Lifecycle::all_stages()
                .into_iter()
                .map(|stage| {
                    let (measurement, test_pair_size) =
                        self.measurements.get(&stage).unwrap().clone();
                    let measurement = measurement.against_baseline(&self.config_memory);
                    ResultRow {
                        stage: format!("{stage:?}"),
                        measurement,
                        test_pair_size,
                    }
                })
                .collect();
            let mut table = Table::new(table);
            table.with(Style::markdown());
            table
        }

        /// return a table showing the diff between each step in the connection
        /// lifecycle. The static memory row is an absolute measurement, not a diff.
        fn assert_expected(&self) {
            const EXPECTED_MEMORY: &[(Lifecycle, usize)] = &[
                (Lifecycle::ConnectionInit, 61_482),
                (Lifecycle::AfterClientHello, 88_302),
                (Lifecycle::AfterServerHello, 116_669),
                (Lifecycle::AfterClientFinished, 107_976),
                (Lifecycle::HandshakeComplete, 90_563),
                (Lifecycle::ApplicationData, 90_563),
            ];
            let actual_memory: Vec<(Lifecycle, usize)> = Lifecycle::all_stages()
                .into_iter()
                .map(|stage| {
                    let measurement = self.measurements.get(&stage).unwrap().0.against_baseline(&self.config_memory);
                    (stage, measurement.curr_bytes)
                })
                .collect();

            for (actual, expected ) in actual_memory.iter().zip(EXPECTED_MEMORY) {
                // make sure we're looking at the right stage
                assert_eq!(actual.0, expected.0);
                assert!(fuzzy_equals(actual.1, expected.1))
            }
        }
    }

    struct MemoryRecordBuilder {
        static_memory: Option<dhat::HeapStats>,
        config_memory: Option<dhat::HeapStats>,
    }

    impl MemoryRecordBuilder {
        fn new() -> Self {
            Self {
                static_memory: None,
                config_memory: None,
            }
        }

        fn after_init(&mut self) {
            self.static_memory = Some(dhat::HeapStats::get());
        }

        fn after_config_creation(mut self) -> MemoryRecorder {
            self.config_memory = Some(dhat::HeapStats::get());

            MemoryRecorder {
                _static_memory: self.static_memory.unwrap().into(),
                config_memory: self.config_memory.unwrap().into(),
                measurements: Default::default(),
            }
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
        let mut memory_recorder = MemoryRecordBuilder::new();

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
        memory_recorder.after_init();

        let config = testing::build_config(&Policy::from_version("default_tls13")?).unwrap();
        let mut memory_recorder = memory_recorder.after_config_creation();

        let mut pair = TestPair::from_config(&config);
        memory_recorder.measure(Lifecycle::ConnectionInit, &pair);

        ////////////////////////////////////////////////////////////////////////
        ////////////////////////////// handshake ///////////////////////////////
        ////////////////////////////////////////////////////////////////////////

        assert!(matches!(pair.client.poll_negotiate(), Poll::Pending));
        memory_recorder.measure(Lifecycle::AfterClientHello, &pair);

        assert!(matches!(pair.server.poll_negotiate(), Poll::Pending));
        memory_recorder.measure(Lifecycle::AfterServerHello, &pair);

        assert!(matches!(pair.client.poll_negotiate(), Poll::Ready(_)));
        memory_recorder.measure(Lifecycle::AfterClientFinished, &pair);

        assert!(matches!(pair.server.poll_negotiate(), Poll::Ready(_)));
        memory_recorder.measure(Lifecycle::HandshakeComplete, &pair);

        ////////////////////////////////////////////////////////////////////////
        /////////////////////////// application data ///////////////////////////
        ////////////////////////////////////////////////////////////////////////

        let _ = pair.client.poll_send(CLIENT_MESSAGE);
        let _ = pair.server.poll_send(SERVER_MESSAGE);
        let _ = pair.client.poll_recv(&mut [0; SERVER_MESSAGE.len()]);
        let _ = pair.server.poll_recv(&mut [0; CLIENT_MESSAGE.len()]);
        memory_recorder.measure(Lifecycle::ApplicationData, &pair);

        println!("{}", memory_recorder.measurement_table());
        memory_recorder.assert_expected();

        Ok(())
    }
}
