# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

# Expected runtime is less than 50 seconds.

MAX_ARRAY_LEN = 10
DEFINES += -DMAX_ARRAY_LEN=$(MAX_ARRAY_LEN)

MAX_ARRAY_ELEMENT_SIZE = 10
DEFINES += -DMAX_ARRAY_ELEMENT_SIZE=$(MAX_ARRAY_ELEMENT_SIZE)

BINARY_SEARCH_BOUND = 5

DEFINES += -DMADV_DONTDUMP=1

CBMCFLAGS +=

HARNESS_ENTRY = s2n_set_add_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_utils.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(PROOF_STUB)/madvise.c
PROOF_SOURCES += $(PROOF_STUB)/memmove_havoc.c
PROOF_SOURCES += $(PROOF_STUB)/mlock.c
PROOF_SOURCES += $(PROOF_STUB)/munlock.c
PROOF_SOURCES += $(PROOF_STUB)/posix_memalign_override.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_calculate_stacktrace.c
PROOF_SOURCES += $(PROOF_STUB)/sysconf.c

PROJECT_SOURCES += $(SRCDIR)/utils/s2n_array.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_blob.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_ensure.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_mem.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_result.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_safety.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_set.c

# We abstract this function because manual inspection demonstrates it is unreachable.
REMOVE_FUNCTION_BODY += s2n_blob_slice
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_mem_c_s2n_mem_cleanup_impl

UNWINDSET += __CPROVER_file_local_s2n_set_c_s2n_set_binary_search.0:$(call addone,$(BINARY_SEARCH_BOUND))
UNWINDSET += __CPROVER_file_local_s2n_set_c_s2n_set_binary_search.1:$(call addone,$(BINARY_SEARCH_BOUND))
UNWINDSET += __CPROVER_file_local_s2n_set_c_s2n_set_binary_search.2:$(call addone,$(BINARY_SEARCH_BOUND))
UNWINDSET += __CPROVER_file_local_s2n_set_c_s2n_set_binary_search.3:$(call addone,$(BINARY_SEARCH_BOUND))
UNWINDSET += __CPROVER_file_local_s2n_set_c_s2n_set_binary_search.4:$(call addone,$(BINARY_SEARCH_BOUND))
UNWINDSET += __CPROVER_file_local_s2n_set_c_s2n_set_binary_search.5:$(call addone,$(BINARY_SEARCH_BOUND))
UNWINDSET += __CPROVER_file_local_s2n_set_c_s2n_set_binary_search.6:$(call addone,$(BINARY_SEARCH_BOUND))
UNWINDSET += __CPROVER_file_local_s2n_set_c_s2n_set_binary_search.7:$(call addone,$(BINARY_SEARCH_BOUND))
UNWINDSET += __CPROVER_file_local_s2n_set_c_s2n_set_binary_search.8:$(call addone,$(BINARY_SEARCH_BOUND))
UNWINDSET += __CPROVER_file_local_s2n_set_c_s2n_set_binary_search.9:$(call addone,$(BINARY_SEARCH_BOUND))
UNWINDSET += __CPROVER_file_local_s2n_set_c_s2n_set_binary_search.10:$(call addone,$(BINARY_SEARCH_BOUND))
UNWINDSET += __CPROVER_file_local_s2n_set_c_s2n_set_binary_search.11:$(call addone,$(BINARY_SEARCH_BOUND))

include ../Makefile.common
