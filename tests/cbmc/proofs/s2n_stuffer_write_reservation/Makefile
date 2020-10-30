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

# Expected runtime is 29 minutes.
DEFINES += -DMADV_DONTDUMP=1

# This the the maximum number of iterations to unroll
# the loop in s2n_stuffer_write_network_order
MAX_WRITE_NETWORK_ORDER = 9

CBMCFLAGS +=

HARNESS_ENTRY = s2n_stuffer_write_reservation_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_utils.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(PROOF_STUB)/madvise.c
PROOF_SOURCES += $(PROOF_STUB)/mlock.c
PROOF_SOURCES += $(PROOF_STUB)/munlock.c
PROOF_SOURCES += $(PROOF_STUB)/posix_memalign_override.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_calculate_stacktrace.c
PROOF_SOURCES += $(PROOF_STUB)/sysconf.c

PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer.c
PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer_network_order.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_blob.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_ensure.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_mem.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_safety.c

# We abstract these functions because manual inspection demonstrates they are unreachable.
REMOVE_FUNCTION_BODY += s2n_blob_slice
REMOVE_FUNCTION_BODY += s2n_stuffer_wipe
REMOVE_FUNCTION_BODY += s2n_stuffer_wipe_n
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_mem_c_s2n_mem_cleanup_impl

UNWINDSET += s2n_stuffer_write_network_order.0:$(MAX_WRITE_NETWORK_ORDER)
UNWINDSET += s2n_stuffer_write_network_order.1:$(MAX_WRITE_NETWORK_ORDER)
UNWINDSET += s2n_stuffer_write_network_order.2:$(MAX_WRITE_NETWORK_ORDER)
UNWINDSET += s2n_stuffer_write_network_order.3:$(MAX_WRITE_NETWORK_ORDER)
UNWINDSET += s2n_stuffer_write_network_order.4:$(MAX_WRITE_NETWORK_ORDER)
UNWINDSET += s2n_stuffer_write_network_order.5:$(MAX_WRITE_NETWORK_ORDER)
UNWINDSET += s2n_stuffer_write_network_order.6:$(MAX_WRITE_NETWORK_ORDER)
UNWINDSET += s2n_stuffer_write_network_order.7:$(MAX_WRITE_NETWORK_ORDER)

include ../Makefile.common
