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

# Enough to get full coverage with 30 seconds of runtime.
MAX_BLOB_SIZE = 2
DEFINES += -DMAX_BLOB_SIZE=$(MAX_BLOB_SIZE)

ABSTRACTIONS += $(HELPERDIR)/stubs/read.c
ABSTRACTIONS += $(HELPERDIR)/stubs/s2n_calculate_stacktrace.c

CBMCFLAGS +=

DEPENDENCIES += $(HELPERDIR)/source/cbmc_utils.c
DEPENDENCIES += $(HELPERDIR)/source/make_common_datastructures.c
DEPENDENCIES += $(HELPERDIR)/source/proof_allocators.c
DEPENDENCIES += $(SRCDIR)/error/s2n_errno.c
DEPENDENCIES += $(SRCDIR)/stuffer/s2n_stuffer.c
DEPENDENCIES += $(SRCDIR)/stuffer/s2n_stuffer_file.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_blob.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_ensure.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_mem.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_safety.c

ENTRY = s2n_stuffer_recv_from_fd_harness

# We abstract these functions because manual inspection demonstrates they are unreachable.
REMOVE_FUNCTION_BODY += --remove-function-body s2n_blob_slice
REMOVE_FUNCTION_BODY += --remove-function-body s2n_stuffer_wipe_n

UNWINDSET += s2n_stuffer_recv_from_fd.7:$(call addone,$(MAX_BLOB_SIZE))

include ../Makefile.common
