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

# Expected runtime is 60 seconds.

CBMCFLAGS +=
MAX_ARR_LEN = 10
DEFINES += -DMAX_ARR_LEN=$(MAX_ARR_LEN)

DEPENDENCIES += $(HELPERDIR)/source/cbmc_utils.c
DEPENDENCIES += $(HELPERDIR)/source/make_common_datastructures.c
DEPENDENCIES += $(HELPERDIR)/source/proof_allocators.c
DEPENDENCIES += $(SRCDIR)/stuffer/s2n_stuffer.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_blob.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_ensure.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_mem.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_safety.c

ENTRY = s2n_safety_constant_time_equals_harness

# We abstract these functions because manual inspection demonstrates they are unreachable.
REMOVE_FUNCTION_BODY += --remove-function-body s2n_blob_slice
REMOVE_FUNCTION_BODY += --remove-function-body s2n_mem_cleanup_impl
REMOVE_FUNCTION_BODY += --remove-function-body s2n_stuffer_wipe_n

UNWINDSET += s2n_constant_time_equals.0:$(call addone,$(MAX_ARR_LEN))

include ../Makefile.common
