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

# Expected runtime is 30 seconds.
MAX_LENGTH = 3
DEFINES += -DMAX_LENGTH=$(MAX_LENGTH)

CBMCFLAGS +=

DEPENDENCIES += $(HELPERDIR)/source/cbmc_utils.c
DEPENDENCIES += $(HELPERDIR)/source/make_common_datastructures.c
DEPENDENCIES += $(HELPERDIR)/source/proof_allocators.c
DEPENDENCIES += $(SRCDIR)/stuffer/s2n_stuffer.c
DEPENDENCIES += $(SRCDIR)/stuffer/s2n_stuffer_network_order.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_blob.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_ensure.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_mem.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_safety.c

ENTRY = s2n_stuffer_write_network_order_harness

# We abstract these functions because manual inspection demonstrates they are unreachable.
REMOVE_FUNCTION_BODY += --remove-function-body s2n_blob_slice
REMOVE_FUNCTION_BODY += --remove-function-body s2n_stuffer_wipe_n

UNWINDSET += s2n_stuffer_write_network_order.1:$(shell echo $$((1 + $(MAX_LENGTH))))

include ../Makefile.common
