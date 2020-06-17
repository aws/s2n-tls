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

# Enough to get full coverage with 40 seconds of runtime.
BLOB_SIZE = 10
DEFINES += -DBLOB_SIZE=$(BLOB_SIZE)

CBMCFLAGS +=

DEPENDENCIES += $(HELPERDIR)/source/cbmc_utils.c
DEPENDENCIES += $(HELPERDIR)/source/make_common_datastructures.c
DEPENDENCIES += $(HELPERDIR)/source/proof_allocators.c
DEPENDENCIES += $(SRCDIR)/stuffer/s2n_stuffer.c
DEPENDENCIES += $(SRCDIR)/stuffer/s2n_stuffer_text.c
DEPENDENCIES += $(SRCDIR)/stuffer/s2n_stuffer_network_order.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_blob.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_ensure.c

ENTRY = s2n_stuffer_skip_to_char_harness

UNWINDSET += s2n_stuffer_skip_to_char.5:$(call addone,$(BLOB_SIZE))

include ../Makefile.common
