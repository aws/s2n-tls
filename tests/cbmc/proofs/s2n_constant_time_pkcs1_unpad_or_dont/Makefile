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

# Expected runtime is 10 seconds.

MAX_ARR_LEN = 10

# Bound for copy or dont must be at at least three higher than the maximum array length
BOUND = $(MAX_ARR_LEN) + 3

DEFINES += -DMAX_ARR_LEN=$(MAX_ARR_LEN)
DEFINES += -DBOUND=$(BOUND)


CBMCFLAGS +=

HARNESS_ENTRY = s2n_constant_time_pkcs1_unpad_or_dont_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/proof_allocators.c

PROJECT_SOURCES += $(SRCDIR)/utils/s2n_safety.c

UNWINDSET += s2n_constant_time_copy_or_dont.0:$(call addone,$(BOUND))
UNWINDSET += s2n_constant_time_pkcs1_unpad_or_dont.0:$(call addone,$(MAX_ARR_LEN))
UNWINDSET += s2n_constant_time_pkcs1_unpad_or_dont_harness.0:$(call addone,$(MAX_ARR_LEN))

include ../Makefile.common
