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

# Expected runtime is less than 10 seconds.

MAX_ARRAY_LEN = 10
DEFINES += -DMAX_ARRAY_LEN=$(MAX_ARRAY_LEN)

MAX_ARRAY_ELEMENT_SIZE = 10
DEFINES += -DMAX_ARRAY_ELEMENT_SIZE=$(MAX_ARRAY_ELEMENT_SIZE)

CBMCFLAGS +=

HARNESS_ENTRY = s2n_set_remove_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_utils.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(PROOF_STUB)/memmove_havoc.c
PROOF_SOURCES += $(PROOF_STUB)/mlock.c
PROOF_SOURCES += $(PROOF_STUB)/munlock.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_calculate_stacktrace.c
PROOF_SOURCES += $(PROOF_STUB)/sysconf.c

PROJECT_SOURCES += $(SRCDIR)/utils/s2n_array.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_blob.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_result.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_safety.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_set.c

UNWINDSET +=

include ../Makefile.common
