#
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

MAX_BLOB_SIZE = 20
DEFINES += -DMAX_BLOB_SIZE=$(MAX_BLOB_SIZE)

CBMCFLAGS +=

PROOF_UID = s2n_stuffer_shift
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_utils.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_STUB)/memmove_simple.c

PROJECT_SOURCES += $(SRCDIR)/error/s2n_errno.c
PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_blob.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_ensure.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_mem.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_result.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_safety.c

UNWINDSET += memmove_impl.0:$(call addone,$(MAX_BLOB_SIZE))
UNWINDSET += memmove_impl.1:$(call addone,$(MAX_BLOB_SIZE))

include ../Makefile.common
