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

# Enough to get full coverage with 10 seconds of runtime.
MAX_BLOB_SIZE = 5
DEFINES += -DMAX_BLOB_SIZE=$(MAX_BLOB_SIZE)

MAX_STRING_LEN = 5
DEFINES += -DMAX_STRING_LEN=$(MAX_STRING_LEN)

CBMCFLAGS +=

PROOF_UID = s2n_stuffer_skip_read_until
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_utils.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_STUB)/posix_memalign_override.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_calculate_stacktrace.c

PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer.c
PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer_network_order.c
PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer_text.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_blob.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_ensure.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_result.c

UNWINDSET += s2n_stuffer_skip_read_until.10:$(call addone,$(MAX_BLOB_SIZE))
UNWINDSET += s2n_stuffer_skip_to_char.1:$(call addone,$(MAX_BLOB_SIZE))
UNWINDSET += strlen.0:$(call addone,$(MAX_STRING_LEN))
UNWINDSET += strncmp.0:$(call addone,$(MAX_STRING_LEN))

include ../Makefile.common
