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
MAX_BLOB_SIZE = 10
DEFINES += -DMAX_BLOB_SIZE=$(MAX_BLOB_SIZE)

CBMCFLAGS +=

PROOF_UID = s2n_blob_char_to_lower
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_utils.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c

PROJECT_SOURCES += $(SRCDIR)/utils/s2n_blob.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_safety.c
PROJECT_SOURCES += $(SRCDIR)/error/s2n_errno.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_result.c

# We abstract this function because manual inspection demonstrates it is unreachable.
REMOVE_FUNCTION_BODY += s2n_calculate_stacktrace

UNWINDSET += s2n_blob_char_to_lower.1:$(call addone,$(MAX_BLOB_SIZE))

include ../Makefile.common
