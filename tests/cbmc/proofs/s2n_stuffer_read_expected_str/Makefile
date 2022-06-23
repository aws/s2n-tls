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

# Enough to get full coverage with 1 minute of runtime.
MAX_STRING_LEN = 10
DEFINES += -DMAX_STRING_LEN=$(MAX_STRING_LEN)

PROOF_UID = s2n_stuffer_read_expected_str
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_utils.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_calculate_stacktrace.c

PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer.c
PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer_network_order.c
PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer_text.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_blob.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_ensure.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_result.c

UNWINDSET += strlen.0:$(call addone,$(MAX_STRING_LEN))
UNWINDSET += memcmp.0:$(call addone,$(MAX_STRING_LEN))

include ../Makefile.common
