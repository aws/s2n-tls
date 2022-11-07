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
#
# Expected runtime is around 5 seconds.

CHECKFLAGS += --memory-leak-check

PROOF_UID = s2n_free_or_wipe
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_utils.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_STUB)/munlock.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_calculate_stacktrace.c
PROOF_SOURCES += $(PROOF_STUB)/sysconf.c

PROJECT_SOURCES += $(SRCDIR)/utils/s2n_blob.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_mem.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_result.c

REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_mem_c_s2n_mem_cleanup_impl

UNWINDSET +=

include ../Makefile.common
