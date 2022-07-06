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

# Expected runtime is less than 2 minutes.

CBMCFLAGS +=

PROOF_UID = s2n_hash_digest
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(OPENSSL_SOURCE)/bn_override.c
PROOF_SOURCES += $(OPENSSL_SOURCE)/ec_override.c
PROOF_SOURCES += $(OPENSSL_SOURCE)/evp_override.c
PROOF_SOURCES += $(OPENSSL_SOURCE)/md5_override.c
PROOF_SOURCES += $(OPENSSL_SOURCE)/sha_override.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_calculate_stacktrace.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_is_in_fips_mode.c

PROJECT_SOURCES += $(SRCDIR)/crypto/s2n_hash.c
PROJECT_SOURCES += $(SRCDIR)/crypto/s2n_evp.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_result.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_safety.c

# We abstract these functions because manual inspection demonstrates they are unreachable.
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_evp_hash_update
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_low_level_hash_update

UNWINDSET +=

include ../Makefile.common
