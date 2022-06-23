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

# Expected runtime is less than 5 minutes.

CBMCFLAGS +=

PROOF_UID = s2n_hmac_free
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(OPENSSL_SOURCE)/bn_override.c
PROOF_SOURCES += $(OPENSSL_SOURCE)/ec_override.c
PROOF_SOURCES += $(OPENSSL_SOURCE)/evp_override.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_is_in_fips_mode.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)

PROJECT_SOURCES += $(SRCDIR)/crypto/s2n_hash.c
PROJECT_SOURCES += $(SRCDIR)/crypto/s2n_hmac.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_result.c

# We abstract these functions because manual inspection demonstrates they are unreachable.
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_evp_hash_init
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_evp_hash_new
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_evp_hash_reset
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_low_level_hash_init
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_low_level_hash_new
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_low_level_hash_reset
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_hash_allow_md5_for_fips
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_evp_hash_allow_md5_for_fips

UNWINDSET +=

include ../Makefile.common
