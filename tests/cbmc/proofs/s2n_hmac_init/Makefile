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

CBMCFLAGS +=

PROOF_UID = s2n_hmac_init
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(OPENSSL_SOURCE)/evp_override.c
PROOF_SOURCES += $(OPENSSL_SOURCE)/md5_override.c
PROOF_SOURCES += $(OPENSSL_SOURCE)/sha_override.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_calculate_stacktrace.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_is_in_fips_mode.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)

PROJECT_SOURCES += $(SRCDIR)/crypto/s2n_hash.c
PROJECT_SOURCES += $(SRCDIR)/crypto/s2n_hmac.c
PROJECT_SOURCES += $(SRCDIR)/crypto/s2n_evp.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_ensure.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_result.c

# We abstract these functions because manual inspection demonstrates they are unreachable.
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_low_level_hash_new
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_low_level_hash_reset
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_low_level_hash_free
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_low_level_hash_digest
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_low_level_hash_update
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_evp_hash_free
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_evp_hash_new
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_evp_hash_reset
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_evp_hash_digest
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_evp_hash_update
REMOVE_FUNCTION_BODY += __CPROVER_file_local_s2n_hash_c_s2n_evp_hash_allow_md5_for_fips
REMOVE_FUNCTION_BODY += s2n_hash_allow_md5_for_fips

# The upper bound limit for these loops is me maximum possible value for xor_pad_size field
# in struct s2n_hmac_state (128) plus one. See definition for struct s2n_hmac_state
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_sslv3_mac_init.0:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_sslv3_mac_init.1:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_sslv3_mac_init.2:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_sslv3_mac_init.3:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_sslv3_mac_init.4:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_sslv3_mac_init.5:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_tls_hmac_init.0:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_tls_hmac_init.1:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_tls_hmac_init.2:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_tls_hmac_init.3:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_tls_hmac_init.4:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_tls_hmac_init.5:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_tls_hmac_init.6:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_tls_hmac_init.8:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_tls_hmac_init.9:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_tls_hmac_init.10:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_tls_hmac_init.11:129
UNWINDSET += __CPROVER_file_local_s2n_hmac_c_s2n_tls_hmac_init.12:129

include ../Makefile.common
