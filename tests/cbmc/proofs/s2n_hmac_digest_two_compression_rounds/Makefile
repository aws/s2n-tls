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

PROOF_UID = s2n_hmac_digest_two_compression_rounds
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_calculate_stacktrace.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_is_in_fips_mode.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_hash_copy.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_hash_digest.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_hash_reset.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_hash_update.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)

PROJECT_SOURCES += $(SRCDIR)/crypto/s2n_hash.c
PROJECT_SOURCES += $(SRCDIR)/crypto/s2n_hmac.c

UNWINDSET +=

include ../Makefile.common
