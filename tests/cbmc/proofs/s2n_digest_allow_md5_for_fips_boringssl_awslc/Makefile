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

# Expected runtime is less than 5 seconds.

DEFINES += -DOPENSSL_IS_BORINGSSL=1
DEFINES += -DOPENSSL_IS_AWSLC=1

CBMCFLAGS +=

PROOF_UID = s2n_digest_allow_md5_for_fips_boringssl_awslc
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(OPENSSL_SOURCE)/evp_override.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_calculate_stacktrace.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_is_in_fips_mode.c

PROJECT_SOURCES += $(SRCDIR)/crypto/s2n_evp.c

UNWINDSET +=

include ../Makefile.common
