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

# Expected runtime is 6 seconds.
MAX_ARR_LEN = 10
DEFINES += -DMAX_ARR_LEN=$(MAX_ARR_LEN)

CBMCFLAGS +=

PROOF_UID = s2n_hmac_digest_verify
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)

PROJECT_SOURCES += $(SRCDIR)/crypto/s2n_hmac.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_safety.c

UNWINDSET += s2n_constant_time_equals.0:$(call addone,$(MAX_ARR_LEN))

include ../Makefile.common
