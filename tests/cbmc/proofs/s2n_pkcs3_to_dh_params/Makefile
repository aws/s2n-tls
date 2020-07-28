# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

# Expected runtime is 10 seconds.
MAX_BLOB_SIZE = 10
DEFINES += -DMAX_BLOB_SIZE=$(MAX_BLOB_SIZE)

CHECKFLAGS +=

HARNESS_ENTRY = s2n_pkcs3_to_dh_params_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_utils.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_SOURCE)/openssl/dh_overrides.c
PROOF_SOURCES += $(PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(PROOF_STUB)/sysconf.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_calculate_stacktrace.c

PROJECT_SOURCES += $(SRCDIR)/utils/s2n_blob.c
PROJECT_SOURCES += $(SRCDIR)/crypto/s2n_dhe.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_ensure.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_mem.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_safety.c
PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer.c

UNWINDSET +=

# These functions are unnecessary for the proof, as the first is an OpenSSL
# function and the second interacts with OpenSSL functions. Since OpenSSL
# is not emulated by CBMC, these do not fall within the scope of the proof.
REMOVE_FUNCTION_BODY += DECLARE_ASN1_ITEM
REMOVE_FUNCTION_BODY += s2n_check_p_g_dh_params

include ../Makefile.common
