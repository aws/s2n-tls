# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

# Enough to get full coverage with 7 minutes of runtime.
MAX_BLOB_SIZE = 10
DEFINES += -DMAX_BLOB_SIZE=$(MAX_BLOB_SIZE)

CHECKFLAGS +=

HARNESS_ENTRY = s2n_stuffer_private_key_from_pem_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_utils.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_calculate_stacktrace.c
PROOF_SOURCES += $(PROOF_STUB)/sysconf.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_stuffer_read_expected_str.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_stuffer_skip_expected_char.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_stuffer_skip_to_char.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_stuffer_skip_whitespace.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_stuffer_read_base64.c
PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer.c
PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer_pem.c
PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer_text.c
PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer_base64.c
PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer_network_order.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_blob.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_ensure.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_mem.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_safety.c

# We abstract this function because manual inspection demonstrates it is unreachable.
REMOVE_FUNCTION_BODY += s2n_stuffer_resize
REMOVE_FUNCTION_BODY += s2n_stuffer_rewrite
REMOVE_FUNCTION_BODY += s2n_add_overflow

UNWINDSET += strlen.0:5 # size of S2N_PEM_PKCS1_RSA_PRIVATE_KEY
UNWINDSET += strncmp.0:5 # size of S2N_PEM_END_TOKEN
UNWINDSET += __CPROVER_file_local_s2n_stuffer_pem_c_s2n_stuffer_pem_read_contents.11:$(call addone,$(MAX_BLOB_SIZE))
UNWINDSET += s2n_stuffer_skip_to_char.3:$(call addone,$(MAX_BLOB_SIZE))

include ../Makefile.common
