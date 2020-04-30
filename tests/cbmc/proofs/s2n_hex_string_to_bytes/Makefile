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

# Enough to get full coverage with 10 seconds of runtime.
MAX_STRING_LEN = 10
DEFINES += -DMAX_STRING_LEN=$(MAX_STRING_LEN)

CBMCFLAGS +=

DEPENDENCIES += $(HELPERDIR)/source/cbmc_utils.c
DEPENDENCIES += $(HELPERDIR)/source/make_common_datastructures.c
DEPENDENCIES += $(HELPERDIR)/source/proof_allocators.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_blob.c
DEPENDENCIES += $(SRCDIR)/utils/s2n_safety.c
DEPENDENCIES += $(SRCDIR)/error/s2n_errno.c

ENTRY = s2n_hex_string_to_bytes_harness

# We abstract this function because manual inspection demonstrates it is unreachable.
REMOVE_FUNCTION_BODY += --remove-function-body s2n_calculate_stacktrace

UNWINDSET += strlen.0:$(shell echo $$((1 + $(MAX_STRING_LEN))))
UNWINDSET += s2n_hex_string_to_bytes.18:$(shell echo $$((1 + $(MAX_STRING_LEN))))

include ../Makefile.common
