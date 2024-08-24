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


# Use the default set of CBMC flags
CHECKFLAGS +=

PROOF_UID = s2n_constant_time_equals_total
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

# Uncomment and complete this if this function calls other functions that have pre- and post-conditions
USE_FUNCTION_CONTRACTS = s2n_constant_time_equals_partial

CHECK_FUNCTION_CONTRACTS=$(PROOF_UID)
FUNCTION_NAME = $(PROOF_UID)
APPLY_LOOP_CONTRACTS=on
USE_DYNAMIC_FRAMES=1

# Use SMT back-end and disable default SAT backend
EXTERNAL_SAT_SOLVER=
CBMCFLAGS=--bitwuzla

# Tell CBMC not to name-mangle and export file-local symbols
EXPORT_FILE_LOCAL_SYMBOLS=

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)

PROJECT_SOURCES += $(SRCDIR)/utils/s2n_safety.c

# Set Verbose=on to see what litani is actually running
VERBOSE=on

include ../Makefile.common
