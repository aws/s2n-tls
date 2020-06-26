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

ABSTRACTIONS += $(HELPERDIR)/stubs/s2n_calculate_stacktrace.c

DEPENDENCIES += $(SRCDIR)/utils/s2n_mem.c

ENTRY = s2n_mem_init_harness

REMOVE_FUNCTION_BODY += --remove-function-body s2n_mem_cleanup_impl

include ../Makefile.common
