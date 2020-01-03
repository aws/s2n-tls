#
# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

SRCS=fips202.c P434.c
OBJS=$(SRCS:.c=.o)

# TODO add when ready for SIKE R2 SAW proofs
#BCS_1=fips202.bc P434.bc
#BCS=$(addprefix $(BITCODE_DIR), $(BCS_1))

.PHONY : all
all: $(OBJS)

# TODO add when ready for SIKE R2 SAW proofs
#.PHONY : bc
#bc: $(BCS)

include ../../s2n.mk
