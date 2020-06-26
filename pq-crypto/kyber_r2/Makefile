#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

SRCS=fips202_kyber_r2.c cbd.c reduce.c ntt.c poly.c polyvec.c verify.c symmetric-fips202.c indcpa.c kyber_r2_kem.c
OBJS=$(SRCS:.c=.o)

.PHONY : all
all: $(OBJS)

include ../../s2n.mk
