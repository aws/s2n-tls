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
.DEFAULT_GOAL := all

include ../../s2n.mk

#WA for GCC 4.8.5 bug.
CFLAGS += -Wno-missing-braces

CFLAGS+=-I../../

SRCS=fp_generic.c P503.c sike_p503_kem.c fips202.c
OBJS=$(SRCS:.c=.o)

.PHONY : all
all: libsike_p503.a

libsike_p503.a: ${OBJS}
	$(AR) cru libsike_p503.a ${OBJS}
	$(RANLIB) libsike_p503.a

.PHONY : clean
clean:
	${MAKE} decruft