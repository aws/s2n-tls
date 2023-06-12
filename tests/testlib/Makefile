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

EXAMPLES_DIR=../../docs/examples
EXAMPLES=$(wildcard $(EXAMPLES_DIR)/*.c)

SRCS=$(wildcard *.c)
# Consider the examples part of the testlib.
# It would be more correct to build the examples separately, but requires more setup
# and we've deprecated our Makefiles anyway.
SRCS += $(EXAMPLES)
OBJS=$(SRCS:.c=.o)
CRYPTO_LDFLAGS = -L$(LIBCRYPTO_ROOT)/lib

.PHONY : all
all: libtests2n.a libtests2n.so libtests2n.dylib

include ../../s2n.mk

CFLAGS += -I../
LIBS += ../../lib/libs2n.a
LDFLAGS += ${CRYPTO_LDFLAGS} ${LIBS} ${CRYPTO_LIBS} -lm -ldl -lrt -pthread
CRUFT += $(filter-out %.c, $(wildcard $(EXAMPLES_DIR)/*))

libtests2n.so: ${OBJS}
	${CC} ${CFLAGS} -shared ${LDFLAGS} -o libtests2n.so ${OBJS}

libtests2n.dylib: ${OBJS}
	test ! -f /usr/lib/libSystem.dylib || libtool ${LDFLAGS} -dynamic -o libtests2n.dylib ${OBJS}

libtests2n.a: ${OBJS}
	$(AR) cru libtests2n.a ${OBJS}
	$(RANLIB) libtests2n.a
