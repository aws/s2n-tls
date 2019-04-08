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

INTERNAL_LIBS += sike/libsike_p503.a

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

.PHONY : all
all: libs2n_pq_crypto.so

libs2n_pq_crypto.so: ${OBJS}
	$(MAKE) -C sike
	${CC} -shared -o libs2n_pq_crypto.so ${OBJS} -Wl,--whole-archive ${INTERNAL_LIBS} -Wl,--no-whole-archive -L../../ ${CFLAGS} ${LDFLAGS} -lm

include ../s2n.mk

.PHONY : clean
clean:
	${MAKE} -C sike clean
	${MAKE} decruft