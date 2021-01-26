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

OBJS = $(wildcard ../utils/*.o ../stuffer/*.o ../tls/*.o ../tls/*/*.o ../iana/*.o ../crypto/*.o ../error/*.o ../pq-crypto/*.o ../pq-crypto/bike_r1/*.o ../pq-crypto/bike_r2/*.o ../pq-crypto/bike_r3/*.o ../pq-crypto/sike_r1/*.o ../pq-crypto/sike_r2/*.o ../pq-crypto/kyber_r2/*.o ../pq-crypto/kyber_90s_r2/*.o ../pq-crypto/kyber_r3/*.o ../pq-crypto/sike_r3/*.o)

.PHONY : all
all: libs2n.a libs2n.so libs2n.dylib

include ../s2n.mk

ifeq ($(FUZZ_COVERAGE), true)
	FUZZCOV_FLAGS = -fprofile-instr-generate -fcoverage-mapping
endif

libs2n.a: ${OBJS}
	$(AR) cru libs2n.a ${OBJS}
	$(RANLIB) libs2n.a

libs2n.so: ${OBJS}
	${CC} ${FUZZCOV_FLAGS} -shared -o libs2n.so ${OBJS} ${LIBS} -L${LIBCRYPTO_ROOT}/lib ${CRYPTO_LIBS}

libs2n.dylib: ${OBJS}
	test ! -f /usr/lib/libSystem.dylib || libtool -dynamic  ${LIBS} -L${LIBCRYPTO_ROOT}/lib ${CRYPTO_LIBS} -o libs2n.dylib ${OBJS}
