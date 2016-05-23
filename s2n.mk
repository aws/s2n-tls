#
# Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

ifeq ($(PLATFORM),Darwin)
    LIBS = -lc -lpthread
    CRYPTO_LIBS =
else ifeq ($(PLATFORM),FreeBSD)
    LIBS = -lthr
    CRYPTO_LIBS = -lcrypto
else ifeq ($(PLATFORM),NetBSD)
    LIBS = -lpthread
    CRYPTO_LIBS = -lcrypto
else
    LIBS = -lpthread -ldl -lrt
    CRYPTO_LIBS = -lcrypto
endif

# If this path does not exist it will simply be ignored by 'clang'.
OPENSSL_INC ?= -I/usr/local/opt/openssl/include


SOURCES = $(wildcard *.c *.h)
CRUFT   = $(wildcard *.c~ *.h~ *.c.BAK *.h.BAK *.o *.a *.so *.dylib *.bc)
INDENT  = $(shell (if indent --version 2>&1 | grep GNU > /dev/null; then echo indent ; elif gindent --version 2>&1 | grep GNU > /dev/null; then echo gindent; else echo true ; fi ))

CFLAGS = -pedantic -Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized \
         -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings -Wstack-protector -fPIC \
         -std=c99 -D_POSIX_C_SOURCE=200112L -fstack-protector-all -O2 -I../libcrypto-root/include/ \
         -I../api/ -I../ -Wno-deprecated-declarations -Wno-unknown-pragmas -Wformat-security \
         -D_FORTIFY_SOURCE=2

#../tests/saw/%.c : %.c %.patch
#	cp $< ../tests/saw/$<
#	patch -d ../tests/saw/

CFLAGS_LLVM = -emit-llvm -I../libcrypto-root/include -I../api -I.. $(OPENSSL_INC) -c

$(BITCODE_DIR)%.bc: %.c
	clang $(CFLAGS_LLVM) -o $@ $< 

#	clang $(CFLAGS_LLVM) $(firstword $(filter %$<, $(PATCHED_C)) $<) 

#	TOCOMPILE=$(if $(findstring $<, $(notdir $(PATCHED_C))),  
#ifneq (,$(findstring hmac.c, $(notdir $(PATCHED_C))))
#	echo found one
#	$(MAKE) ../tests/saw/crypto/$<
#else
#	@echo $<
#	@echo $(notdir $(PATCHED_C))
#	@echo $(findstring $<, $(notdir $(PATCHED_C)))
#	@echo ____
#endif
#		clang ($CFLAGS_LLVM) -o ../saw/

INDENTOPTS = -npro -kr -i4 -ts4 -nut -sob -l180 -ss -ncs -cp1

.PHONY : indentsource
indentsource:
	( for source in ${SOURCES} ; do ${INDENT} ${INDENTOPTS} $$source; done )

.PHONY : decruft
decruft:
	$(RM) -- ${CRUFT}
