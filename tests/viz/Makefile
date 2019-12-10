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

.PHONY : all
all: build_viz

include ../../s2n.mk

LDFLAGS += -L../../lib ${LIBS} -ls2n -L$(LIBCRYPTO_ROOT)/lib ${CRYPTO_LIBS}

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	CFLAGS := -Wl,--no-as-needed $(CFLAGS)
endif

# Run state machine graph generation
# with `make STATE_MACHINE_GRAPHS=1`.
# graphviz is required.

build_viz::
	${CC} ${CFLAGS} -o s2n_state_machine_viz s2n_state_machine_viz.c ${LDFLAGS}
	@[ "${STATE_MACHINE_GRAPHS}" ] && \
	DYLD_LIBRARY_PATH="../../lib:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	./s2n_state_machine_viz || true

.PHONY : clean
clean: decruft
	rm -f s2n_state_machine_viz
