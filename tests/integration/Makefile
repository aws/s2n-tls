#
# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

S2ND_PORT=8888
S2ND_HOST=127.0.0.1

# If the libcrypto that s2n was built with is not specified, assume latest(1.1.0).
# Required to determine the cipher suites to use in integration tests.
ifndef S2N_LIBCRYPTO
	export S2N_LIBCRYPTO="openssl-1.1.0"
endif

.PHONY : all
all:
	# Run s2n client endpoint handshake tests
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	python3 s2n_client_endpoint_handshake_test.py $(S2ND_HOST) $(S2ND_PORT); \
	)
	# Run s_client handshake tests
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	python3 s2n_handshake_test_s_client.py --libcrypto $(S2N_LIBCRYPTO) $(S2ND_HOST) $(S2ND_PORT); \
	)
	# Run s_server handshake tests
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	python3 s2n_handshake_test_s_server.py --libcrypto $(S2N_LIBCRYPTO) $(S2ND_HOST) $(S2ND_PORT); \
	)
	# Run gnutls handshake tests
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLID_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	python3 s2n_handshake_test_gnutls.py --libcrypto $(S2N_LIBCRYPTO) $(S2ND_HOST) $(S2ND_PORT); \
	)
	# Run SSLyze Tests
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLID_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	python3 s2n_sslyze_test.py --libcrypto $(S2N_LIBCRYPTO) $(S2ND_HOST) $(S2ND_PORT); \
	)
