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

S2ND_PORT=8888
S2ND_HOST=127.0.0.1

# If the libcrypto that s2n was built with is not specified, assume latest(1.1.1).
# Required to determine the cipher suites to use in integration tests.
ifndef S2N_LIBCRYPTO
	export S2N_LIBCRYPTO="openssl-1.1.1"
endif

HANDSHAKE_TEST_PARAMS:=--libcrypto $(S2N_LIBCRYPTO) $(S2ND_HOST) $(S2ND_PORT)

ifeq ($(S2N_CORKED_IO),true)
	HANDSHAKE_TEST_PARAMS:=--use_corked_io $(HANDSHAKE_TEST_PARAMS)
endif

.PHONY : all
ifdef S2N_NO_PQ
all: tls13 client_endpoints dynamic_record old_s_client s_client s_server gnutls_cli gnutls_serv sslyze
else
all: tls13 client_endpoints dynamic_record old_s_client s_client s_server gnutls_cli gnutls_serv sslyze pq_handshake
endif

tls13:
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	S2N_INTEG_TEST=1 \
	python3 s2n_tls13_handshake_tests.py $(S2ND_HOST) $(S2ND_PORT); \
	)

client_endpoints:
	# Run s2n client endpoint handshake tests
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	S2N_INTEG_TEST=1 \
	python3 s2n_client_endpoint_handshake_test.py; \
	)

dynamic_record:
	# Run dynamic record size tests
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	S2N_INTEG_TEST=1 \
	python3 s2n_dynamic_record_size_test.py --libcrypto $(S2N_LIBCRYPTO) $(S2ND_HOST) $(S2ND_PORT); \
	)

s_client:
	# Run s_client handshake tests
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	S2N_INTEG_TEST=1 \
	python3 s2n_handshake_test_s_client.py $(HANDSHAKE_TEST_PARAMS); \
	)

old_s_client:
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	PATH=$(OPENSSL_0_9_8_INSTALL_DIR)/bin:$$PATH \
	S2N_INTEG_TEST=1 \
	python3 s2n_handshake_test_old_s_client.py $(HANDSHAKE_TEST_PARAMS); \
	)

s_server:
	# Run s_server handshake tests
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	S2N_INTEG_TEST=1 \
	python3 s2n_handshake_test_s_server.py $(HANDSHAKE_TEST_PARAMS); \
	)

gnutls_cli:
	# Run gnutls-cli handshake tests
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLID_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	S2N_INTEG_TEST=1 \
	python3 s2n_handshake_test_gnutls-cli.py --libcrypto $(S2N_LIBCRYPTO) $(S2ND_HOST) $(S2ND_PORT); \
	)

gnutls_serv:
	# Run gnutls-serv handshake tests
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLID_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	S2N_INTEG_TEST=1 \
	python3 s2n_handshake_test_gnutls-serv.py --libcrypto $(S2N_LIBCRYPTO) $(S2ND_HOST) $(S2ND_PORT); \
	)

sslyze:
	# Run SSLyze Tests
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLID_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	S2N_INTEG_TEST=1 \
	python3 s2n_sslyze_test.py --libcrypto $(S2N_LIBCRYPTO) $(S2ND_HOST) $(S2ND_PORT); \
	)

pq_handshake:
	# PQ handshake tests
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLID_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	S2N_INTEG_TEST=1 \
	python3 s2n_pq_handshake_test.py $(S2ND_HOST) $(S2ND_PORT); \
	)

