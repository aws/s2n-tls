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

#Make sure these path variables have something.
ifeq ($(OPENSSL_0_9_8_INSTALL_DIR),)
	OPENSSL_0_9_8_INSTALL_DIR:=${CURDIR}/../../test-deps/openssl-0.9.8
endif
ifeq ($(OPENSSL_1_1_1_INSTALL_DIR),)
	OPENSSL_1_1_1_INSTALL_DIR:=${CURDIR}/../../test-deps/openssl-1.1.1
endif
ifeq ($(GNUTLS_INSTALL_DIR),)
	GNUTLS_INSTALL_DIR:=${CURDIR}/../../test-deps/gnutls
endif
ifeq ($(OQS_OPENSSL_1_1_1_INSTALL_DIR),)
	OQS_OPENSSL_1_1_1_INSTALL_DIR:=${CURDIR}/../../test-deps/oqs_openssl-1.1.1
endif

TESTS = tls13 client_endpoints dynamic_record old_s_client s_client s_server pq_handshake

ifndef S2N_NO_PQ
	TESTS += pq_handshake
endif

#TODO: these tests are currenly failing on AL2
ifneq ($(DISTRO), "amazon linux")
	TETS+= gnutls_cli gnutls_serv sslyze
endif

.PHONY : all
all: $(TESTS)

# Undefined arguments are fine.
# NOTE: Pathing is how we're getting a specific openssl version.
define run_test
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	PATH=$(OPENSSL_1_1_1_INSTALL_DIR)/bin:$$PATH \
	S2N_INTEG_TEST=1 \
	python3 $(1).py $(2) $(3) $(4) $(5); \
	)
endef

# Install openssl 0.9.8 if it's missing
$(OPENSSL_0_9_8_INSTALL_DIR)/bin/openssl:
	@{ set -e; \
	 cd ../..; \
	 export BUILDTMP=$$(mktemp -d); \
	 echo "Installing openssl to $(OPENSSL_0_9_8_INSTALL_DIR)"; \
	 codebuild/bin/install_openssl_0_9_8.sh "$$BUILDTMP" $(OPENSSL_0_9_8_INSTALL_DIR) $(OS_NAME); \
	}

# Install openssl 1.1.1 if it's missing
$(OPENSSL_1_1_1_INSTALL_DIR)/bin/openssl:
	@{ set -e; \
	 cd ../..; \
	 export BUILDTMP=$$(mktemp -d); \
	 echo "Installing openssl to $(OPENSSL_1_1_1_INSTALL_DIR)"; \
	 codebuild/bin/install_openssl_1_1_1.sh "$$BUILDTMP" $(OPENSSL_1_1_1_INSTALL_DIR) $(OS_NAME); \
	}

# Install gnutls if it's missing
$(GNUTLS_INSTALL_DIR)/gnutls-serv:
	@{ set -e; \
	 cd ../..; \
	 export BUILDTMP=$$(mktemp -d); \
	 echo "Installing gnutls to $(GNUTLS_INSTALL_DIR)"; \
	 echo "codebuild/bin/install_gnutls.sh "$$BUILDTMP" $(GNUTLS_INSTALL_DIR)" ;\
	 codebuild/bin/install_gnutls.sh "$$BUILDTMP" $(GNUTLS_INSTALL_DIR) ;\
	}

tls13: clean $(OPENSSL_1_1_1_INSTALL_DIR)/bin/openssl clean
	$(call run_test,s2n_tls13_handshake_tests,$(S2ND_HOST),$(S2ND_PORT))

client_endpoints: $(OPENSSL_1_1_1_INSTALL_DIR)/bin/openssl clean
	# Run s2n client endpoint handshake tests
	$(call run_test,s2n_client_endpoint_handshake_test)

dynamic_record: $(OPENSSL_1_1_1_INSTALL_DIR)/bin/openssl clean
	# Run dynamic record size tests
	$(call run_test,s2n_dynamic_record_size_test,--libcrypto,$(S2N_LIBCRYPTO),$(S2ND_HOST),$(S2ND_PORT))

s_client: $(OPENSSL_1_1_1_INSTALL_DIR)/bin/openssl clean
	# Run s_client handshake tests
	$(call run_test,s2n_handshake_test_s_client,$(HANDSHAKE_TEST_PARAMS))

# Test with old openssl
# NOTE: Pathing is how we're getting a specific openssl version.
old_s_client: $(OPENSSL_0_9_8_INSTALL_DIR)/bin/openssl clean
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	PATH=$(OPENSSL_0_9_8_INSTALL_DIR)/bin:$$PATH \
	S2N_INTEG_TEST=1 \
	python3 s2n_handshake_test_old_s_client.py $(HANDSHAKE_TEST_PARAMS); \
	)

s_server: $(OPENSSL_1_1_1_INSTALL_DIR)/bin/openssl clean
	# Run s_server handshake tests
	$(call run_test,s2n_handshake_test_s_server,$(HANDSHAKE_TEST_PARAMS))

gnutls_cli: $(GNUTLS_INSTALL_DIR)/gnutls-serv
	# Run gnutls-cli handshake tests
	$(call run_test,s2n_handshake_test_gnutls-cli,--libcrypto,$(S2N_LIBCRYPTO),$(S2ND_HOST),$(S2ND_PORT))

gnutls_serv: $(GNUTLS_INSTALL_DIR)/gnutls-serv
	# Run gnutls-serv handshake tests
	$(call run_test,s2n_handshake_test_gnutls-serv,--libcrypto,$(S2N_LIBCRYPTO),$(S2ND_HOST),$(S2ND_PORT))

sslyze:
	# Run SSLyze Tests
	$(call run_test,s2n_sslyze_test,--libcrypto,$(S2N_LIBCRYPTO),$(S2ND_HOST),$(S2ND_PORT))

pq_handshake:
	# PQ handshake tests
	$(call run_test,s2n_pq_handshake_test,$(S2ND_HOST),$(S2ND_PORT))

.PHONEY: clean
clean:
	@pkill s2nd || true
	@pkill openssl || true
