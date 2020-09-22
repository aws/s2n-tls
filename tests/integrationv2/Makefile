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

# If the libcrypto that s2n was built with is not specified, assume latest(1.1.1).
# Required to determine the cipher suites to use in integration tests.
ifndef S2N_LIBCRYPTO
	export S2N_LIBCRYPTO="openssl-1.1.1"
endif

HANDSHAKE_TEST_PARAMS:=--libcrypto $(S2N_LIBCRYPTO) $(S2ND_HOST) $(S2ND_PORT)

ifeq ($(S2N_CORKED_IO),true)
	HANDSHAKE_TEST_PARAMS:=--use_corked_io $(HANDSHAKE_TEST_PARAMS)
endif


define run_tox
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	S2N_INTEG_TEST=1 \
	PATH="../../bin":$(LIBCRYPTO_ROOT)/bin:$(PATH) \
	TOX_TEST_NAME=$(1) \
	tox \
	)
endef

test_key_update.py:
	$(call run_tox,$@)
test_client_authentication.py:
	$(call run_tox,$@)
test_dynamic_record_sizes.py:
	$(call run_tox,$@)
test_happy_path.py:
	$(call run_tox,$@)
test_session_resumption.py:
	$(call run_tox,$@)
test_sni_match.py:
	$(call run_tox,$@)
test_well_known_endpoints.py:
	$(call run_tox,$@)
test_compatibility_with_oqs_openssl.py:
	$(call run_tox,$@)
test_fragmentation.py:
	$(call run_tox,$@)
test_hello_retry_requests.py:
	$(call run_tox,$@)
test_pq_handshake.py:
	$(call run_tox,$@)
test_signature_algorithms.py:
	$(call run_tox,$@)
test_version_negotiation.py:
	$(call run_tox,$@)

.PHONY : test_client_authentication.py test_dynamic_record_sizes.py test_happy_path.py test_key_update.py test_session_resumption.py test_sni_match.py test_well_known_endpoints.py test_compatibility_with_oqs_openssl.py test_fragmentation.py test_hello_retry_requests.py test_pq_handshake.py test_signature_algorithms.py test_version_negotiation.py all

all: test_client_authentication.py test_dynamic_record_sizes.py test_happy_path.py test_key_update.py test_session_resumption.py test_sni_match.py test_well_known_endpoints.py test_compatibility_with_oqs_openssl.py test_fragmentation.py test_hello_retry_requests.py test_pq_handshake.py test_signature_algorithms.py test_version_negotiation.py

