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

test_key_update:
	$(call run_tox,$@.py)
test_client_authentication:
	$(call run_tox,$@.py)
test_dynamic_record_sizes:
	$(call run_tox,$@.py)
test_early_data:
	$(call run_tox,$@.py)
test_happy_path:
	$(call run_tox,$@.py)
test_session_resumption:
	$(call run_tox,$@.py)
test_sni_match:
	$(call run_tox,$@.py)
test_well_known_endpoints:
	$(call run_tox,$@.py)
test_fragmentation:
	$(call run_tox,$@.py)
test_hello_retry_requests:
	$(call run_tox,$@.py)
test_pq_handshake:
	$(call run_tox,$@.py)
test_signature_algorithms:
	$(call run_tox,$@.py)
test_version_negotiation:
	$(call run_tox,$@.py)
test_single:
	$(call run_tox,$(TOX_TEST_NAME))

.PHONY : test_early_data test_client_authentication test_dynamic_record_sizes test_key_update test_happy_path test_session_resumption test_sni_match test_well_known_endpoints test_fragmentation test_hello_retry_requests test_pq_handshake test_signature_algorithms test_version_negotiation
all: test_early_data test_client_authentication test_dynamic_record_sizes test_key_update test_happy_path test_session_resumption test_sni_match test_well_known_endpoints test_fragmentation test_hello_retry_requests test_pq_handshake test_signature_algorithms test_version_negotiation

