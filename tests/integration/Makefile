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

.PHONY : all
all:
	# Run our resume test
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	python3 s2n_resume_test.py $(S2ND_HOST) $(S2ND_PORT); \
	STATUS=$$?; \
	exit $$STATUS \
    )
	# Run our handshake test
	( \
	DYLD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$DYLD_LIBRARY_PATH" \
	LD_LIBRARY_PATH="../../lib/:../testlib/:$(LIBCRYPTO_ROOT)/lib:$$LD_LIBRARY_PATH" \
	python3 s2n_handshake_test.py $(S2ND_HOST) $(S2ND_PORT); \
	STATUS=$$?; \
	exit $$STATUS \
	)
