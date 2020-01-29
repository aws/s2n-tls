#####################
# Copyright 2019 Galois, Inc. All Rights Reserved
#
#  Authors:
#	Joey Dodds : jdodds@galois.com
#	
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
########################

SCRIPTS = $(wildcard *.saw)
LOGS=$(patsubst %.saw,tmp/%.log,${SCRIPTS})
SHELL:=/bin/bash

all : ${LOGS}

force_all : clean_bike_logs all

create_dirs :
	@mkdir -p tmp

clean_bike_logs :
	${RM} -r tmp/*.log

tmp/%.log: %.saw create_dirs 
	@echo "Running formal verification with ${YICES_VERSION}"
	@echo saw $<
	@set -o pipefail; \
	saw --verbose=warning $< | tee $@
