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

DIRS=$(wildcard */)
SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

.PHONY : all
all: bin
	$(MAKE) -C tests

include s2n.mk

.PHONY : libs
libs:
	$(MAKE) -C utils
	$(MAKE) -C error
	$(MAKE) -C stuffer
	$(MAKE) -C crypto
	$(MAKE) -C tls
	$(MAKE) -C lib

.PHONY : bin
bin: libs
	$(MAKE) -C bin
	$(MAKE) -C utils
	$(MAKE) -C error
	$(MAKE) -C stuffer
	$(MAKE) -C crypto
	$(MAKE) -C tls
	$(MAKE) -C lib

.PHONY : indent
indent:
	$(MAKE) -C tests indentsource
	$(MAKE) -C stuffer indentsource
	$(MAKE) -C crypto indentsource
	$(MAKE) -C utils indentsource
	$(MAKE) -C error indentsource
	$(MAKE) -C tls indentsource
	$(MAKE) -C bin indentsource

.PHONY : pre_commit_check
pre_commit_check: all indent clean

.PHONY : clean
clean:
	$(MAKE) -C tests clean
	$(MAKE) -C stuffer decruft
	$(MAKE) -C crypto decruft
	$(MAKE) -C utils decruft
	$(MAKE) -C error decruft
	$(MAKE) -C tls decruft
	$(MAKE) -C bin decruft
	$(MAKE) -C lib decruft
