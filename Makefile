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

all: bin
	make -C tests

include s2n.mk

libs:
	make -C utils
	make -C error
	make -C stuffer
	make -C crypto
	make -C tls
	make -C lib

bin: libs
	make -C bin

indent:
	make -C tests indentsource
	make -C stuffer indentsource
	make -C crypto indentsource
	make -C utils indentsource
	make -C error indentsource
	make -C tls indentsource
	make -C bin indentsource

pre_commit_check: all indent clean

clean:
	make -C tests clean
	make -C stuffer decruft
	make -C crypto decruft
	make -C utils decruft
	make -C error decruft
	make -C tls decruft
	make -C bin decruft
	make -C lib decruft
