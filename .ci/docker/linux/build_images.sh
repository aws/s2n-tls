#!/bin/bash -e
# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

docker build -m6g -t s2n_ubuntu:19.04_base -f docker_images/ubuntu-19.04_base .
docker build -m6g -t s2n_ubuntu:19.04_openssl-1.1.1 -f docker_images/ubuntu-19.04_openssl-1.1.1_base .
docker build -m6g -t ubuntu-19.04:gcc-9x_openssl-1.1.1 -f docker_images/ubuntu-19.04_gcc-9x_openssl-1.1.1 .
docker build -m6g -t ubuntu-19.04:clang-8x_openssl-1.1.1 -f docker_images/ubuntu-19.04_clang-8x_openssl-1.1.1 .

docker build -m6g -t s2n_ubuntu:19.04_openssl-1.0.2 -f docker_images/ubuntu-19.04_openssl-1.0.2_base .
docker build -m6g -t ubuntu-19.04:gcc-6x_openssl-1.0.2 -f docker_images/ubuntu-19.04_gcc-6x_openssl-1.0.2 .
