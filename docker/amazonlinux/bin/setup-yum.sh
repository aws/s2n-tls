#!/bin/bash

# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

# This script installs dependencies from APT. If specific additional dependencies are needed,
# the $EXTRA_PACKAGES environment variable can be set from the Dockerfile to avoid having to
# `apt-get update' twice in the dockerfile.

EXTRA_PACKAGES=${EXTRA_PACKAGES:-}

set -euxo pipefail

yum update

yum upgrade -y
yum groupinstall -y "Development Tools"
yum install -y wget cmake git awscli valgrind ninja-build zlib-devel json-c-devel imake $EXTRA_PACKAGES
yum clean all
