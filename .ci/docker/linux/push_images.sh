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

if [ -z ${1+x} ]; then
  ECS_REPO="024603541914.dkr.ecr.us-west-2.amazonaws.com/linux-docker-images"
else
  ECS_REPO=$1
fi

echo "Uploading docker images to ${ECS_REPO}."

$(aws ecr get-login --no-include-email --region us-west-2)

docker tag ubuntu-19.04:gcc-9x_openssl-1.1.1 ${ECS_REPO}:ubuntu-19.04_gcc-9x_openssl-1.1.1_`date +%Y-%m-%d`
docker push ${ECS_REPO}:ubuntu-19.04_gcc-9x_openssl-1.1.1_`date +%Y-%m-%d`

docker tag ubuntu-19.04:clang-8x_openssl-1.1.1 ${ECS_REPO}:ubuntu-19.04_clang-8x_openssl-1.1.1_`date +%Y-%m-%d`
docker push ${ECS_REPO}:ubuntu-19.04_clang-8x_openssl-1.1.1_`date +%Y-%m-%d`

docker tag ubuntu-19.04:gcc-6x_openssl-1.0.2 ${ECS_REPO}:ubuntu-19.04_gcc-6x_openssl-1.0.2_`date +%Y-%m-%d`
docker push ${ECS_REPO}:ubuntu-19.04_gcc-6x_openssl-1.0.2_`date +%Y-%m-%d`