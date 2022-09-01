#!/bin/bash
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

# Ensure that s2nc accepts all generated certificates

s2nc_path="../../../bin/s2nc"
s2nd_path="../../../bin/s2nd"

cert_chains=("none_revoked" "leaf_revoked" "intermediate_revoked" "all_revoked")

for cert_chain in "${cert_chains[@]}"; do
  "${s2nd_path}" \
      --self-service-blinding \
      --negotiate \
      --cert "${cert_chain}_cert_chain.pem" \
      --key "${cert_chain}_key.pem" \
      localhost 8888 &
  s2nd_pid=$!

  "${s2nc_path}" \
      --ca-file "root_cert.pem" \
      localhost 8888
  s2nc_success=$?

  kill ${s2nd_pid}

  if [ ${s2nc_success} -ne 0 ]; then
    exit 1
  fi
done
