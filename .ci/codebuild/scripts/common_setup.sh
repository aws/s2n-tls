# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

sudo prlimit --pid "$$" --memlock=unlimited:unlimited
ln -s /test-deps/ .
export LIBCRYPTO_ROOT=$(pwd)/test-deps/${S2N_LIBCRYPTO}
export NUM_CORES=$(nproc --all)
rm -rf libcrypto-root && ln -s "$LIBCRYPTO_ROOT" libcrypto-root
source .travis/s2n_override_paths.sh