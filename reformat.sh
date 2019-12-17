#!/bin/bash

# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

# The command used to generate the clang-format config file is:
#   clang-format --style=Google -dump-config

echo "Checking version number"
VER=$(clang-format --version|cut -f3 -d' '|cut -f1 -d'.')
if [ $VER -ge 8 ];then
  set -euxo pipefail
  find {.,s2n}/{include,source,tests} -name '*.h' -or -name '*.c' -or -name '*.cpp' | xargs clang-format -i
else
  echo "clang-format version 8 or greater is needed to read the format file."
fi

