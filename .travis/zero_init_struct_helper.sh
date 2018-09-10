#!/bin/bash
# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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


usage() {
    echo "init_structs.sh struct_name init_value"
    echo "Example: ./init_structs.sh s2n_blob {0}"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

STRUCT_NAME=$1
INIT_VALUE=$2

LINES_WITH_UNINITIALIZED_STRUCTS=`grep -En "struct ${STRUCT_NAME} [a-z0-9_]+;" ./**/s2n*.c | cut -d: -f1-2`;
LINE_COUNT=`echo "$LINES_WITH_UNINITIALIZED_STRUCTS" | wc -l`
WORD_COUNT=`echo "$LINES_WITH_UNINITIALIZED_STRUCTS" | wc -w`

if [ $WORD_COUNT -eq 0 ]; then
    echo "Found zero uninitialized ${STRUCT_NAME} structs."
    exit
fi

echo "Found $LINE_COUNT uninitialized ${STRUCT_NAME} structs..."

for line in $LINES_WITH_UNINITIALIZED_STRUCTS
do
  # Line Format: "${file_name}:${line_num}"
  FILENAME=`echo "${line}" | cut -d: -f 1`
  LINE_NUM=`echo "${line}" | cut -d: -f 2`
  
  # Use sed to replace ";" with " = {0};"
  SED_ARGS="-i '' '${LINE_NUM}s/;/ = ${INIT_VALUE};/' ${FILENAME}"
  echo "Initializing ${STRUCT_NAME} at ${FILENAME}:${LINE_NUM} with: ${INIT_VALUE}."
  echo "${SED_ARGS}"| xargs sed;
done
