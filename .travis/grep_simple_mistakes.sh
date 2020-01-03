#!/bin/bash
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

FAILED=0

# Assert that functions do not return -1 or S2N_ERR* codes directly.
# To indicate failure, functions should use the S2N_ERROR* macros defined
# in s2n_errno.h.
S2N_FILES_ASSERT_RETURN=$(find "$PWD" -type f -name "s2n*.c" -not -path "*/tests/*")
for file in $S2N_FILES_ASSERT_RETURN; do
  RESULT_NEGATIVE_ONE=`grep -rn 'return -1;' $file`
  RESULT_S2N_ERR=`grep -rn 'return S2N_ERR*' $file`
  RESULT_S2N_FAIL=`grep -rn 'return S2N_FAIL*' $file`

  if [ "${#RESULT_NEGATIVE_ONE}" != "0" ]; then
    FAILED=1
    printf "\e[1;34mGrep for 'return -1;' check failed in $file:\e[0m\n$RESULT_NEGATIVE_ONE\n\n"
  fi
  if [ "${#RESULT_S2N_ERR}" != "0" ]; then
    FAILED=1
    printf "\e[1;34mGrep for 'return S2N_ERR*' check failed in $file:\e[0m\n$RESULT_S2N_ERR\n\n"
  fi
  if [ "${#RESULT_S2N_FAIL}" != "0" ]; then
    FAILED=1
    printf "\e[1;34mGrep for 'return S2N_FAIL*' check failed in $file:\e[0m\n$RESULT_S2N_FAIL\n\n"
  fi
done

# Detect any array size calculations that are not using the s2n_array_len() function.
S2N_FILES_ARRAY_SIZING_RETURN=$(find "$PWD" -type f -name "s2n*.c" -path "*")
for file in $S2N_FILES_ARRAY_SIZING_RETURN; do
  RESULT_ARR_DIV=`grep -Ern 'sizeof\((.*)\) \/ sizeof\(\1\[0\]\)' $file`

  if [ "${#RESULT_ARR_DIV}" != "0" ]; then
    FAILED=1
    printf "\e[1;34mUsage of 'sizeof(array) / sizeof(array[0])' check failed. Use s2n_array_len(array) instead in $file:\e[0m\n$RESULT_ARR_DIV\n\n"
  fi
done

# Assert that all assignments from s2n_stuffer_raw_read() have a
# notnull_check (or similar manual null check) on the same, or next, line.
# The assertion is shallow; this doesn't guarantee that we're doing the
# *correct* null check, just that we are doing *some* null check.
S2N_FILES_ASSERT_NOTNULL_CHECK=$(find "$PWD" -type f -name "s2n*.[ch]" -not -path "*/tests/*")
for file in $S2N_FILES_ASSERT_NOTNULL_CHECK; do
  while read -r line_one; do
    # When called with the -A option, grep uses lines of "--" as delimiters. We ignore them.
    if [[ $line_one == "--" ]]; then
      continue
    fi

    read -r line_two

    # $line_one definitely contains an assignment from s2n_stuffer_raw_read(),
    # because that's what we grepped for. So verify that either $line_one or
    # $line_two contains a null check.
    manual_null_check_regex=".*if.*==\ NULL"
    if [[ $line_one == *"notnull_check("* ]] || [[ $line_one =~ $manual_null_check_regex ]] ||\
    [[ $line_two == *"notnull_check("* ]] || [[ $line_two =~ $manual_null_check_regex ]]; then
      # Found a notnull_check
      continue
    else
      FAILED=1
      printf "\e[1;34mFound a call to s2n_stuffer_raw_read without a notnull_check in $file:\e[0m\n$line_one\n\n"
    fi
  done < <(grep -rnE -A 1 "=\ss2n_stuffer_raw_read\(.*\)" $file)
done

if [ $FAILED == 1 ]; then
  printf "\\033[31;1mFAILED Grep For Simple Mistakes check\\033[0m\\n"
  exit -1
else
  printf "\\033[32;1mPASSED Grep For Simple Mistakes check\\033[0m\\n"
fi
