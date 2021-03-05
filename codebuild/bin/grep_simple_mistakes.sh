#!/usr/bin/env bash
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
    manual_null_check_regex="(.*(if|ENSURE_POSIX|POSIX_ENSURE).*=\ NULL)|(ENSURE_REF)"
    if [[ $line_one == *"notnull_check("* ]] || [[ $line_one =~ $manual_null_check_regex ]] ||\
    [[ $line_two == *"notnull_check("* ]] || [[ $line_two =~ $manual_null_check_regex ]]; then
      # Found a notnull_check
      continue
    else
      FAILED=1
      printf "\e[1;34mFound a call to s2n_stuffer_raw_read without an ENSURE_REF in $file:\e[0m\n$line_one\n\n"
    fi
  done < <(grep -rnE -A 1 "=\ss2n_stuffer_raw_read\(.*\)" $file)
done

# Assert that "index" is not a variable name. An "index" function exists in strings.h, and older compilers (<GCC 4.8) 
# warn if any local variables called "index" are used because they are considered to shadow that declaration. 
S2N_FILES_ASSERT_VARIABLE_NAME_INDEX=$(find "$PWD" -type f -name "s2n*.[ch]")
for file in $S2N_FILES_ASSERT_VARIABLE_NAME_INDEX; do
  RESULT_VARIABLE_NAME_INDEX=`gcc -fpreprocessed -dD -E -w $file | grep -v '"' | grep '[\*|,|;|[:space:]]index[;|,|\)|[:space:]]'`
  if [ "${#RESULT_VARIABLE_NAME_INDEX}" != "0" ]; then
    FAILED=1
    printf "\e[1;34mGrep for variable name 'index' check failed in $file:\e[0m\n$RESULT_VARIABLE_NAME_INDEX\n\n"
  fi
done

## Assert that there are no new uses of S2N_ERROR_IF
# TODO add crypto, tls (see https://github.com/aws/s2n-tls/issues/2635)
S2N_ERROR_IF_FREE="bin error pq-crypto scram stuffer utils tests"
for dir in $S2N_ERROR_IF_FREE; do
  files=$(find "$dir" -type f -name "*.c" -path "*")
  for file in $files; do
    result=`grep -Ern 'S2N_ERROR_IF' $file`
    if [ "${#result}" != "0" ]; then
      FAILED=1
      printf "\e[1;34mUsage of 'S2N_ERROR_IF' check failed. Use 'POSIX_ENSURE' instead in $file:\e[0m\n$result\n\n"
    fi
  done
done

if [ $FAILED == 1 ]; then
  printf "\\033[31;1mFAILED Grep For Simple Mistakes check\\033[0m\\n"
  exit -1
else
  printf "\\033[32;1mPASSED Grep For Simple Mistakes check\\033[0m\\n"
fi
