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

#############################################
# Grep for any instances of raw memcpy() function. s2n code should instead be
# using one of the *_ENSURE_MEMCPY macros.
#############################################
S2N_FILES_ASSERT_NOT_USING_MEMCPY=$(find "$PWD" -type f -name "s2n*.[ch]" -not -path "*/tests/*")
for file in $S2N_FILES_ASSERT_NOT_USING_MEMCPY; do
  RESULT_NUM_LINES=`grep 'memcpy(' $file | wc -l`
  if [ "${RESULT_NUM_LINES}" != 0 ]; then
    echo "Found ${RESULT_NUM_LINES} raw 'memcpy' calls in $file"
    FAILED=1
  fi
done

#############################################
# Grep for any instances of raw memcmp() function. s2n code should instead be
# using s2n_constant_time_equals()
#
# KNOWN_MEMCMP_USAGE is used to capture all known uses of memcmp and acts as a
# safeguard against any new uses of memcmp.
#############################################
S2N_FILES_ASSERT_NOT_USING_MEMCMP=$(find "$PWD" -type f -name "s2n*.[ch]" -not -path "*/tests/*" -not -path "*/bindings/*")
declare -A KNOWN_MEMCMP_USAGE
KNOWN_MEMCMP_USAGE["$PWD/crypto/s2n_rsa.c"]=1
KNOWN_MEMCMP_USAGE["$PWD/tls/s2n_early_data.c"]=1
KNOWN_MEMCMP_USAGE["$PWD/tls/s2n_kem.c"]=1
KNOWN_MEMCMP_USAGE["$PWD/tls/s2n_cipher_suites.c"]=3
KNOWN_MEMCMP_USAGE["$PWD/tls/s2n_server_hello.c"]=3
KNOWN_MEMCMP_USAGE["$PWD/tls/s2n_security_policies.c"]=1
KNOWN_MEMCMP_USAGE["$PWD/tls/s2n_psk.c"]=1
KNOWN_MEMCMP_USAGE["$PWD/tls/s2n_config.c"]=1
KNOWN_MEMCMP_USAGE["$PWD/tls/s2n_resume.c"]=2
KNOWN_MEMCMP_USAGE["$PWD/tls/s2n_connection.c"]=1
KNOWN_MEMCMP_USAGE["$PWD/tls/s2n_protocol_preferences.c"]=1
KNOWN_MEMCMP_USAGE["$PWD/utils/s2n_map.c"]=3
KNOWN_MEMCMP_USAGE["$PWD/stuffer/s2n_stuffer_text.c"]=1

for file in $S2N_FILES_ASSERT_NOT_USING_MEMCMP; do
  # NOTE: this matches on 'memcmp', which will also match comments. However, there
  # are no uses of 'memcmp' in comments so we opt for this stricter check.
  RESULT_NUM_LINES=`grep -n 'memcmp' $file | wc -l`

  # set default KNOWN_MEMCMP_USAGE value
  [ -z "${KNOWN_MEMCMP_USAGE["$file"]}" ] && KNOWN_MEMCMP_USAGE["$file"]="0"

  # check if memcmp usage is 0 or a known value
  if [ "${RESULT_NUM_LINES}" != "${KNOWN_MEMCMP_USAGE["$file"]}" ]; then
    echo "Expected: ${KNOWN_MEMCMP_USAGE["$file"]} Found: ${RESULT_NUM_LINES} usage of 'memcmp' in $file"
    FAILED=1
  fi
done

#############################################
# Assert that functions do not return -1 or S2N_ERR* codes directly.
# To indicate failure, functions should use the S2N_ERROR* macros defined
# in s2n_errno.h.
#############################################
S2N_FILES_ASSERT_RETURN=$(find "$PWD" -type f -name "s2n*.c" -not -path "*/tests/*" -not -path "*/docs/examples/*")
for file in $S2N_FILES_ASSERT_RETURN; do
  RESULT_NEGATIVE_ONE=`grep -rn 'return -1;' $file`
  RESULT_S2N_ERR=`grep -rn 'return S2N_ERR*' $file`
  RESULT_S2N_FAIL=`grep -rn 'return S2N_FAIL*' $file`
  RESULT_S2N_RESULT_ERR=`grep -rn 'return S2N_RESULT_ERR*' $file`

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
  if [ "${#RESULT_S2N_RESULT_ERR}" != "0" ]; then
    FAILED=1
    printf "\e[1;34mGrep for 'return S2N_RESULT_ERR*' check failed in $file:\e[0m\n$RESULT_S2N_RESULT_ERR\n\n"
  fi
done

#############################################
# Detect any array size calculations that are not using the s2n_array_len() function.
#############################################
S2N_FILES_ARRAY_SIZING_RETURN=$(find "$PWD" -type f -name "s2n*.c" -path "*")
for file in $S2N_FILES_ARRAY_SIZING_RETURN; do
  RESULT_ARR_DIV=`grep -Ern 'sizeof\((.*)\) \/ sizeof\(\1\[0\]\)' $file`

  if [ "${#RESULT_ARR_DIV}" != "0" ]; then
    FAILED=1
    printf "\e[1;34mUsage of 'sizeof(array) / sizeof(array[0])' check failed. Use s2n_array_len(array) instead in $file:\e[0m\n$RESULT_ARR_DIV\n\n"
  fi
done

#############################################
# Assert that all assignments from s2n_stuffer_raw_read() have a
# notnull_check (or similar manual null check) on the same, or next, line.
# The assertion is shallow; this doesn't guarantee that we're doing the
# *correct* null check, just that we are doing *some* null check.
#############################################
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
    null_check_regex="(.*(if|ENSURE).*=\ NULL)|(ENSURE_REF)"
    if [[ $line_one =~ $null_check_regex ]] || [[ $line_two =~ $null_check_regex ]]; then
      # Found a notnull_check
      continue
    else
      FAILED=1
      printf "\e[1;34mFound a call to s2n_stuffer_raw_read without an ENSURE_REF in $file:\e[0m\n$line_one\n\n"
    fi
  done < <(grep -rnE -A 1 "=\ss2n_stuffer_raw_read\(.*\)" $file)
done

#############################################
# Assert that "index" is not a variable name. An "index" function exists in strings.h, and older compilers (<GCC 4.8) 
# warn if any local variables called "index" are used because they are considered to shadow that declaration. 
#############################################
S2N_FILES_ASSERT_VARIABLE_NAME_INDEX=$(find "$PWD" -type f -name "s2n*.[ch]")
for file in $S2N_FILES_ASSERT_VARIABLE_NAME_INDEX; do
  RESULT_VARIABLE_NAME_INDEX=`gcc -fpreprocessed -dD -E -w $file | grep -v '"' | grep '[\*|,|;|[:space:]]index[;|,|\)|[:space:]]'`
  if [ "${#RESULT_VARIABLE_NAME_INDEX}" != "0" ]; then
    FAILED=1
    printf "\e[1;34mGrep for variable name 'index' check failed in $file:\e[0m\n$RESULT_VARIABLE_NAME_INDEX\n\n"
  fi
done

#############################################
# Assert that we didn't accidentally add an extra semicolon when ending a line.
# This also errors when there is whitespace in-between semicolons, as that is an empty
# statement and usually not purposeful.
#############################################
S2N_FILES_ASSERT_DOUBLE_SEMICOLON=$(find "$PWD" -type f -name "s2n*.[ch]" -not -path "*/bindings/*")
for file in $S2N_FILES_ASSERT_DOUBLE_SEMICOLON; do
  RESULT_DOUBLE_SEMICOLON=`grep -Ern ';[[:space:]]*;' $file`
  if [ "${#RESULT_DOUBLE_SEMICOLON}" != "0" ]; then
    FAILED=1
    printf "\e[1;34mFound a double semicolon in $file:\e[0m\n$RESULT_DOUBLE_SEMICOLON\n\n"
  fi
done

#############################################
# Assert that we don't call malloc directly outside of utils/s2n_mem.c or tests.
# All other allocations must use s2n_alloc or s2n_realloc.
#############################################
S2N_FILES_ASSERT_MALLOC=$(find "$PWD" -type f -name "s2n*.c" \
    -not -path "*/utils/s2n_mem.c" \
    -not -path "*/tests/*" \
    -not -path "*/bin/*")
for file in $S2N_FILES_ASSERT_MALLOC; do
  RESULT_MALLOC=`grep -n "= malloc(" $file`
  if [ "${#RESULT_MALLOC}" != "0" ]; then
    FAILED=1
    printf "\e[1;34mFound malloc in $file:\e[0m\n$RESULT_MALLOC\n\n"
  fi
done

#############################################
## Assert that there are no new uses of S2N_ERROR_IF
# TODO add crypto, tls (see https://github.com/aws/s2n-tls/issues/2635)
#############################################
S2N_ERROR_IF_FREE="bin error scram stuffer utils tests"
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

#############################################
## Assert all ".[c|h]" source files have the correct file mode.
#############################################
S2N_FILES_WITH_WRONG_MODE=$(find "$PWD" \( -name '*.c' -o -name '*.h' \) -a \! -perm 644)
if [[ -n $S2N_FILES_WITH_WRONG_MODE ]]; then
  for file in $S2N_FILES_WITH_WRONG_MODE; do
    FAILED=1
    printf "\\033[31;1mFile mode of %s is not 644.\\033[0m\\n" "$file"
  done
  printf "\\033[31;1mPlease run \`find s2n-tls/ -name '*.c' -o -name '*.h' -exec chmod 644 {} \\;\` to fix all file modes.\\033[0m\\n"
fi

#############################################
## Assert "extern" is not added to function declarations unnecessarily.
#############################################
S2N_UNNECESSARY_EXTERNS=$(find "$PWD" -type f -name "s2n*.[h]" \! -path "*/api/*" \! -path "*/bindings/*" \
  -exec grep -RE "extern (.*?) (.*?)\(" {} +)
if [[ -n $S2N_UNNECESSARY_EXTERNS ]]; then
  FAILED=1
  printf "\e[1;34mFound unnecessary 'extern' in function declaration:\e[0m\n"
  printf "$S2N_UNNECESSARY_EXTERNS\n\n"
fi

#############################################
# Assert ENSURE/GUARD have a valid error code
#############################################
S2N_ENSURE_WITH_INVALID_ERROR_CODE=$(find "$PWD" -type f -name "s2n*.c" -path "*" \! -path "*/tests/*" \
    -exec grep -RE "(ENSURE|GUARD_OSSL)\(.*?, .*?);" {} + | grep -v "S2N_ERR_")
if [[ -n $S2N_ENSURE_WITH_INVALID_ERROR_CODE ]]; then
  FAILED=1
  printf "\e[1;34mENSURE and GUARD_OSSL require a valid error code from errors/s2n_errno.h:\e[0m\n"
  printf "$S2N_ENSURE_WITH_INVALID_ERROR_CODE\n\n"
fi

#############################################
# REPORT FINAL RESULTS
#############################################
if [ $FAILED == 1 ]; then
  printf "\\033[31;1mFAILED Grep For Simple Mistakes check\\033[0m\\n"
  exit -1
else
  printf "\\033[32;1mPASSED Grep For Simple Mistakes check\\033[0m\\n"
fi
