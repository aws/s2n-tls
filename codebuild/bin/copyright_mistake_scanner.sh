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


# NOTE: If you use the pipe character (|) anywhere in this string, you must escape it (\|).
# NOTE: If you use the double quote character (") anywhere in this string, you must escape it (\"),
# NOTE: End every pattern with the $ anchor, to be explicit. This is needed for the scan feature to correctly identify the files you already registered.
# You can safely comment in this string by using # and ending it with a newline character.
S2N_REGISTERED_PATTERNS="

#the license
.*s2n-tls/NOTICE$

#all the headers in /api
.*s2n-tls/api/.*\.h$

#all files in bin
.*s2n-tls/bin/[^/]*$

#all cpp files that begin with s2n_
.*s2n-tls/.*/s2n_[^/]*\.cc$

#all c files that begin with s2n_
.*s2n-tls/.*/[sS]2[nN]_[^/]*\.[ch]$

#codebuild/bin shell scripts
.*s2n-tls/codebuild/bin/[^/]*.\.sh$

#that one C file in codebuild/bin
.*s2n-tls/codebuild/bin/s2n_dynamic_load_test\.c$

#codebuild/spec yamls
.*s2n-tls/codebuild/spec/[^/]*\.yml$

#all files in crypto
.*s2n-tls/crypto/[^/]*$

#that one docker yaml
.*s2n-tls/docker-images/docker-compose\.yml$

#saw files
.*s2n-tls/tests/saw/.*\.saw$

#cry files in tests/saw/HMAC/spec
.*s2n-tls/tests/saw/.*\.cry$

#all files in tests/benchmark/utils
.*s2n-tls/tests/benchmark/utils/.*$

#all shell scripts in /tests
.*s2n-tls/tests/.*\.sh$

#tests/cbmc/stubs (unregistered the README)
.*s2n-tls/tests/cbmc/stubs/[^/]*$

#all rust files in bindings/rust
.*s2n-tls/bindings/rust/.*[^/]*\.rs$

#all shell scripts in bindings/rust
.*s2n-tls/bindings/rust/.*[^/]*\.sh$

#cbmc_proof headers
.*s2n-tls/tests/cbmc/include/cbmc_proof/.*$

#python files in test/cbmc/proofs
.*/s2n-tls/tests/cbmc/proofs/.*\.py$

#makefiles
.*s2n-tls/.*Makefile[^/]*$

#files that can't be grouped well in regex:
.*s2n-tls/tests/cbmc/sources/cbmc_utils\.c$
.*s2n-tls/tests/cbmc/sources/make_common_datastructures\.c$
.*s2n-tls/tests/sidetrail/working/s2n-cbc/cbc\.c$
.*s2n-tls/tests/sidetrail/count_success\.pl$
.*s2n-tls/tests/ctverif/count_success\.pl$
.*s2n-tls/tests/pems/sni/generate\.sh$
.*s2n-tls/tests/pems/gen_self_signed_cert\.sh$
.*s2n-tls/tests/fuzz/LD_PRELOAD/global_overrides\.c$
.*s2n-tls/tests/LD_PRELOAD/allocator_overrides\.c$
.*s2n-tls/tests/saw/spec/extras/HMAC/LICENSE$
.*s2n-tls/\.github/s2n_doxygen\.sh$
.*s2n-tls/\.github/workflows/proof_ci\.yaml$
.*s2n-tls/\.github/install_osx_dependencies\.sh$
.*s2n-tls/\.github/s2n_bsd\.sh$
.*s2n-tls/\.github/s2n_osx\.sh$
.*s2n-tls/\.github/gha_monitor/gha_monitor/__main__\.py$
.*s2n-tls/\.github/gha_monitor/gha_monitor/sns\.py$
.*s2n-tls/bindings/rust/s2n-tls-sys/templates/features\.template$
.*s2n-tls/.git/hooks/pre-rebase\.sample$
.*s2n-tls/pq-crypto/s2n_pq_asm\.mk$
.*s2n-tls/pq-crypto/kyber_r3/KeccakP-brg_endian_avx2\.h$
"
#END OF REGISTERED PATTERNS

# NOTE: If you use the pipe character (|) anywhere in this string, you must escape it (\|).
# NOTE: If you use the double quote character (") anywhere in this string, you must escape it (\"),
# NOTE: End every spattern with the $ anchor, to be explicit. This is needed for the scan feature to correctly identify the files you already registered.
# You can safely comment in this string by using # and ending it with a newline character.
S2N_UNREGISTERED_PATTERNS="

.*s2n-tls/tests/cbmc/stubs/README.md$

"
# END OF UNREGISTERED PATTERNS

# Strip comments from pattern strings
S2N_REGISTERED_PATTERNS=`printf "%s" "$S2N_REGISTERED_PATTERNS" | sed "s|^#.*$||g"`
S2N_UNREGISTERED_PATTERNS=`printf "%s" "$S2N_UNREGISTERED_PATTERNS" | sed "s|^#.*$||g"`


FAIL_COUNT=0
SUCCESS_COUNT=0

# If the -scan flag is provided, we search all files not registered/unregistered and report on any new copyright headers that should be registered/unregistered.
if [ "$1" == "-scan" ];
then
    ALL_FILES=`find "$PWD" -type f`

    for pattern in $S2N_REGISTERED_PATTERNS; do
        ALL_FILES=`printf "%s" "$ALL_FILES" | sed "s|$pattern||g"`
    done

    for pattern in $S2N_UNREGISTERED_PATTERNS; do
        ALL_FILES=`printf "%s" "$ALL_FILES" | sed "s|$pattern||g"`
    done

    for file in $ALL_FILES; do
        # The word "Copyright" should appear at least once in the first 3 lines of every file
        if head -3 "$file" | grep -q "Copyright";
        then
	    SUCCESS_COUNT=$((SUCCESS_COUNT+1))
	    file=`printf "%s" "$file" | grep -o "s2n-tls/.*"`
            printf "\nNew copyright header found:\n%s\n" "$file"
        fi
    done

    printf "\n%d new copyright headers found during scan.\n" "$SUCCESS_COUNT"
    exit 0
fi


for pattern in $S2N_REGISTERED_PATTERNS; do
    FOUND_FILES=`find "$PWD" -type f -regex "$pattern"`
    S2N_FILES=`printf "%s\n%s" "$S2N_FILES" "$FOUND_FILES"`
done

S2N_FILES=`printf "%s" "$S2N_FILES" | sort -u`

for pattern in $S2N_UNREGISTERED_PATTERNS; do
    S2N_FILES=`printf "%s" "$S2N_FILES" | sed "s|$pattern||g"`
done

for file in $S2N_FILES; do
    # The word "Copyright" should appear at least once in the first 3 lines of every file
    if head -3 "$file" | grep -q "Copyright";
    then
	SUCCESS_COUNT=$((SUCCESS_COUNT+1))
    else
	FAIL_COUNT=$((FAIL_COUNT+1))
	file=`printf "%s" "$file" | grep -o "s2n-tls/.*"`
        printf "\n%s\n%s\n" "Copyright Check Failed:" "$file"
    fi
done

TOTAL_COUNT=`expr $FAIL_COUNT + $SUCCESS_COUNT`

printf "\n%d/%d Files Passing\n" "$SUCCESS_COUNT" "$TOTAL_COUNT"

if [ $FAIL_COUNT -gt 0 ];
then
    printf "\\033[31;1mFAILED Copyright Check\\033[0m\\n"
    exit -1
else
    printf "\\033[32;1mPASSED Copyright Check\\033[0m\\n"
    exit 0
fi
