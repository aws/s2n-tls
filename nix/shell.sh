echo nix/shell.sh: Entering a devShell
export SRC_ROOT=$(pwd)
export PATH=$SRC_ROOT/build/bin:$PATH

banner()
{
    echo "+---------------------------------------------------------+"
    printf "| %-55s |\n" "$1"
    echo "+---------------------------------------------------------+"
}

function libcrypto_alias {
    local libcrypto_name=$1
    local libcrypto_binary_path=$2
    if [[ -f $libcrypto_binary_path ]]; then
      alias $libcrypto_name=$libcrypto_binary_path
      echo "Libcrypto binary $libcrypto_binary_path available as $libcrypto_name"
    else
      banner "Could not find libcrypto $libcrypto_binary_path for alias"
    fi
}
libcrypto_alias openssl102 "${OPENSSL_1_0_2_INSTALL_DIR}/bin/openssl"
libcrypto_alias openssl111 "${OPENSSL_1_1_1_INSTALL_DIR}/bin/openssl"
libcrypto_alias openssl30 "${OPENSSL_3_0_INSTALL_DIR}/bin/openssl"
libcrypto_alias bssl "${AWSLC_INSTALL_DIR}/bin/bssl"
libcrypto_alias libressl "${LIBRESSL_INSTALL_DIR}/bin/openssl"
#No need to alias gnutls because it is included in common_packages (see flake.nix).

function clean {
    banner "Cleanup ./build"
    rm -rf ./build
}

function configure {
    banner "Configuring with cmake"
    cmake -S . -B./build \
          -DBUILD_TESTING=ON \
          -DS2N_INTEG_TESTS=ON \
          -DS2N_INSTALL_S2NC_S2ND=ON \
          -DS2N_INTEG_NIX=ON \
          -DBUILD_SHARED_LIBS=ON \
          $S2N_CMAKE_OPTIONS \
          -DCMAKE_BUILD_TYPE=RelWithDebInfo
}

function build {
    banner "Running Build"
    javac tests/integrationv2/bin/SSLSocketClient.java
    cmake --build ./build -j $(nproc)
}

function unit {
    if [[ -z "$1" ]]; then
        (cd $SRC_ROOT/build; ctest -L unit -j $(nproc) --verbose)
    else
        (cd $SRC_ROOT/build; ctest -L unit -R $1 -j $(nproc) --verbose)
    fi
}

function integ {
    if [ "$1" == "help" ]; then
        echo "The following tests are not supported:"
        echo " - cross_compatibility"
        echo "    This test depends on s2nc_head and s2nd_head. To run"
        echo "    the test build s2n-tls from the main branch on github."
        echo "    Change the names of s2n[cd] to s2n[cd]_head and add those"
        echo "    binaries to \$PATH."
        echo "- renegotiate_apache"
        echo "   This test requires apache to be running. See codebuild/bin/s2n_apache.sh"
        echo "    for more info."
        return
    fi
    if [[ -z "$1" ]]; then
        banner "Running all integ tests except cross_compatibility, renegotiate_apache."
        (cd $SRC_ROOT/build; ctest -L integrationv2 -E "(integrationv2_cross_compatibility|integrationv2_renegotiate_apache)" --verbose)
    else
        banner "Warning: cross_compatibility & renegotiate_apache are not supported in nix for various reasons integ help for more info."
        for test in $@; do
            ctest --test-dir ./build -L integrationv2 --no-tests=error --output-on-failure -R "$test" --verbose
            if [ "$?" -ne 0 ]; then
               echo "Test failed, stopping execution"
               return 1
            fi
        done
    fi
}

function check-clang-format {
    banner "Dry run of clang-format"
    (cd $SRC_ROOT;
    include_regex=".*\.(c|h)$";
    src_files=`find ./api -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./bin -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./crypto -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./stuffer -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./error -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./tls -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./utils -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./tests/unit -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./tests/testlib -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    echo $src_files | xargs -n 1 -P $(nproc) clang-format --dry-run -style=file)
}
function do-clang-format {
    banner "In place clang-format"
    (cd $SRC_ROOT;
    include_regex=".*\.(c|h)$";
    src_files=`find ./api -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./bin -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./crypto -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./stuffer -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./error -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./tls -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./utils -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./tests/unit -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./tests/testlib -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    echo $src_files | xargs -n 1 -P $(nproc) clang-format -style=file -i)
}

function test_toolchain_counts {
    # This is a starting point for a unit test of the devShell.
    # The chosen S2N_LIBCRYPTO should be 2, and the others should be zero.
    banner "Checking the CMAKE_INCLUDE_PATH for libcrypto counts"
    echo $CMAKE_INCLUDE_PATH|gawk 'BEGIN{RS=":"; o10=0; o11=0; o3=0;awslc=0;libre=0}
      /openssl-3.0/{o3++}
      /openssl-1.1/{o11++}
      /openssl-1.0/{o10++}
      /aws-lc/{awslc++}
      /libressl/{libre++}
      END{print "\nOpenssl3:\t",o3,"\nOpenssl1.1:\t",o11,"\nOpenssl1.0.2:\t",o10,"\nAwlc:\t\t",awslc,"\nLibreSSL:\t", libre}'
    banner "Checking tooling counts (these should all be 1)"
    echo -e "\nOpenssl integ:\t $(openssl version|grep -c '1.1.1')"
    echo -e "Corretto 17:\t $(java -version 2>&1|grep -ce 'Runtime.*Corretto-17')"
    echo -e "gnutls-cli:\t $(gnutls-cli --version |grep -c 'gnutls-cli 3.7')"
    echo -e "gnutls-serv:\t $(gnutls-serv --version |grep -c 'gnutls-serv 3.7')"
    echo -e "Nix Python:\t $(which python|grep -c '/nix/store')"
    echo -e "Nix pytest:\t $(which pytest|grep -c '/nix/store')"
    echo -e "Nix sslyze:\t $(which sslyze|grep -c '/nix/store')"
    echo -e "python nassl:\t $(pip freeze|grep -c 'nassl')"
    echo -e "valgrind:\t $(valgrind --version|grep -c 'valgrind-3.19.0')"
}

function test_nonstandard_compilation {
    # Any script that needs to compile s2n in a non-standard way can run here
    ./codebuild/bin/test_dynamic_load.sh $(mktemp -d)
}

