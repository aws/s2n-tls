echo nix/shell.sh: Entering a devShell
export SRC_ROOT=$(pwd)

banner()
{
    echo "+------------------------------------------+"
    printf "| %-40s |\n" "$1"
    echo "+------------------------------------------+"
}


function configure {
    banner "Configuring with cmake"
    cmake -S . -B./build \
          -DBUILD_TESTING=ON \
          -DS2N_INTEG_TESTS=ON \
          -DS2N_INSTALL_S2NC_S2ND=ON \
          -DS2N_NIX_FAST_INTEG_TESTS=ON \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_BUILD_TYPE=RelWithDebInfo
}

function build {
    banner "Running Build"
    javac tests/integrationv2/bin/SSLSocketClient.java
    cmake --build ./build -j $(nproc)
}

function unit {
    cd build
    if [[ -z "$1" ]]; then
        ctest -L unit -j $(nproc) --verbose
    else
        ctest -L unit -R $1 -j $(nproc) --verbose
    fi
    cd ../
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
        (cd $SRC_ROOT/build; ctest -L integrationv2 -R "$1" --verbose)
    fi
}

function check-clang-format {
    banner "Dry run of clang-format"
    cd $SRC_ROOT
    include_regex=".*\.(c|h)$"
    src_files=`find ./api -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./bin -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./crypto -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./stuffer -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./error -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./tls -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./utils -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./tests/unit -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./tests/testlib -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    echo $src_files | xargs -n 1 -P $(nproc) clang-format --dry-run -style=file                 
}
function do-clang-format {
    banner "In place clang-format"
    cd $SRC_ROOT
    include_regex=".*\.(c|h)$"
    src_files=`find ./api -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./bin -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./crypto -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./stuffer -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./error -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./tls -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./utils -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./tests/unit -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    src_files+=" "
    src_files+=`find ./tests/testlib -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
    echo $src_files | xargs -n 1 -P $(nproc) clang-format -style=file -i
}
