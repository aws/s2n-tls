#!/bin/bash

# Install missing test dependencies. If the install directory already exists, cached artifacts will be used
# for that dependency.

if [[ ! -d test-deps ]]; then 
    mkdir test-deps ; 
fi

#Install & Run shell check before installing dependincies
echo "Running ShellCheck..."
.travis/install_shellcheck.sh
.travis/run_shellcheck.sh
echo "Shell Check is success."

if [[ "$TRAVIS_OS_NAME" == "linux" ]]; then
    .travis/install_ubuntu_dependencies.sh;
fi

if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then 
    .travis/install_osx_dependencies.sh;
fi

.travis/install_default_dependencies.sh

# Set GCC 6 as Default on both Ubuntu and OSX
if [[ "$GCC6_REQUIRED" == "true" ]]; then
    alias gcc="\$(which gcc-6)";
fi
