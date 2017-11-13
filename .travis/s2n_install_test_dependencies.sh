#!/bin/bash

set -ex

# Clear the Travis Cache Weekly to ensure that any upstream breakages in test dependencies are caught
if [[ "$TRAVIS_EVENT_TYPE" == "cron" ]]; then
    sudo rm -rf ./test-deps
fi

# Install missing test dependencies. If the install directory already exists, cached artifacts will be used
# for that dependency.

if [[ ! -d test-deps ]]; then 
    mkdir test-deps ; 
fi

#Install & Run shell check before installing dependencies
echo "Running ShellCheck..."
.travis/install_shellcheck.sh "$TRAVIS_OS_NAME"
.travis/run_shellcheck.sh
echo "Shell Check is success."

if [[ "$TRAVIS_OS_NAME" == "linux" ]]; then
    .travis/install_ubuntu_dependencies.sh;
fi

if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then 
    .travis/install_osx_dependencies.sh;
fi

.travis/install_default_dependencies.sh

echo "Success"
