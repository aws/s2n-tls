#!/bin/bash

set -ex
find ./lib ./libcrypto-build ./tls ./utils -name '*.h' -or -name '*.c' -or -name '*.cpp' -exec clang-format --verbose -i {} \;

if [[ `git status --porcelain` ]]; then
	echo "clang-format updated files, throwing an error"
	exit 255
else
	echo "No files touched"
fi
