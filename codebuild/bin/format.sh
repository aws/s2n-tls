#!/bin/bash

set -ex

CLANGFORMAT=$(which clang-format-9)

find ./lib ./libcrypto-build ./tls ./utils -exec "$CLANGFORMAT --verbose -i {}" \; -name '*.h' -or -name '*.c' -or -name '*.cpp'

if [[ `git status --porcelain` ]]; then
	echo "clang-format updated files, throwing an error"
	exit 255
else
	echo "No files touched"
fi
