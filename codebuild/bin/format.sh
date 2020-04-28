#!/bin/bash

set -e

for i in $(find ./lib ./libcrypto-build ./tls ./utils -name '*.h' -or -name '*.c' -or -name '*.cpp'); do
        clang-format-9 --verbose -i "$i" ;
done

if [[ `git status --porcelain` ]]; then
        echo "clang-format updated files, throwing an error"
        exit 255
else
        echo "No files touched"
fi
