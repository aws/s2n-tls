#!/bin/bash
debug_std=out_std
debug_arpa=out_arpa

for dir in *; do
    if [ ! -d $dir ]; then
        continue
    fi

    cd $dir
    echo "<CLEANING - ($dir) >"

    make veryclean > /dev/null
    rm -f $debug_arpa
    rm -f $debug_std
    cd ..

done
