#!/bin/bash

makefile=Makefile
results=arpa-test-results.log
debug_std=out_std
debug_arpa=out_arpa

function initialize {
        rm -f $results
}

function look_for {
    if [ ! -f $1 ]; then
        echo "-- $1 does not exist in ($dir)." 1>&2
        echo "<SKIPPING>" 1>&2
        cd ..
        echo "ERROR  -  $dir" >> $results
        continue
    fi
}

function get_functions {
        cbmc --show-goto-functions gotos/$harness.goto
}

function make_std {
    make veryclean
    make goto
    fcts_std=$(get_functions)
    fcts_std_clean=$(grep -v " *//.*" <<< "$fcts_std")
}

function make_arpa {
    make veryclean
    make arpa

    makefile_temp=$(sed -e 's-PROOF_SOURCES += \$(PROOF_SOURCE).*--g' \
        -e 's-PROJECT_SOURCES += .*--g' \
        -e 's-include ../Makefile.common-include Makefile.arpa\'$'\ninclude ../Makefile.common-g'\
        $makefile)

    make goto -f <(echo "$makefile_temp")
    fcts_arpa=$(get_functions)
    fcts_arpa_clean=$(grep -v " *//.*" <<< "$fcts_arpa")
}

# MAIN
initialize
for dir in *; do
    if [ ! -d $dir ]; then
        continue
    fi

    cd $dir
    harness="$dir"_harness.c
    echo -e "\n<BEGIN - ($dir) >"

    # check files
    look_for $makefile
    look_for $harness

    # define fcts_std_clean
    echo "-- Listing goto functions for STANDARD approach"
    make_std > /dev/null

    # define fcts_arpa_clean
    echo "-- Listing goto functions for ARPA approach"
    make_arpa > /dev/null

    # compare functions list
    is_dif=$(diff -q <(echo "$fcts_std_clean") \
        <(echo "$fcts_arpa_clean"))

    # report
    echo -n "<END - "
    if [ "$is_dif" ]; then
        echo -n "(DIFFERENT)"
        echo "FAILURE  -  $dir" >> ../$results
        echo "$fcts_std_clean" > $debug_std
        echo "$fcts_arpa_clean" > $debug_arpa
    else
        echo -n "(IDENTICAL)"
        echo "SUCCESS  -  $dir" >> ../$results
        make veryclean > /dev/null
    fi
    echo " >"

    # clean up
    cd ..
done
