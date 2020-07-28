#!/bin/bash

# This script is to test whether arpa can provide full coverage of goto functions
# required to run a given proof

makefile=Makefile
results=arpa-test-results.log

arpa_log=arpa-test-logs
goto_functions_std=$arpa_log/goto-functions-std
goto_functions_arpa=$arpa_log/goto-functions-arpa


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


function write_failure_log {
        mkdir -p $arpa_log
    cp Makefile.arpa $arpa_log
    cp arpa_cmake/compile_commands.json $arpa_log
    echo "$fcts_std_clean" > $goto_functions_std
    echo "$fcts_arpa_clean" > $goto_functions_arpa
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
        # goto functions are different
        echo -n "(DIFFERENT)"
        echo "FAILURE  -  $dir" >> ../$results

        #write files to arpa_log
        write_failure_log
    else
        # goto functions are identical
        echo -n "(IDENTICAL)"
        echo "SUCCESS  -  $dir" >> ../$results
    fi
    echo " >"

    # clean up
    make veryclean > /dev/null
    cd ..
done
