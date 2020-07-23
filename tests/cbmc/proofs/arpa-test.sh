#!/bin/bash

makefile=Makefile

function check_files {
    if [ ! -f $makefile ]; then
        echo "-- Makefile does not exist in $dir. Skipping." 1>&2
        cd ..
        continue
    fi
    if [ ! -f $harness ]; then
        echo "-- Harness file does not exist in $dir. Skipping." 1>&2
        cd ..
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
}

function clean_up {
    make veryclean
    # rm diff_file
    # rm fcts_std
    # rm fcts_arpa
}

# for x in *; do
for dir in s2n_stuffer_free; do

    cd $dir
    harness="$dir"_harness.c
    echo -e "\n<BEGIN in $dir>"

    # check files
    check_files
    echo "-- Confirmed existence of required files"

    # define fcts_std
    make_std > /dev/null
    echo "-- Created list of goto functions for STANDARD approach"

    # define fcts_arpa
    make_arpa > /dev/null
    echo "-- Created list of goto functions for ARPA approach"

    # compare functions list
    echo -n "-- Comparing goto functions..."
    # get rid of comments
    fcts_std_clean=$(grep -v " *//.*" <<< "$fcts_std")
    fcts_arpa_clean=$(grep -v " *//.*" <<< "$fcts_arpa")
    # echo "$fcts_arpa_clean" > fcts_arpa
    # echo "$fcts_std_clean" > fcts_std
    
    # diff --new-line-format="" --unchanged-line-format="" \
    #     <(echo "$fcts_std_clean") \
    #     <(echo "$fcts_arpa_clean")

    is_ident=$(diff -s <(echo "$fcts_std_clean") \
        <(echo "$fcts_arpa_clean"))

    if [ is_ident ]; then
        echo " IDENTICAL :)"
    else
        echo " DIFFERENT :("
    fi

    echo -e "<END>\n"
    # compare fcts_std and fcts_arpa


    # clean up
    clean_up > /dev/null
    cd ..

done

