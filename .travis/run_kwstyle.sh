#! /bin/bash

S2N_FILES=`find $PWD -type f -name "s2n_*.[ch]" | grep -v "test"`

FAILED=0

for file in $S2N_FILES; do
    ERROR_LIST=`KWStyle -gcc -v -xml .travis/KWStyle.xml "$file"`
    if [ "$ERROR_LIST" != "" ] ;
    then
        echo "$ERROR_LIST"
        FAILED=1
    fi
done

if [ $FAILED == 1 ];
then
    printf "\033[31;1mFAILED kwstyle\033[0m\n"
    exit -1
else
    printf "\033[32;1mPASSED kwstyle\033[0m\n"
fi