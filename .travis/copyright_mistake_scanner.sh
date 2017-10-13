#!/bin/bash

#header checker for either copyright info and/or proper year

YEAR=$(date +%Y)
while IFS= read -r -d $'\0' file; do
	grep -L "* Copyright $YEAR" $file | perl -ne 'print "File is missing copyright info: $_"'
done < <(find . -type f -print0 -name '*.c' -o -name '*.h')
