#!/bin/bash

grep -rnw "let.*$1" .
grep -rnw "$1.*<-" .
