#! /usr/bin/python

import sys
import re

args = sys.argv[1:]
assert len(args) == 2, "usage is <bpl-file-name> <trace-to-convert>"
print args


def make_bpl_c_mapping(bpl_filename):
    linenum = 0
    bpl_c_mapping = {}
    current_bb_line = -1
    with open(bpl_filename) as bpl_file:
        for line in bpl_file:
            linenum += 1
            if re.match(r'\$bb\d+', line):
                current_bb_line = linenum
                bpl_c_mapping[current_bb_line] = []

            matchObj = re.match(r'  assume {:sourceloc "(.+)", (\d+), (\d+)} true;', line)
            if matchObj:
                matched_filename = matchObj.group(1)
                matched_fileline = matchObj.group(2)
                bpl_c_mapping[current_bb_line].append((matched_filename, matched_fileline))

    return bpl_c_mapping


def convert_trace_to_c(trace_filename, bpl_c_mapping):
    with open(trace_filename) as tracefile:
        for line in tracefile:
            matchObj = re.match(r'.*\.bpl\((\d+),\d+\).*', line)
            if matchObj:
                bpl_line = int(matchObj.group(1))
                if bpl_line in bpl_c_mapping:
                    mapping = bpl_c_mapping[bpl_line]
                    if len(mapping) > 0:
                        print mapping[0]
                    else:
                        print "No Source Loc"
                else:
                    print "unknown basic block"

                print "\t\t", matchObj.group(0), matchObj.group(1)


bpl_c_mapping = make_bpl_c_mapping(args[0])
convert_trace_to_c(args[1], bpl_c_mapping)
