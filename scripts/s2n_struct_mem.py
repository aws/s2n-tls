#! /usr/bin/env python

'''
Script to examine the fields of a structure.
Useful for identifying large fields in complex structures like s2n_connection.

Example usage:
./scripts/s2n_struct_mem.py -h : print the usage message
./scripts/s2n_struct_mem.py s2n_connection --min 100 : list the size of all fields of s2n_connection larger than 100 bytes
./scripts/s2n_struct_mem.py s2n_crypto_parameters --file tls/s2n_crypto.h --types : list the size and type of all fields of s2n_crypto_parameters
'''

import sys
import os
import argparse
import re

parser = argparse.ArgumentParser(description='Examine the fields of a struct')
parser.add_argument('struct_name',
                    help='a structure to examine. Example: s2n_connection')
parser.add_argument('--file',
                    help='header file containing the struct definition. If not provided, defaults to tls/<struct_name>.h')
parser.add_argument('--min', default=0,
                    help='ignore fields smaller than the given size in bytes')
parser.add_argument('--types', action='store_true',
                    help='include type information in output (more verbose)')
args = parser.parse_args()

struct_name = args.struct_name

file_name = args.file if args.file else "tls/%s.h" % (struct_name)
if not os.path.exists(file_name):
    sys.exit("'%s' does not exist" % file_name)

struct_re = re.compile(r"^struct %s ?\{.+?^\};" % struct_name, re.MULTILINE | re.DOTALL)
field_re = re.compile(r"^(.+ \*?(\w+)(:1)?(?:\[.*\])?);", re.MULTILINE)

buffer = open(file_name).read()
struct_match = struct_re.search(buffer)
if not struct_match:
    sys.exit("'%s' not found in '%s'" % (struct_name, file_name))
field_matches = field_re.findall(struct_match.group(0))
if not field_matches or not len(field_matches):
    sys.exit("no fields found in '%s'" % struct_name)

field_entry = "{ .name = \"%s\", .size = sizeof(target.%s) },"
bitfield_entry = "{ .name = \"%s\", .size = 1 },"

test_entries = []
spacing = 40
for field_match in field_matches:
    if args.types:
        match = field_match[0]
    else:
        match = field_match[1]
    spacing = max(spacing, len(match))
    field = field_match[1]
    is_bitfield = field_match[2]
    if is_bitfield:
        test_entries.append(bitfield_entry % (match))
    else:
        test_entries.append(field_entry % (match, field))
        
test_contents = """
#include "s2n_test.h"
#include "%(file_name)s"

struct %(struct_name)s target = { 0 };

struct {
    const char* name;
    size_t size;
} fields[] = {
%(test_entries)s
};

int main(int argc, char **argv)
{
    fprintf(stdout, "\\nTotal size of %(struct_name)s: %%lu\\n", (long) sizeof(struct %(struct_name)s));
    for (size_t i = 0; i < s2n_array_len(fields); i++) {
        if (fields[i].size < %(min)s) {
            continue;
        }
        fprintf(stdout, "%%%(spacing)ss: %%6lu bytes\\n", fields[i].name, (long) fields[i].size);
    }
}
""" % {'file_name': file_name, 'struct_name': struct_name, 'test_entries': "\n".join(test_entries),
       'min': args.min, 'spacing': spacing}      

test_file = 'tests/unit/VISUALIZE_STRUCT.c'
open(test_file, 'w').write(test_contents)

os.system('UNIT_TESTS="VISUALIZE_STRUCT" make')
os.remove(test_file)
