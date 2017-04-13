#!/usr/bin/perl -w
# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

# This script takes ct-verif output, and counts the number of successful
# and failed tests.  If these match expected, it returns 0. Else it dies
# with a non-zero exit code.

use strict;
use warnings;

if (@ARGV != 2) {
    die "usage: count_success.pl expected_success expected_failures";
}

my $expected_success = shift;
my $expected_failure = shift;

my $verified = 0;
my $errors = 0;
while (my $line = <STDIN>){
    print $line;
    if ($line =~ /Boogie program verifier finished with (\d+) verified, (\d+) errors/) {
	$verified = $verified + $1;
	$errors = $errors + $2;
    }
}

if($verified == $expected_success and $errors == $expected_failure){
   print "verified: $verified errors: $errors as expected\n";
} else {
    die "ERROR:\tExpected \tverified: $expected_success\terrors: $expected_failure.\n\tGot\t\tverified: $verified\terrors: $errors.\n";
}
