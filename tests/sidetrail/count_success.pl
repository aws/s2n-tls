#!/usr/bin/perl -w
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

sub  trim { my $s = shift; $s =~ s/^\s+|\s+$//g; return $s };

if (@ARGV != 3) {
    die "usage: count_success.pl expected_success expected_failures filename";
}

my $expected_success = shift;
my $expected_failure = shift;
my $filename = shift;
my @undefined_functions = ();
my %allowed_undefined = ("__CONTRACT_invariant" => 1,
			 "malloc" => 1,
			 "nondet" => 1,
			 "free" => 1,
    );

my $verified = 0;
my $errors = 0;
open (FILE, $filename) or die "Can't open $filename $!";
while (my $line = <FILE>){
    #Check if the code under test used unexpected functions
    if ($line =~ /warning: module contains undefined functions:([a-zA-Z0-9_, ]+)/) {
	print "found undefined\n\n";
	for my $fns (split(",",$1)){
	    my $trimmed = trim ($fns);
	    unless ($allowed_undefined{$trimmed}) {
		push @undefined_functions, $trimmed;
	    }
	}
    }
    
    #Count the number of errors / successes
    if ($line =~ /Boogie program verifier finished with (\d+) verified, (\d+) error/) {
	$verified = $verified + $1;
	$errors = $errors + $2;
    }
}

if($verified == $expected_success and $errors == $expected_failure){
   print "verified: $verified errors: $errors as expected\n";
} else {
    die "ERROR:\tExpected \tverified: $expected_success\terrors: $expected_failure.\n\tGot\t\tverified: $verified\terrors: $errors.\n";
}

if (@undefined_functions) {
    die "Unable to prove that code was constant time due to the presence of external functions: @undefined_functions\n";
}
