#!/usr/bin/perl

# Copyright (c) 2003 America Online, Inc.  All rights reserved.

# A crude, simple script that looks at "loss record" (stacks) in valgrind 
# output, and if the stack contains any of the funcs to ignore, then it 
# skips that stack else the stack is printed.

# syntax 
#   test_leaks.pl <file containing funcs to ignore> <valgrind output file>


$ignore_file = shift @ARGV;
$valgrind_output = shift @ARGV;

# gather funcs to ignore
open(IN, "$ignore_file") || die "Unable to open file $ignore_file";
$i=0;
while(<IN>) {
    chop;
    $ignore[$i++] = $_;
}
close IN;

# now walk through the valgrind output
open(IN, "$valgrind_output") || die "Unable to open file $valgrind_output";
while(<IN>) {
    if (/==\d+==.*loss record.*\n/) {
	$line=$_;
	next;
    } else {
	if (/==\d+== \n/ && $line) {
            $i=0;
            $bad=0;
            while ($ignore[$i]) {
	        if ($line =~ /$ignore[$i]/) {
                    #printf "STACK TO BE IGNORED : \n%s\n", $line;
		    $bad=1;
		    break;
                }
		$i++;
	    }

	    # if none of the patterns matched...
	    if ($bad==0) {
                printf "STACK TO EXAMINE: \n%s\n", $line;
	    }

	    undef $line;
	    next;
	}

	if ($line) {
	    $line=$line.$_;
	}
   
   }
}
close IN;

