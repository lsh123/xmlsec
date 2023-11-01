#!/bin/perl
#
# Usage:
#  egrep -r -A8 -n 'xmlSec.*Error[0-9]?\(' ./src/ | sed 's/ //g' | perl ./scripts/check-return.pl
# 

my $has_return = 0;
my $where = "";
foreach my $line ( <STDIN> ) {
    chomp( $line );
    if($line eq "--" || $line eq '}' || $line eq 'continue' || $line eq 'break') {
        if(not $has_return) {
            print("FOUND MISSING RETURN: $where\n");
        }    
        $has_return = 0;
        $where = "";
    } elsif($line =~ /.*Error.*/ && $where eq "") {
        # print("Found error: $line\n");
        $where = $line
    } elsif($line =~ /.*goto.*/ || $line =~ /.*return.*/ || $line =~ /.*ignoreerror.*/) {
        $has_return = 1;
    }
}