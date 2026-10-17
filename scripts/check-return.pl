#!/usr/bin/perl
#
# Usage:
#  egrep -r -A8 -n 'xmlSec.*Error[0-9]?\(' ./src/ | sed 's/ //g' | perl ./scripts/check-return.pl
#

my $has_return = 0;
my $where = "";
my $saw_open = 0;
foreach my $line ( <STDIN> ) {
    chomp( $line );
    if($line eq "--") {
        if(not $has_return) {
            print("FOUND MISSING RETURN: $where\n");
        }
        $has_return = 0;
        $where = "";
        $saw_open = 0;
    } elsif($line eq 'continue' || $line eq 'break') {
        if(not $has_return) {
            print("FOUND MISSING RETURN: $where\n");
        }
        $has_return = 0;
        $where = "";
        $saw_open = 0;
    } elsif($line eq '}' && not $saw_open) {
        # A closing brace only ends the block containing the error call
        # if no nested block was opened after the call; intermediate
        # closing braces of inner blocks are not boundaries.
        if(not $has_return) {
            print("FOUND MISSING RETURN: $where\n");
        }
        $has_return = 0;
        $where = "";
        $saw_open = 0;
    } elsif($line =~ /.*Error.*/ && $where eq "") {
        # print("Found error: $line\n");
        $where = $line
    } elsif($line =~ /.*goto.*/ || $line =~ /.*return.*/ || $line =~ /.*ignoreerror.*/) {
        $has_return = 1;
    } elsif($line =~ /\{/) {
        $saw_open = 1;
    }
}
