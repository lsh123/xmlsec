#!/usr/bin/perl -w

use strict;

my $file;
while ($file = shift @ARGV) {
    print "Processing $file..\n";
    open (IN, $file) || die "Can't open $file: $!";
    my $entire_file;
    while(<IN>) {
	$entire_file = $entire_file . $_;
    }
    close (IN);
    $entire_file =~ s%<GTKDOCLINK\s+HREF="([^"]*)"\s*>(.*?)</GTKDOCLINK\s*>% "<font>$2</font>" %ge;

    open (OUT, ">$file") || die "Can't open $file: $!";
    print OUT $entire_file;
    close (OUT);	
}

