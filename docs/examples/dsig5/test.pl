#
# Read STDIN input and send it to 
# XML Digital Signature Verifier 
# usage:
#   cat <filename> | test.pl
#
use HTTP::Request::Common;
use LWP::UserAgent; 

my $url = 'http://www.aleksey.com/cgi-bin/xmldsigverify';
my $ua = LWP::UserAgent->new();
my $headers;
my $body = join "", <STDIN>;
my $req =  HTTP::Request->new('POST', $url, $headers, $body);
my $resp = $ua->request($req);
print $resp->content;