#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;
use Test::Exception;

BEGIN {
    use_ok( 'Google::Auth::Exceptions' ) || print "Bail out!\n";
}

diag( "Testing Google::Auth::Exceptions $Google::Auth::Exceptions::VERSION, Perl $], $^X" );

throws_ok{ Google::Auth::Error->throw("generic Google Auth Error"); } qr/generic/;

done_testing(2);
