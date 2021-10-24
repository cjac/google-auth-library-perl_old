#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 2;

BEGIN {
    use_ok( 'Google::Auth' ) || print "Bail out!\n";
    use_ok( 'Google::Auth::IDTokens::KeySources' ) || print "Bail out!\n";
}

diag( "Testing Google::Auth $Google::Auth::VERSION, Perl $], $^X" );
