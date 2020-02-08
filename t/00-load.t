#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'Google::Auth' ) || print "Bail out!\n";
}

diag( "Testing Google::Auth $Google::Auth::VERSION, Perl $], $^X" );
