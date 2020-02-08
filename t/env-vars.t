#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
    use_ok( 'Google::Auth::EnvironmentVars' ) || print "Bail out!\n";
}

diag( "Testing Google::Auth::EnvironmentVars $Google::Auth::EnvironmentVars::VERSION, Perl $], $^X" );

my $prj_str = 'test-project-string';
$ENV{GOOGLE_CLOUD_PROJECT}=$prj_str;

my $gaev = Google::Auth::EnvironmentVars->new();

is( $gaev->{PROJECT}, $prj_str, '$gaev->{PROJECT} defined when environment variable GOOGLE_CLOUD_PROJECT set' );

done_testing(2);
