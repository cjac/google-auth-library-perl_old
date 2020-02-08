use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Google::Auth',
    AUTHOR           => q{C.J. Collier <CJCOLLIER@CPAN.ORG>},
    VERSION_FROM     => 'lib/Google/Auth.pm',
    ABSTRACT_FROM    => 'lib/Google/Auth.pm',
    LICENSE          => 'Apache 2.0',
    PL_FILES         => {},
    MIN_PERL_VERSION => '5.006',
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => '0',
    },
    BUILD_REQUIRES => {
        'Test::More' => '0',
    },
    PREREQ_PM => {
        #'ABC'              => '1.6',
        #'Foo::Bar::Module' => '5.0401',
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Google-Auth-Library-Perl-*' },
);
