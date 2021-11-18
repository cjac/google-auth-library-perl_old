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
        'DateTime' => '0',
        'Test::More' => '0',
        'Test::Exception' => '0',
        'Test::LWP::UserAgent' => '0',
        'JSON::XS' => '0',
        'HTTP::Request::Common' => '0',
        'LWP::UserAgent' => '0',
        'Crypt::PK::ECC' => 0,
        'Crypt::PK::RSA' => 0,
        'Crypt::X509' => 0,

    },
    PREREQ_PM => {
        #'ABC'              => '1.6',
        #'Foo::Bar::Module' => '5.0401',
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Google-Auth-Library-Perl-*' },
);
