# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

use Data::Dumper;

use strict;
use warnings;
use Test::More;
use Test::Exception;
use Test::Deep;

use Test::LWP::UserAgent;
use Test::More;

use Crypt::PK::ECC;
use Crypt::PK::RSA;
use Crypt::OpenSSL::CA;

use FindBin;

use DateTime;

{
  package KeySourcesTest;
  our $useragent = Test::LWP::UserAgent->new();
}

plan tests => 8;

use Google::Auth::IDTokens::KeySources;

#
# Static Key Source
#

my $key1 = Google::Auth::IDTokens::KeyInfo->new({id => "1234", key => "key1", algorithm => "RS256"});
my $key2 = Google::Auth::IDTokens::KeyInfo->new({id => "5678", key => "key2", algorithm => "ES256"});
my $keys = [$key1,$key2];
my $source = Google::Auth::IDTokens::StaticKeySource->new({keys => $keys});

is(ref $key1, "Google::Auth::IDTokens::KeyInfo", 'KeyInfo object correct');
is_deeply($keys, $source->current_keys, 'returns a static set of keys');
is_deeply($keys, $source->refresh_keys, 'does not change on refresh');

#
# HttpKeySource
#

my $certs_uri = "https://example.com/my-certs";
my $certs_body = {};

$source = Google::Auth::IDTokens::HttpKeySource->new( {uri => $certs_uri} );

my $ua = $KeySourcesTest::useragent;

my $not_json_hr =
  HTTP::Response->new('200', 'OK', ['Content-Type' => 'text/plain'], 'whoops');
$ua->map_response(qr/\Q$certs_uri\E/, $not_json_hr);

throws_ok { $source->refresh_keys } qr/KeySourceError: Unable to parse JSON/,
  'raises an error when failing to parse json from the site';
is( $ua->last_http_request_sent->uri, $certs_uri,
    'uri matches the one my code should have constructed' );


my $empty_json_hr = HTTP::Response->new('200', 'OK', ['Content-Type' => 'text/plain'], $certs_body);
$ua->map_response(qr/\Q$certs_uri\E/, $empty_json_hr);


lives_ok { $source->refresh_keys } 'downloads data';
is_deeply( $source->current_keys, [], 'gets no keys from JSON' );

#
# X509CertHttpKeySource
#

$key1 = Crypt::PK::RSA->new();
$key1->generate_key( 256, 65537 );

$key2 = Crypt::PK::RSA->new();
$key2->generate_key( 256, 65537 );

my( $id1, $id2 ) = ( "1234", "5678" );

my $coder = JSON::XS->new->ascii->pretty->allow_nonref;

my $dn = Crypt::OpenSSL::CA::X509_NAME->new
  (C => 'BE', O => 'Test', OU => 'Test', CN => 'Test');

ok( defined $dn, 'instance of Crypt::OpenSSL::CA::X509_Name is defined' );

my( $cert1, $cert2 ) = ( generate_cert( $key1 ),
                         generate_cert( $key2 ),
                       );

$certs_body = $coder->encode( { $id1 => $cert1->{pem},
                                $id2 => $cert2->{pem} } );

sub generate_cert {
  my( $key ) = @_;

  my $k = Crypt::OpenSSL::CA::PrivateKey->parse($key->export_key_pem('private'));
  my $pubkey = $k->get_public_key;

  my $x509 = Crypt::OpenSSL::CA::X509->new($pubkey);
  $x509->set_subject_DN( $dn );
  $x509->set_issuer_DN( $dn );
  $x509->set_notBefore( DateTime->now->strftime("%Y%m%d%H%M%SZ") );
  $x509->set_notAfter( DateTime->now->add( days => 365 )->strftime("%Y%m%d%H%M%SZ") );
  $x509->set_serial( "0x0" );
  my $pem = $x509->sign( $k, "sha1" );

  return { pem => $pem,
           x509 => $x509 };
}

diag Data::Dumper::Dumper($certs_body);


#qr/KeySourceError: Unable to retrieve data from $certs_uri/,
#  'raises an error when failing to parse json from the site';

#my $not_found_hr = HTTP::Response->new('404', 'Not Found', ['Content-Type' => 'text/plain'], 'whoops');
