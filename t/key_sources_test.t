# Copyright 2020,2021,2022 Google LLC
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

diag( "Testing Google::Auth::IDTokens::KeySources $Google::Auth::IDTokens::KeySources::VERSION, Perl $], $^X" );

BEGIN {
  plan tests => 44;
  $ENV{TESTING} = 1;
  use_ok( 'Google::Auth::IDTokens::KeySources' ) || print "Bail out!\n";
}

{
  package KeySourcesTest;
  our $useragent = Test::LWP::UserAgent->new();
}

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
my $certs_body_json = "{}";

my $ua = $KeySourcesTest::useragent;

my $response;

#
# Not JSON
#

my $not_json_hr   = HTTP::Response->new('200', 'OK', ['Content-Type' => 'text/plain'], 'whoops');
$ua->unmap_all();
$ua->map_response(qr/\Q$certs_uri\E/, $not_json_hr);
$source = Google::Auth::IDTokens::HttpKeySource->new( {uri => $certs_uri} );
throws_ok { $source->refresh_keys } qr/KeySourceError: Unable to parse JSON/,
  'raises an error when failing to parse json from the site, class=' . ref $source;
is( $ua->last_http_request_sent->uri, $certs_uri,
    'uri matches the one expected' );

$response = $ua->last_http_response_received;
is( $response->{_rc}, 200, 'return code matches' );
is( $response->{_content}, 'whoops', 'content matches' );

#
# Empty JSON
#

my $empty_json_hr = HTTP::Response->new('200', 'OK', ['Content-Type' => 'text/plain'], $certs_body_json);
$ua->unmap_all();
$ua->map_response(qr/\Q$certs_uri\E/, $empty_json_hr);
$source = Google::Auth::IDTokens::HttpKeySource->new( {uri => $certs_uri} );
lives_ok { $source->refresh_keys } 'downloads data but gets no keys';

$response = $ua->last_http_response_received;
is( $response->{_rc}, 200, 'empty JSON return code matches' );
is( $response->{_content}, $certs_body_json, 'empty JSON content matches' );
is_deeply( $source->current_keys, [], 'gets no keys from JSON' );

#
# Not found
#

my $not_found_hr  = HTTP::Response->new('404', 'Not Found', ['Content-Type' => 'text/plain'], 'not a found');
$ua->unmap_all();
$ua->map_response(qr/\Q$certs_uri\E/, $not_json_hr);
$source = Google::Auth::IDTokens::HttpKeySource->new( {uri => $certs_uri} );
throws_ok { $source->refresh_keys } qr/KeySourceError: Unable to parse JSON/,
  'raises an error when failing to parse json from the site, class=' . ref $source;
TODO: {
  local $TODO = 'return code and content do not match for some reason';
is( $response->{_rc}, 404, 'return code matches' );
is( $response->{_content}, 'not a found', 'content matches' );
};


#
# X509CertHttpKeySource
#

my $dn = Crypt::OpenSSL::CA::X509_NAME->new
  (C => 'BE', O => 'Test', OU => 'Test', CN => 'Test');

ok( defined $dn, 'instance of Crypt::OpenSSL::CA::X509_Name is defined' );

$key1 = Crypt::PK::RSA->new();
$key1->generate_key( 256, 65537 );

$key2 = Crypt::PK::RSA->new();
$key2->generate_key( 256, 65537 );

my( $cert1, $cert2 ) = ( generate_cert( $key1 ),
                         generate_cert( $key2 ),
                       );

my( $id1, $id2 ) = ( "1234", "5678" );

my $coder = JSON::XS->new->ascii->pretty->allow_nonref;

$certs_body = { $id1 => $cert1->{pem},
                $id2 => $cert2->{pem} };
$certs_body_json = $coder->encode ( $certs_body );

sub generate_cert {
  my( $key ) = @_;

  my $k = Crypt::OpenSSL::CA::PrivateKey->parse( $key->export_key_pem('private') );
  my $pubkey = $k->get_public_key;

  my $x509 = Crypt::OpenSSL::CA::X509->new($pubkey);
  $x509->set_subject_DN( $dn );
  $x509->set_issuer_DN( $dn );
  $x509->set_notBefore( DateTime->now->strftime("%Y%m%d%H%M%SZ") );
  $x509->set_notAfter( DateTime->now->add( days => 365 )->strftime("%Y%m%d%H%M%SZ") );
  $x509->set_serial( "0x0" );

  return { pem  => $x509->sign( $k, "sha1" ),
           x509 => $x509 };
}

#
# Correct exception thrown when JSON not found
#

$ua->unmap_all();
$ua->map_response(qr/\Q$certs_uri\E/, $not_found_hr);

$source = Google::Auth::IDTokens::X509CertHttpKeySource->new( {uri => $certs_uri} );
throws_ok { $source->refresh_keys; }
  qr/KeySourceError: Unable to retrieve data from $certs_uri/,
  'raises an error when failing to reach the site';

#
# Correct exception thrown when content is not JSON
#

$ua->unmap_all();
$ua->map_response(qr/\Q$certs_uri\E/, $not_json_hr);

$source = Google::Auth::IDTokens::X509CertHttpKeySource->new( {uri => $certs_uri} );
throws_ok { $source->refresh_keys } qr/KeySourceError: Unable to parse JSON/,
  'raises an error when failing to parse json from the site, class=' . ref $source;
is( $ua->last_http_request_sent->uri, $certs_uri,
    'uri matches the one expected' );

#
# Negative x509 test
#

my $not_x509_hr  = HTTP::Response->new('200', 'OK', ['Content-Type' => 'text/plain'], '{"hi": "whoops"}');
$source = Google::Auth::IDTokens::X509CertHttpKeySource->new( {uri => $certs_uri} );

$ua->unmap_all();
$ua->map_response(qr/\Q$certs_uri\E/, $not_x509_hr);
TODO: {
  local $TODO = 'return code and content do not match for some reason';
throws_ok { $source->refresh_keys }
  qr/KeySourceError: Unable to retrieve data from/,
  'raises an error when failing to parse x509 from the site';

};

#
# Positive x509 test
#

my $x509_hr  = HTTP::Response->new('200', 'OK', ['Content-Type' => 'text/plain'], $certs_body_json);
$source = Google::Auth::IDTokens::X509CertHttpKeySource->new( {uri => $certs_uri} );
$ua->unmap_all();
$ua->map_response(qr/\Q$certs_uri\E/, $x509_hr);

lives_ok { $keys = $source->refresh_keys } 'key refresh succeeds';
is( $keys->[0]->{id}, $id1, 'first key matches' );
is( $keys->[1]->{id}, $id2, 'second key matches' );
is( $keys->[0]->{algorithm}, 'RS256', 'first algorithm matches' );
is( $keys->[1]->{algorithm}, 'RS256', 'second algorithm matches' );
is( $ua->last_http_request_sent->uri, $certs_uri,
    'uri matches the one expected' );

#
# JWK source tests
#

my $jwk_uri = 'https://example.com/my-jwk';
$id1 = 'fb8ca5b7d8d9a5c6c6788071e866c6c40f3fc1f9';
$id2 = 'LYyP2g';

my $jwk1 = {
  alg => "RS256",
        e =>   "AQAB",
        kid => $id1,
        kty => "RSA",
        n => "zK8PHf_6V3G5rU-viUOL1HvAYn7q--dxMoUkt7x1rSWX6fimla-lpoYAKhFTLU" .
             "ELkRKy_6UDzfybz0P9eItqS2UxVWYpKYmKTQ08HgUBUde4GtO_B0SkSk8iLtGh" .
             "653UBBjgXmfzdfQEz_DsaWn7BMtuAhY9hpMtJye8LQlwaS8ibQrsC0j0GZM5KX" .
             "RITHwfx06_T1qqC_MOZRA6iJs-J2HNlgeyFuoQVBTY6pRqGXa-qaVsSG3iU-vq" .
             "NIciFquIq-xydwxLqZNksRRer5VAsSHf0eD3g2DX-cf6paSy1aM40svO9EfSvG" .
             "_07MuHafEE44RFvSZZ4ubEN9U7ALSjdw",
        use => "sig"
};
my $jwk2 = {
        alg => "ES256",
        crv => "P-256",
        kid => $id2,
        kty => "EC",
        use => "sig",
        x =>   "SlXFFkJ3JxMsXyXNrqzE3ozl_0913PmNbccLLWfeQFU",
        y =>   "GLSahrZfBErmMUcHP0MGaeVnJdBwquhrhQ8eP05NfCI"
    };
my $bad_type_jwk = {
    alg => "RS256",
    kid => "hello",
    kty => "blah",
    use => "sig"
};

my $jwk_body = $coder->encode( { keys => [ $jwk1, $jwk2 ] } );
my $bad_type_body = $coder->encode( { keys => [ $bad_type_jwk ] } );

#
# Correct exception thrown when JSON not found
#

$ua->unmap_all();
$ua->map_response(qr/\Q$jwk_uri\E/, $not_found_hr);
my $params = {uri => $jwk_uri};

$source = Google::Auth::IDTokens::JwkHttpKeySource->new( $params );
throws_ok { $source->refresh_keys; }
  qr/KeySourceError: Unable to retrieve data from $jwk_uri/,
  'raises an error when failing to reach the site';

#
# Correct exception thrown when content is not JSON
#

$ua->unmap_all();
$ua->map_response(qr/\Q$jwk_uri\E/, $not_json_hr);

$source = Google::Auth::IDTokens::JwkHttpKeySource->new( $params );
throws_ok { $source->refresh_keys }
  qr/KeySourceError: Unable to parse JSON/,
  'raises an error when failing to parse json from the site, class=' . ref $source;
is( $ua->last_http_request_sent->uri, $jwk_uri,
    'uri matches the one expected' );

#
# Negative JwkHttp test
#

my $not_jwk_hr  = HTTP::Response->new('200', 'OK', ['Content-Type' => 'text/plain'], 'whoops');
$source = Google::Auth::IDTokens::JwkHttpKeySource->new( $params );

$ua->unmap_all();
$ua->map_response(qr/\Q$jwk_uri\E/, $not_jwk_hr);

throws_ok { $source->refresh_keys }
qr/Unable to parse JSON: malformed JSON string/,
  'raises an error when failing to parse jwk from the site';


my $malformed_jwk_hr  = HTTP::Response->new('200', 'OK', ['Content-Type' => 'text/plain'], '{"hi": "whoops"}');
$source = Google::Auth::IDTokens::JwkHttpKeySource->new( $params );

$ua->unmap_all();
$ua->map_response(qr/\Q$jwk_uri\E/, $malformed_jwk_hr);

throws_ok { $source->refresh_keys }
qr/No keys found in jwk set/,
  "raises an error when the json structure is malformed";

my $unrecognized_kt_hr = HTTP::Response->new('200', 'OK', ['Content-Type' => 'text/plain'], $bad_type_body );
$source = Google::Auth::IDTokens::JwkHttpKeySource->new( $params );

$ua->unmap_all();
$ua->map_response(qr/\Q$jwk_uri\E/, $unrecognized_kt_hr);

throws_ok { $source->refresh_keys }
qr/Cannot use key type blah/,
  'raises an error when an unrecognized key type is encountered';
  
#
# Positive JwkHttp test
#

my $correct_hr = HTTP::Response->new('200', 'OK', ['Content-Type' => 'text/plain'], $jwk_body );
$source = Google::Auth::IDTokens::JwkHttpKeySource->new( $params );

$ua->unmap_all();
$ua->map_response(qr/\Q$jwk_uri\E/, $correct_hr);

TODO: {
  local $TODO = 'the following tests are incomplete';

lives_ok { $keys = $source->refresh_keys }
  'refresh succeeds';
};
is( ref $keys, 'ARRAY', 'an array of keys is returned');

is( scalar @{$keys}, 2, 'two keys in the results');

is( ref $keys->[0], 'Google::Auth::IDTokens::KeyInfo', 'first returned key is a blessed hash');
is( ref $keys->[1], 'Google::Auth::IDTokens::KeyInfo', 'second returned key is a blessed hash');

TODO: {
  local $TODO = 'the following tests are incomplete';

is( $keys->[0]->{id}, $id1, 'first key matches' );
is( $keys->[1]->{id}, $id2, 'second key matches' );
is( ref $keys->[0]->{key}, 'Crypt::PK::RSA', 'key type for first key is correct');
is( ref $keys->[1]->{key}, 'Crypt::PK::ECC', 'key type for second key is correct');
};
is( $keys->[0]->{algorithm}, 'RS256', 'first algorithm matches' );
TODO: {
  local $TODO = 'the following tests are incomplete';
is( $keys->[1]->{algorithm}, 'ES256', 'second algorithm matches' );
is( $ua->last_http_request_sent->uri, $certs_uri,
    'uri matches the one expected' );
};


#diag $obj->{ua};

#diag Data::Dumper::Dumper( $ua->last_http_response_received );

#diag Data::Dumper::Dumper($certs_body);


#qr/KeySourceError: Unable to retrieve data from $certs_uri/,
#  'raises an error when failing to parse json from the site, class=' . ref $source;

#my $not_found_hr = HTTP::Response->new('404', 'Not Found', ['Content-Type' => 'text/plain'], 'whoops');
