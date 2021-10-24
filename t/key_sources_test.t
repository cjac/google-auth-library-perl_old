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

use strict;
use warnings;
use Test::More;
use Test::Exception;
use Test::Deep;

use Test::LWP::UserAgent;
use Test::More;

{
  package KeySourcesTest;
  our $useragent = Test::LWP::UserAgent->new();
}

plan tests => 7;

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
