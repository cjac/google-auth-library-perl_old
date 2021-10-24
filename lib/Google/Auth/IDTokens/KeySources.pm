# frozen_string_literal: true

package Google::Auth::IDTokens::KeySources;
use URI;
use DateTime;
use JSON::XS;
use Mutex;
use HTTP::Request::Common;
use LWP::UserAgent;
use Crypt::PK::ECC;
use Crypt::PK::RSA;
use Crypt::X509;

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

1;

      ##
      # A public key used for verifying ID tokens.
      #
      # This includes the public key data, ID, and the algorithm used for
      # signature verification. RSA and Elliptical Curve (EC) keys are
      # supported.
      #

package Google::Auth::IDTokens::KeyInfo;

my $coder = JSON::XS->new->ascii->pretty->allow_nonref;

        ##
        # Create a public key info structure.
        #
        # @param id [String] The key ID.
        # @param key [Crypt::PK::RSA,Crypt::PK::ECC] The key itself.
        # @param algorithm [String] The algorithm (normally `RS256` or `ES256`)
        #
        sub new {
          my( $class, $params ) = @_;
          $class = ref $class if ref $class;
          my $self = bless { id        => $params->{id}        // undef,
                             key       => $params->{key}       // undef,
                             algorithm => $params->{algorithm} // undef,
                           }, $class;
        }

        ##
        # The key ID.
        # @return [String]
        #
        sub id { return $_[0]->{id} }

        ##
        # The key itself.
        # @return [OpenSSL::PKey::RSA,OpenSSL::PKey::EC]
        #
        sub key { return $_[0]->{key} }

        ##
        # The signature algorithm. (normally `RS256` or `ES256`)
        # @return [String]
        #
        sub algorithm { return $_[0]->{algorithm} }

          ##
          # Create a KeyInfo from a single JWK, which may be given as either a
          # hash or an unparsed JSON string.
          #
          # @param jwk [Hash,String] The JWK specification.
          # @return [KeyInfo]
          # @raise [KeySourceError] If the key could not be extracted from the
          #     JWK.
          #
        sub from_jwk {
          my( $self, $jwk ) = @_;
          $jwk = ensure_json_parsed( $jwk );
          if( $jwk->{kty} eq 'RSA' ){
            $self->{key} = $self->extract_rsa_key( $jwk );
          }elsif( $jwk->{kty} eq 'EC' ){
            $self->{key} = $self->extract_ec_key( $jwk );
          }elsif( !defined $jwk->{kty}  ){
            die "Key type not found";
          }else{
            die "Cannot use key type [$jwk->{kty}]"
          }
          $self->{id} = $jwk->{kid};
          $self->{key} = $pub_key;
          $self->{algorithm} = $jwk->{alg};

          return $self;
        }
          ##
          # Create an array of KeyInfo from a JWK Set, which may be given as
          # either a hash or an unparsed JSON string.
          #
          # @param jwk [Hash,String] The JWK Set specification.
          # @return [Array<KeyInfo>]
          # @raise [KeySourceError] If a key could not be extracted from the
          #     JWK Set.
          #
        sub from_jwk_set {
          my( $self, $jwk_set ) = @_;
          $jwk_set = ensure_json_parsed( $jwk_set );
          die "No keys found in jwk set" unless( exists $jwks->{keys} &&
                                                 ref $jwks->{keys} eq 'ARRAY' );
          my $jwks = [ map { from_jwk( $_ ) } @{$jwk_set->{keys}} ];
        }

        sub ensure_json_parsed {
          my( $self, $input ) = @_;
          return $input if ref $input;
          my $decoded = eval { $coder->decode ($input) };
          die "Unable to parse JSON: $@" if $@;
          return $decoded
        }

        sub symbolize_keys {
          my( $self, $hash ) = @_;
          my $result = {};
          while( my($key,$val) = each %$hash ){
            $result->{$key} = $val
          }
          return $result;
        }

        sub extract_rsa_key {
          my( $self, $jwk ) = @_;

          my $pk = Crypt::PK::RSA->new();
          $pk->import_key( $jwk );
          return $pk;
        }

          # @private
        my $CURVE_NAME_MAP = {
            "P-256"     => "prime256v1",
            "P-384"     => "secp384r1",
            "P-521"     => "secp521r1",
            "secp256k1" => "secp256k1"
        };

        sub extract_ec_key {
          my($self, $jwk) = @_;
          die "Unsupported EC curve $jwk->{crv}"
            unless exists $CURVE_NAME_MAP->{$jwk->{crv}};

          my $pk = Crypt::PK::ECC->new();
          $pk->import_key( $jwk );

          return $pk;
        }

1;

package Google::Auth::IDTokens::StaticKeySource;
      ##
      # A key source that contains a static set of keys.
      #
        ##
        # Create a static key source with the given keys.
        #
        # @param keys [Array<KeyInfo>] The keys
        #
        sub new {
          my( $class, $params ) = @_;
          $class = ref $class if ref $class;
          my $self = bless { current_keys => [@{$params->{keys}}] }, $class;
          return $self;
        }

        ##
        # Return the current keys. Does not perform any refresh.
        #
        # @return [Array<KeyInfo>]
        #
        sub current_keys { return $_[0]->{current_keys} };
        *refresh_keys = \&current_keys;

          ##
          # Create a static key source containing a single key parsed from a
          # single JWK, which may be given as either a hash or an unparsed
          # JSON string.
          #
          # @param jwk [Hash,String] The JWK specification.
          # @return [StaticKeySource]
          #
        sub from_jwk {
          my($self,$jwk) = @_;
          return Google::Auth::IDTokens::KeyInfo->new()->from_jwk( $jwk );
        }

          ##
          # Create a static key source containing multiple keys parsed from a
          # JWK Set, which may be given as either a hash or an unparsed JSON
          # string.
          #
          # @param jwk_set [Hash,String] The JWK Set specification.
          # @return [StaticKeySource]
          #
        sub from_jwk {
          my($self,$jwk_set) = @_;
          return Google::Auth::IDTokens::KeyInfo->new()->from_jwk_set( $jwk_set );
        }

1;

package Google::Auth::IDTokens::HttpKeySource;
      ##
      # A base key source that downloads keys from a URI. Subclasses should
      # override {HttpKeySource#interpret_json} to parse the response.
      #
        ##
        # The default interval between retries in seconds (3600s = 1hr).
        #
        # @return [Integer]
        #
        our $DEFAULT_RETRY_INTERVAL = 3600;

        ##
        # Create an HTTP key source.
        #
        # @param uri [String,URI] The URI from which to download keys.
        # @param retry_interval [Integer,nil] Override the retry interval in
        #     seconds. This is the minimum time between retries of failed key
        #     downloads.
        #
        sub new {
          my( $class, $params ) = @_;
          $class = ref $class if ref $class;
          my $self = bless { retry_interval   => $params->{retry_interval} || $DEFAULT_RETRY_INTERVAL,
                             allow_refresh_at => DateTime->now,
                             current_keys     => [],
                             monitor          => Mutex->new,
                             uri              => URI->new( $params->{uri} ),
                           }, $class;

          if(exists $ENV{TESTING} && $ENV{TESTING} ){
            $self->{ua} = $KeySourcesTest::useragent;
          }else{
            $self->{ua} = LWP::UserAgent->new(timeout => 10);
          }

          return $self;
        }

        ##
        # The URI from which to download keys.
        # @return [Array<KeyInfo>]
        #
        sub uri { return $_[0]->{uri} }

        ##
        # Return the current keys, without attempting to re-download.
        #
        # @return [Array<KeyInfo>]
        #
        sub current_keys { return $_[0]->{current_keys} }

        ##
        # Attempt to re-download keys (if the retry interval has expired) and
        # return the new keys.
        #
        # @return [Array<KeyInfo>]
        # @raise [KeySourceError] if key retrieval failed.
        #
        sub refresh_keys {
          my($self) = @_;
          return @{$self->{current_keys}} if DateTime->compare(DateTime->now, $self->{allow_refresh_at}) < 0;

          $self->{allow_refresh_at} = DateTime->now()->add( seconds => $self->{retry_interval} );

          my $response = $self->{ua}->get( $self->{uri} );

          die("KeySourceError: Unable to retrieve data from $self->{uri}: " . $response->status_line())
            unless $response->is_success;

          my $data = eval { $coder->decode ($response->decoded_content) };
          die "KeySourceError: Unable to parse JSON: $@" if $@;

          $self->{current_keys} = [$self->interpret_json($data)];
        }

        sub intepret_json {
          my($self,$data) = @_;

          die "Subclasses should override interpret_json to parse the response.";
        }

1;

package Google::Auth::IDTokens::X509CertHttpKeySource;
use base 'Google::Auth::IDTokens::HttpKeySource';
      ##
      # A key source that downloads X509 certificates.
      # Used by the legacy OAuth V1 public certs endpoint.
      #

        ##
        # Create a key source that downloads X509 certificates.
        #
        # @param uri [String,URI] The URI from which to download keys.
        # @param algorithm [String] The algorithm to use for signature
        #     verification. Defaults to "`RS256`".
        # @param retry_interval [Integer,nil] Override the retry interval in
        #     seconds. This is the minimum time between retries of failed key
        #     downloads.
        #
        sub new {
          my( $class, $params ) = @_;
          $class = ref $class if ref $class;
          my $self = $class->SUPER::new($params);
          $self->{algorithm} = $algorithm || 'RS256';
          return $self;
        }

        sub interpret_json {
          my($self,$data) = @_;
          return map {
            Google::Auth::IDTokens::KeyInfo->
                new({ id        => $_,
                      key       => $Crypt::X509->new(cert => $data->{$_})->pubkey,
                      algorithm => $self->{algorithm}
                    });
          } keys %$data;
          return @current_keys;
        }

package Google::Auth::IDTokens::JwkHttpKeySource;
use base 'Google::Auth::IDTokens::HttpKeySource';
      ##
      # A key source that downloads a JWK set.
      #
        ##
        # Create a key source that downloads a JWT Set.
        #
        # @param uri [String,URI] The URI from which to download keys.
        # @param retry_interval [Integer,nil] Override the retry interval in
        #     seconds. This is the minimum time between retries of failed key
        #     downloads.
        #
        sub interpret_json {
          my($self,$data) = @_;
          Google::Auth::IDTokens::KeyInfo->from_jwk_set($data);
        }

package Google::Auth::IDTokens::AggregateKeySource;
      ##
      # A key source that aggregates other key sources. This means it will
      # aggregate the keys provided by its constituent sources. Additionally,
      # when asked to refresh, it will refresh all its constituent sources.
      #
        ##
        # Create a key source that aggregates other key sources.
        #
        # @param sources [Array<key source>] The key sources to aggregate.
        #
        sub new {
          my( $class, $params ) = @_;
          $class = ref $class if ref $class;
          my $self = bless { sources => [@{$params->{sources}}] }, $class;
          return $self;
        }

        ##
        # Return the current keys, without attempting to refresh.
        #
        # @return [Array<KeyInfo>]
        #
        sub current_keys {
          my @current_keys_set;
          foreach my $source ( @{$self->{sources}} ){
            push(@current_keys_set, $source->current_keys);
          }
          return @current_keys_set;
        }

        ##
        # Attempt to refresh keys and return the new keys.
        #
        # @return [Array<KeyInfo>]
        # @raise [KeySourceError] if key retrieval failed.
        #
        sub current_keys {
          my @current_keys_set;
          foreach my $source ( @{$self->{sources}} ){
            eval { $source->refresh_keys(); };
            die "KeySourceError: $@" if $@;
            push(@current_keys_set, $source->current_keys);
          }
          return @current_keys_set;
        }
