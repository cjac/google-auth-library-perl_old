# frozen_string_literal: true
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

package Google::Auth::IDTokens::Verifier;

use strict;
use warnings;

use URI;
use DateTime;
use JSON::XS;
use Mutex;
use HTTP::Request::Common;
use LWP::UserAgent;
use Crypt::PK::ECC;
use Crypt::PK::RSA;
use Crypt::X509;

our $VERSION = 0.02;

1;
