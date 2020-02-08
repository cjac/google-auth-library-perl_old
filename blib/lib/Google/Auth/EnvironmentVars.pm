# Copyright 2019 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package Google::Auth::EnvironmentVars;

use 5.006;
use strict;
use warnings;

=head1 NAME

Google::Auth::EnvironmentVars - Environment variables used by Google::Auth

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

Canonical package for reading environment variables used with Google::Auth

=head1 SUBROUTINES/METHODS

=head2 new

=cut

sub new {
  my $class = $_[0];

  my $self;
  if( ref $class ){
    $self = $class;
    $class = ref $class
  }else{
    $self = {
             PROJECT => $ENV{GOOGLE_CLOUD_PROJECT},
             # Environment variable defining default project.

             # This used by Google::Auth to explicitly set a project
             # ID. This environment variable is also used by the
             # Google Cloud Perl Library.

             LEGACY_PROJECT => $ENV{GCLOUD_PROJECT},
             # Previously used environment variable defining the
             # default project.

             # This environment variable is used instead of the
             # current one in some situations (such as Google App
             # Engine).

             CREDENTIALS => $ENV{GOOGLE_APPLICATION_CREDENTIALS},

             # Environment variable defining the location of Google
             # application default credentials.

             # The environment variable name which can replace
             # ~/.config if set.
             CLOUD_SDK_CONFIG_DIR => $ENV{CLOUDSDK_CONFIG},

             # Environment variable defines the location of Google
             # Cloud SDK's config files.

             # These two variables allow for customization of the addresses used when
             # contacting the GCE metadata service.
             GCE_METADATA_ROOT => $ENV{GCE_METADATA_ROOT},

             # Environment variable providing an alternate hostname or
             # host:port to be used for GCE metadata requests.

             GCE_METADATA_IP => $ENV{GCE_METADATA_IP}

             # Environment variable providing an alternate ip:port to
             # be used for ip-only GCE metadata requests.
            };
  }
  return $self;
}

=head2 function2

=cut

sub function2 {
}

=head1 AUTHOR

C.J. Collier, C<< <cjcollier at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-google-auth-library-perl at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Google-Auth-Library-Perl>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Google::Auth


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Google-Auth-Library-Perl>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Google-Auth-Library-Perl>

=item * CPAN Ratings

L<https://cpanratings.perl.org/d/Google-Auth-Library-Perl>

=item * Search CPAN

L<https://metacpan.org/release/Google-Auth-Library-Perl>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2020 C.J. Collier.

This program is released under the following license: Apache 2.0


=cut

1; # End of Google::Auth
