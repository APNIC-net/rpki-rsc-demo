package APNIC::RPKI::Utils;

use warnings;
use strict;

use File::Slurp qw(read_file);
use File::Temp;

use Exporter qw(import);

our @EXPORT_OK = qw(canonicalise_pem
                    system_ad);

sub canonicalise_pem
{
    my ($pem) = @_;

    $pem =~ s/\s*//g;
    $pem =~ s/(.{1,60})/$1\n/gs;
    chomp $pem;

    return $pem;
}

sub system_ad
{
    my ($cmd, $debug) = @_;

    my $res = system($cmd.($debug ? "" : " >/dev/null 2>&1"));
    if ($res != 0) {
        die "Command execution failed.\n";
    }

    return 1;
}

1;
