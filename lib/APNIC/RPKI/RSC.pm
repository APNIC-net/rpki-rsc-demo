package APNIC::RPKI::RSC;

use warnings;
use strict;

use Convert::ASN1;
use Net::IP;
use Set::IntSpan;
use Net::CIDR::Set;
use File::Basename;
use base qw(Class::Accessor);
APNIC::RPKI::RSC->mk_accessors(qw(
    version
    ipv4
    ipv6
    asn
    algorithm
    paths
    paths_unnamed
    filenames
    hashes
    hashes_unnamed
));

use constant ID_SHA256 => '2.16.840.1.101.3.4.2.1';

use constant RSC_ASN1 => q<
RpkiSignedChecklist ::= SEQUENCE {
    version [0] INTEGER OPTIONAL, -- DEFAULT 0,
    resources             ResourceBlock,
    digestAlgorithm       AlgorithmIdentifier,
    checkList             SEQUENCE OF FileNameAndHash
    }

ResourceBlock       ::= SEQUENCE {
    asID         [0]       ConstrainedASIdentifiers OPTIONAL,
    ipAddrBlocks [1]       ConstrainedIPAddrBlocks OPTIONAL }
    -- at least one of asList or ipAddrBlocks must be present

ConstrainedIPAddrBlocks     ::= SEQUENCE OF ConstrainedIPAddressFamily

ConstrainedIPAddressFamily   ::= SEQUENCE { -- AFI & opt SAFI --
    addressFamily        OCTET STRING, -- (SIZE (2)),
    addressesOrRanges    SEQUENCE OF IPAddressOrRange }

ConstrainedASIdentifiers    ::= SEQUENCE {
    asnum               [0] SEQUENCE OF ASIdOrRange }

ASIdOrRange         ::= CHOICE {
    id                   ASId,
    range                ASRange }

ASRange             ::= SEQUENCE {
    min                  ASId,
    max                  ASId }

ASId                ::= INTEGER

IPAddressOrRange    ::= CHOICE {
    addressPrefix        IPAddress,
    addressRange         IPAddressRange }

IPAddressRange      ::= SEQUENCE {
    min                  IPAddress,
    max                  IPAddress }

IPAddress           ::= BIT STRING

AlgorithmIdentifier ::= SEQUENCE {
    algorithm            OBJECT IDENTIFIER,
    parameters           ANY DEFINED BY algorithm OPTIONAL }

FileNameAndHash     ::= SEQUENCE {
    fileName             IA5String OPTIONAL,
    hash                 OCTET STRING }
>;

sub new
{
    my ($class) = @_;

    my $parser = Convert::ASN1->new();
    $parser->configure(
	encoding   => "DER",
	encode     => { time => "utctime" },
	decode     => { time => "utctime" },
	tagdefault => "EXPLICIT",
    );
    my $res = $parser->prepare(RSC_ASN1());
    if (not $res) {
        die $parser->error();
    }
    $parser = $parser->find('RpkiSignedChecklist');

    my $self = { parser => $parser };
    bless $self, $class;
    return $self;
}

sub _match_length
{
    my ( $lhs, $rhs ) = @_;

    my $bit;

    my $len = length($lhs);
    $len == length($rhs)
        or die "both binary strings must have the same length";

    $len--;

    for ( $bit = 0 ; $bit <= $len ; $bit++ ) {
        if ( substr( $lhs, $bit, 1 ) ne substr( $rhs, $bit, 1 ) ) {
            return $bit;
        }
    }

    return $bit;
}

sub _bin_string_to_num
{
    my ($val) = @_;

    my $len  = length($val) - 1;
    my $xval = 0;
    my $pval = 0;

    for ( my $i = 0 ; $i <= $len ; $i++ ) {
        $xval = $pval << 1;
        $pval = ( $xval + ( ( substr( $val, $i, 1 ) eq "1" ) ? 1 : 0 ) );
    }
    return $pval;
}

sub _encode_ipaddr
{
    my ( $val, $zlen ) = @_;

    my $dval;

    my $octets = do { use integer; ( $zlen + 7 ) / 8 };

    for ( my $i = 0 ; $i < $octets ; $i++ ) {
        my $oct = substr( $val, $i * 8, 8 );
        my $bval = _bin_string_to_num($oct);
        $dval .= chr($bval);
    }

    return [ $dval, $zlen ];
}

sub _match_bits_from_end
{
    my ( $val, $from, $match ) = @_;

    my $bit = 0;

    my $len = length($val) - 1;

    for ( $bit = $len ; $bit >= $from ; $bit-- ) {
        if ( substr( $val, $bit, 1 ) ne $match ) {
            return ($bit);
        }
    }
    return $bit;
}

sub encode_ip_range_or_prefix
{
    my ($in) = @_;

    my $result;

    my $ip = Net::IP->new($in);

    my $fam = $ip->version;

    my $type = "ipv$fam";

    my $sbits = $ip->binip();
    my $ebits = $ip->last_bin();
    my $size  = length($ebits);

    my $en = _match_length( $sbits, $ebits );

    my $zeropos = _match_bits_from_end( $sbits, $en, 0 );
    my $start = _encode_ipaddr( $sbits, $zeropos + 1 );

    if (    substr( $sbits, $en ) =~ /^0*$/
        and substr( $ebits, $en ) =~ /^1*$/ ) {
        $ip->prefixlen and $ip->prefixlen > 0
            or die "expected a prefix and there is no prefixlen!";

        return { addressPrefix => $start };
    } else {
        !$ip->prefixlen
            or die "expected a range and there is a prefixlen!";
        my $onepos = _match_bits_from_end( $ebits, $en, 1 );
        my $end = _encode_ipaddr( $ebits, $onepos + 1 );

        return { addressRange => { min => $start, max => $end } };
    }
}

sub encode
{
    my ($self) = @_;

    my $data = {};

    if ($self->version() != 0) {
        $data->{'version'} = $self->version();
    }

    my $ipv4_set = $self->ipv4();
    my @ipv4_ranges;
    if ($ipv4_set) {
        @ipv4_ranges = $ipv4_set->as_array($ipv4_set->iterate_ranges());
    }

    my $ipv6_set = $self->ipv6();
    my @ipv6_ranges;
    if ($ipv6_set) {
        @ipv6_ranges = $ipv6_set->as_array($ipv6_set->iterate_ranges());
    }

    my $asn_set = $self->asn();
    my @asn_ranges;
    if ($asn_set) {
        @asn_ranges = $asn_set->spans();
    }

    my $resources = {};
    if (@ipv4_ranges) {
        $resources->{'ipAddrBlocks'} ||= [];
        push @{$resources->{'ipAddrBlocks'}},
             { addressFamily => "\x00\x01",
               addressesOrRanges => [
                   map { encode_ip_range_or_prefix($_) }
                       @ipv4_ranges
               ] };
    }
    if (@ipv6_ranges) {
        $resources->{'ipAddrBlocks'} ||= [];
        push @{$resources->{'ipAddrBlocks'}},
             { addressFamily => "\x00\x02",
               addressesOrRanges => [
                   map { encode_ip_range_or_prefix($_) }
                       @ipv6_ranges
               ] };
    }
    if (@asn_ranges) {
        $resources->{'asID'} = {
            asnum => [
                map {
                    my $s = $_;
                    ($s->[0] == $s->[1])
                        ? +{ id => $s->[0] }
                        : +{ range => { min => $s->[0], max => $s->[1] } }
                } @asn_ranges
            ]
        };
    }

    $data->{'resources'} = $resources;

    if ($self->algorithm() eq 'SHA256') {
        $data->{'digestAlgorithm'} = {
            algorithm => ID_SHA256
        };
    } else {
        die "the only valid algorithm is SHA256 (got '".
            $self->algorithm()."')";
    }

    my @checklist;
    my @filenames;
    my @hashes;
    my @hashes_unnamed;
    my %seen_filenames;
    my %seen_hashes_unnamed;
    my $paths_ref = $self->paths();
    my @paths =
        grep { defined $_ }
            (ref $paths_ref
                ? @{$paths_ref}
                : $paths_ref);
    for my $path (@paths) {
        my ($digest) = `sha256sum $path`;
        chomp $digest;
        $digest =~ s/ .*//;
        my $filename = basename($path);
        my $hash = pack('H*', $digest);
        push @checklist, {
            fileName => $filename,
            hash => $hash,
        };
        push @filenames, $filename;
        push @hashes, $hash;
        if ($seen_filenames{$filename}) {
            die "Filename '$filename' already in RSC.\n";
        }
        $seen_filenames{$filename} = 1;
    }
    my $paths_unnamed_ref = $self->paths_unnamed();
    my @paths_unnamed =
        grep { defined $_ }
            (ref $paths_unnamed_ref
                ? @{$paths_unnamed_ref}
                : $paths_unnamed_ref);
    for my $path_unnamed (@paths_unnamed) {
        my ($digest) = `sha256sum $path_unnamed`;
        chomp $digest;
        $digest =~ s/ .*//;
        my $hash = pack('H*', $digest);
        # Permit duplicate hashes to be entered here for testing.
        push @checklist, {
            hash => $hash,
        };
        push @hashes_unnamed, $hash;
        if ($seen_hashes_unnamed{$hash}) {
            die "Hash '$hash' already in RSC.\n";
        }
        $seen_hashes_unnamed{$hash} = 1;
    }
    $data->{'checkList'} = \@checklist;
    $self->filenames(@filenames);
    $self->hashes(@hashes);
    $self->hashes_unnamed(\@hashes_unnamed);

    my $parser = $self->{'parser'};
    my $rsc = $parser->encode($data);
    if (not $rsc) {
        die $parser->error();
    }

    return $rsc;
}

sub decode_ipv4_addr
{
    my ($addr, $len) = @_;

    my @octets = map { ord($_) } split //, $addr;
    my $extra = (4 - @octets);
    while ($extra--) {
        push @octets, 0;
    }
    my $prefix = (join '.', @octets).'/'.$len;
    return $prefix;
}

sub decode_ipv6_addr
{
    my ($addr, $len) = @_;

    my @octets = map { ord($_) } split //, $addr;
    my $extra = (16 - @octets);
    while ($extra--) {
        push @octets, 0;
    }
    my @parts;
    for (my $i = 0; $i < 16; $i += 2) {
        push @parts, sprintf("%02x%02x", $octets[$i], $octets[$i+1]);
    }
    $addr = join ':', @parts;
    return $addr.'/'.$len;
}

sub decode
{
    my ($self, $rsc) = @_;

    my $parser = $self->{'parser'};
    my $data = $parser->decode($rsc);
    if (not $data) {
        die $parser->error();
    }

    if (exists $data->{'version'}) {
        $self->version($data->{'version'});
    } else {
        $self->version(0);
    }
    if ($data->{'digestAlgorithm'}->{'algorithm'} eq ID_SHA256) {
        $self->algorithm('SHA256');
    } else {
        die "the only valid algorithm is SHA256 (got '".
            $data->{'digestAlgorithm'}->{'algorithm'}."')";
    }

    my @filenames;
    my @hashes;
    my @hashes_unnamed;
    for my $file_details (@{$data->{'checkList'}}) {
        my $filename = $file_details->{'fileName'};
        my $hash = $file_details->{'hash'};
        if ($filename) {
            push @filenames, $filename;
            push @hashes, $hash;
        } else {
            push @hashes_unnamed, $hash;
        }
    }
    $self->filenames(@filenames);
    $self->hashes(@hashes);
    $self->hashes_unnamed(@hashes_unnamed);

    my $resources = $data->{'resources'};
    my @as_ranges;
    for my $as (@{$resources->{'asID'}->{'asnum'} || []}) {
        if ($as->{'id'}) {
            push @as_ranges, $as->{'id'};
        } else {
            push @as_ranges, $as->{'range'}->{'min'}.'-'.$as->{'range'}->{'max'};
        }
    }
    $self->asn(Set::IntSpan->new((join ',', @as_ranges)));

    my @ipv4_ranges;
    my @ipv6_ranges;
    for my $ip_range (@{$resources->{'ipAddrBlocks'} || []}) {
        my ($method, $range_ref) =
            ($ip_range->{'addressFamily'} eq "\x00\x01")
                ? (\&decode_ipv4_addr, \@ipv4_ranges)
                : (\&decode_ipv6_addr, \@ipv6_ranges);

        my $addresses_or_ranges = $ip_range->{'addressesOrRanges'} || [];
        for my $ar (@{$addresses_or_ranges}) {
            if ($ar->{'addressPrefix'}) {
                my ($addr, $len) = @{$ar->{'addressPrefix'}};
                push @{$range_ref}, $method->($addr, $len);
            } else {
                my $min = $method->(@{$ar->{'addressRange'}->{'min'}});
                my $max = $method->(@{$ar->{'addressRange'}->{'max'}});
                $min =~ s/\/.*//;
                $max =~ s/\/.*//;
                push @{$range_ref}, $min.'-'.$max;
            }
        }
    }

    if (@ipv4_ranges) {
        $self->ipv4(Net::CIDR::Set->new({type => 'ipv4'}, (join ',', @ipv4_ranges)));
    } else {
        $self->ipv4(undef);
    }
    if (@ipv6_ranges) {
        $self->ipv6(Net::CIDR::Set->new({type => 'ipv6'}, (join ',', @ipv6_ranges)));
    } else {
        $self->ipv6(undef);
    }

    return 1;
}

sub equals
{
    my ($self, $other) = @_;

    if ($self->version() != $other->version()) {
        return;
    }
    if ($self->algorithm() ne $other->algorithm()) {
        return;
    }
    if ($self->ipv4() xor $other->ipv4()) {
        return;
    }
    if ($self->ipv4()) {
        if (not $self->ipv4()->equals($other->ipv4())) {
            return;
        }
    }
    if ($self->ipv6() xor $other->ipv6()) {
        return;
    }
    if ($self->ipv6()) {
        if (not $self->ipv6()->equals($other->ipv6())) {
            return;
        }
    }
    if ($self->asn() xor $other->asn()) {
        return;
    }
    if ($self->asn()) {
        if (not $self->asn() eq $other->asn()) {
            return;
        }
    }
    my $filenames_ref = $self->filenames();
    my @filenames =
        grep { defined $_ }
            (ref $filenames_ref ? @{$filenames_ref} : $filenames_ref);
    my $other_filenames_ref = $other->filenames();
    my @other_filenames =
        grep { defined $_ }
            (ref $other_filenames_ref ? @{$other_filenames_ref} : $other_filenames_ref);
    if (@filenames != @other_filenames) {
        return;
    }
    for (my $i = 0; $i < @filenames; $i++) {
        if ($filenames[$i] ne $other_filenames[$i]) {
            return;
        }
    }

    my $hashes_ref = $self->hashes();
    my @hashes =
        grep { defined $_ }
            (ref $hashes_ref ? @{$hashes_ref} : $hashes_ref);
    my $other_hashes_ref = $other->hashes();
    my @other_hashes =
        grep { defined $_ }
            (ref $other_hashes_ref ? @{$other_hashes_ref} : $other_hashes_ref);
    if (@hashes != @other_hashes) {
        return;
    }
    for (my $i = 0; $i < @hashes; $i++) {
        if ($hashes[$i] ne $other_hashes[$i]) {
            return;
        }
    }

    my $hashes_unnamed_ref = $self->hashes_unnamed();
    my @hashes_unnamed =
        grep { defined $_ }
            (ref $hashes_unnamed_ref
                ? @{$hashes_unnamed_ref}
                : $hashes_unnamed_ref);
    my $other_hashes_unnamed_ref = $other->hashes_unnamed();
    my @other_hashes_unnamed =
        grep { defined $_ }
            (ref $other_hashes_unnamed_ref
                ? @{$other_hashes_unnamed_ref}
                : $other_hashes_unnamed_ref);
    if (@hashes_unnamed != @other_hashes_unnamed) {
        return;
    }
    for (my $i = 0; $i < @hashes_unnamed; $i++) {
        if ($hashes_unnamed[$i] ne $other_hashes_unnamed[$i]) {
            return;
        }
    }

    return 1;
}

1;
