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
    digest
    paths
    filenames
    hashes
));

use constant ID_SHA256 => '2.16.840.1.101.3.4.2.1';

use constant RSC_ASN1 => q<
RpkiSignedChecklist ::= SEQUENCE {
    version [0] INTEGER OPTIONAL, -- DEFAULT 0,
    resources             ResourceBlock,
    digestAlgorithm       AlgorithmIdentifier,
    checkList             SEQUENCE OF FileAndHash
    }

ResourceBlock       ::= SEQUENCE {
    asList       [0]       AsList OPTIONAL,
    ipAddrBlocks [1]       IPList OPTIONAL }
    -- at least one of asList or ipAddrBlocks must be present

AsList              ::= SEQUENCE OF ASIdOrRange

ASIdOrRange         ::= CHOICE {
    id                   ASId,
    range                ASRange }

ASRange             ::= SEQUENCE {
    min                  ASId,
    max                  ASId }

ASId                ::= INTEGER

IPList              ::= SEQUENCE OF IPAddressFamily

IPAddressFamily     ::= SEQUENCE {    -- AFI & optional SAFI --
    addressFamily        OCTET STRING, -- (SIZE (2..3)),
    addressesOrRanges    SEQUENCE OF IPAddressOrRange }

IPAddressOrRange    ::= CHOICE {
    addressPrefix        IPAddress,
    addressRange         IPAddressRange }

IPAddressRange      ::= SEQUENCE {
    min                  IPAddress,
    max                  IPAddress }

IPAddress           ::= BIT STRING

AlgorithmIdentifier  ::= SEQUENCE {
    algorithm            OBJECT IDENTIFIER,
    parameters           ANY DEFINED BY algorithm OPTIONAL }

FileAndHash ::= SEQUENCE {
    file            IA5String,
    hash            OCTET STRING }
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
    
    $data->{'version'} = $self->version();
    
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
                    map {
                        encode_ip_range_or_prefix($_)
                    } @ipv4_ranges
                ] };
    }
    if (@ipv6_ranges) {
        $resources->{'ipAddrBlocks'} ||= [];
        push @{$resources->{'ipAddrBlocks'}},
            { addressFamily => "\x00\x02",
                addressesOrRanges => [
                    map {
                        encode_ip_range_or_prefix($_)
                    } @ipv6_ranges
                ] };
    }
    if (@asn_ranges) {
        $resources->{'asList'} = [
            map {
                my $s = $_;
                ($s->[0] == $s->[1])
                    ? +{ id => $s->[0] }
                    : +{ range => { min => $s->[0], max => $s->[1] } }
            } @asn_ranges
        ];
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
    my %seen_filenames;
    my $paths_ref = $self->paths();
    my @paths = (ref $paths_ref ? @{$paths_ref} : $paths_ref);
    for my $path (@paths) {
        my ($digest) = `sha256sum $path`;
        chomp $digest;
        $digest =~ s/ .*//;
        my $filename = basename($path);
        my $hash = pack('H*', $digest);
        push @checklist, { 
            file => $filename,
            hash => $hash,
        };
        push @filenames, $filename; 
        push @hashes, $hash;
        if ($seen_filenames{$filename}) {
            die "Filename '$filename' already in RSC.\n";
        }
        $seen_filenames{$filename} = 1;
    }
    $data->{'checkList'} = \@checklist;
    $self->filenames(@filenames);
    $self->hashes(@hashes);

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

    $self->version($data->{'version'});
    if ($data->{'digestAlgorithm'}->{'algorithm'} eq ID_SHA256) {
        $self->algorithm('SHA256');
    } else {
        die "the only valid algorithm is SHA256 (got '".
            $data->{'digestAlgorithm'}->{'algorithm'}."')";
    }

    my @filenames;
    my @hashes;
    for my $file_details (@{$data->{'checkList'}}) {
        my $filename = $file_details->{'file'};
        my $hash = unpack('H*', $file_details->{'hash'});
        push @filenames, $filename;
        push @hashes, $hash;
    }
    $self->filenames(@filenames);
    $self->hashes(@hashes);

    my $resources = $data->{'resources'};
    my @as_ranges;
    for my $as (@{$resources->{'asList'} || []}) {
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

        my $ar = $ip_range->{'addressesOrRanges'} || [];
        for my $a (@{$ar}) {
            if ($a->{'addressPrefix'}) {
                my ($addr, $len) = @{$a->{'addressPrefix'}};
                push @{$range_ref}, $method->($addr, $len);
            } else {
                my $min = $method->(@{$a->{'addressRange'}->{'min'}});
                my $max = $method->(@{$a->{'addressRange'}->{'max'}});
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
    if ($self->digest() ne $other->digest()) {
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
        (ref $filenames_ref ? @{$filenames_ref} : $filenames_ref);
    my $other_filenames_ref = $other->filenames();
    my @other_filenames =
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
        (ref $hashes_ref ? @{$hashes_ref} : $hashes_ref);
    my $other_hashes_ref = $other->hashes();
    my @other_hashes =
        (ref $other_hashes_ref ? @{$other_hashes_ref} : $other_hashes_ref);
    if (@hashes != @other_hashes) {
        return;
    }
    for (my $i = 0; $i < @hashes; $i++) {
        if ($hashes[$i] ne $other_hashes[$i]) {
            return;
        }
    }

    return 1;
}

1;
