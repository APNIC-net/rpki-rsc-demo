#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RSC;
use Net::CIDR::Set;
use Set::IntSpan;

use Test::More tests => 2;

{
    my @ipv4_resources = qw(1.0.0.0/8);
    my @ipv6_resources = qw(2000::/16);
    my @as_resources = qw(1 2 3 4);
    my @paths_unnamed = qw(./t/00-load.t);

    my $rsc = APNIC::RPKI::RSC->new();
    $rsc->version(0);
    $rsc->ipv4(Net::CIDR::Set->new({type => 'ipv4'}, (join ',', @ipv4_resources)));
    $rsc->ipv6(Net::CIDR::Set->new({type => 'ipv6'}, (join ',', @ipv6_resources)));
    $rsc->asn(Set::IntSpan->new((join ',', @as_resources)));
    $rsc->paths_unnamed(@paths_unnamed);
    $rsc->algorithm('SHA256');

    my $rsc_encoded = $rsc->encode();

    my $rsc2 = APNIC::RPKI::RSC->new();
    $rsc2->decode($rsc_encoded);

    ok($rsc->equals($rsc2),
        'RSC encodes/decodes correctly (unnamed paths)');
}

{
    my @ipv4_resources = qw(1.0.0.0/8);
    my @ipv6_resources = qw(2000::/16);
    my @as_resources = qw(1 2 3 4);
    my @paths = qw(./t/10-basic.t);
    my @paths_unnamed = qw(./t/00-load.t);

    my $rsc = APNIC::RPKI::RSC->new();
    $rsc->version(0);
    $rsc->ipv4(Net::CIDR::Set->new({type => 'ipv4'}, (join ',', @ipv4_resources)));
    $rsc->ipv6(Net::CIDR::Set->new({type => 'ipv6'}, (join ',', @ipv6_resources)));
    $rsc->asn(Set::IntSpan->new((join ',', @as_resources)));
    $rsc->paths(@paths);
    $rsc->paths_unnamed(@paths_unnamed);
    $rsc->algorithm('SHA256');

    my $rsc_encoded = $rsc->encode();

    my $rsc2 = APNIC::RPKI::RSC->new();
    $rsc2->decode($rsc_encoded);

    ok($rsc->equals($rsc2),
        'RSC encodes/decodes correctly (named and unnamed paths)');
}

1;
