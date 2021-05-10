package APNIC::RPKI::CA;

use warnings;
use strict;

use File::Slurp qw(read_file
                   write_file);
use File::Temp qw(tempdir);
use HTTP::Daemon;
use HTTP::Status qw(:constants);
use MIME::Base64;
use Net::IP;
use LWP::UserAgent;
use Storable;
use XML::LibXML;

use APNIC::RPKI::OpenSSL;
use APNIC::RPKI::Utils qw(system_ad);

use constant CA_CONFIG_PARAMETERS => qw(dir ca root_ca_ext_extra
                                        signing_ca_ext_extra);

use constant CA_CONFIG => <<EOF;
[ default ]
ca                      = root-ca
dir                     = .

[ req ]
default_bits            = 2048
encrypt_key             = yes
default_md              = sha256
utf8                    = yes
string_mask             = utf8only
prompt                  = no
distinguished_name      = ca_dn
req_extensions          = ca_reqext

[ ca_dn ]
commonName              = "Simple Root CA"

[ ca_reqext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash

[ pqs ]
policyIdentifier        = 1.3.6.1.5.5.7.14.2

[ ca ]
default_ca              = root_ca

[ root_ca ]
certificate             = {dir}/ca/{ca}.crt
private_key             = {dir}/ca/{ca}/private/{ca}.key
new_certs_dir           = {dir}/ca/{ca}
serial                  = {dir}/ca/{ca}/db/{ca}.crt.srl
crlnumber               = {dir}/ca/{ca}/db/{ca}.crl.srl
database                = {dir}/ca/{ca}/db/{ca}.db
unique_subject          = no
default_days            = 3652
default_md              = sha256
policy                  = match_pol
email_in_dn             = no
preserve                = no
name_opt                = ca_default
cert_opt                = ca_default
copy_extensions         = none
x509_extensions         = signing_ca_ext
default_crl_days        = 365
crl_extensions          = crl_ext

[ match_pol ]
commonName              = supplied

[ any_pol ]
domainComponent         = optional
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional

[ root_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always
certificatePolicies     = critical,\@pqs
{root_ca_ext_extra}

[ signing_ca_ext ]
keyUsage                = critical,digitalSignature
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always
certificatePolicies     = critical,\@pqs
{signing_ca_ext_extra}

[ crl_ext ]
authorityKeyIdentifier  = keyid:always
EOF

use constant EE_CSR_FILENAME  => 'ee.csr';
use constant EE_CERT_FILENAME => 'ee.crt';
use constant EE_KEY_FILENAME  => 'ee.key';
use constant CRL_FILENAME     => 'crl.pem';

use constant ID_SMIME  => '1.2.840.113549.1.9.16';
use constant ID_CT     => ID_SMIME . '.1';
use constant ID_CT_XML => ID_CT . '.28';
use constant ID_CT_RSC => '1.2.840.113549.1.9.16.1.48';

our $DEBUG = 0;

our $VERSION = '0.1';

sub new
{
    my $class = shift;

    my %args = @_;
    my $self = \%args;
    bless $self, $class;

    if (not $self->{'ca_path'}) {
        die "'ca_path' argument must be provided.";
    }
    if (not $self->{'openssl'}) {
        $self->{'openssl'} = APNIC::RPKI::OpenSSL->new();
    }

    return $self;
}

sub _chdir_ca
{
    my ($self) = @_;

    chdir $self->{'ca_path'} or die $!;

    return 1;
}

sub _system
{
    my (@args) = @_;

    my $cmd = join " ", @args;

    return system_ad($cmd, $DEBUG);
}

sub is_initialised
{
    my ($self) = @_;

    $self->_chdir_ca();

    return (-e "ca.cnf");
}

sub _generate_config
{
    my ($self, %parameters) = @_;

    my $config = CA_CONFIG();
    my $ca_path = $self->{'ca_path'};
    $config =~ s/{dir}/$ca_path/g;
    $config =~ s/{ca}/ca/g;

    for my $key (keys %parameters) {
        my $value = $parameters{$key};
        $config =~ s/{$key}/$value/g;
    }

    for my $key (CA_CONFIG_PARAMETERS()) {
        $config =~ s/{$key}//g;
    }

    write_file('ca.cnf', $config);

    return 1;
}

sub initialise
{
    my ($self, $common_name, $key_only) = @_;

    $self->_chdir_ca();

    if ($self->is_initialised()) {
        die "CA has already been initialised.";
    }

    $self->_generate_config();

    for my $dir (qw(newcerts ca ca/ca ca/ca/private ca/ca/db)) {
        mkdir $dir or die $!;
    }
    for my $file (qw(ca/ca/db/ca.db ca/ca/db/ca.db.attr index.txt)) {
        _system("touch $file");
    }
    for my $serial_file (qw(ca.crt.srl ca.crl.srl)) {
        write_file("ca/ca/db/$serial_file", "01");
    }

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl genrsa -out ca/ca/private/ca.key 2048");
    if (not $key_only) {
        _system("$openssl req -new -x509 -key ca/ca/private/ca.key -out ca/ca.crt -subj '/CN=$common_name'");
    }

    return 1;
}

sub get_ca_request
{
    my ($self, $common_name, $ip_resources, $as_resources) = @_;

    $self->_chdir_ca();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl req -new -key ca/ca/private/ca.key -out ca/ca.req -subj '/CN=$common_name'");

    my $data = read_file('ca/ca.req');
    return $data;
}

sub _generate_sbgp_config
{
    my ($self, $ip_resources, $as_resources) = @_;

    my $ipv4_index = 0;
    my $ipv6_index = 0;

    my @ip_lines;
    for my $ip_resource (@{$ip_resources}) {
        my $type = Net::IP->new($ip_resource)->version();
        if ($type == 4) {
            push @ip_lines, "IPv4.$ipv4_index = $ip_resource";
            $ipv4_index++;
        } else {
            push @ip_lines, "IPv6.$ipv6_index = $ip_resource";
            $ipv6_index++;
        }
    }

    my $ip_content =
        (@ip_lines)
            ? "[ ip-section ]\n".(join "\n", @ip_lines)."\n\n"
            : "";

    my $as_index = 0;
    my @as_lines;
    for my $as_resource (@{$as_resources}) {
        push @as_lines, "AS.$as_index = $as_resource";
        $as_index++;
    }

    my $as_content =
        (@as_lines)
            ? "[ as-section ]\n".(join "\n", @as_lines)."\n\n"
            : "";

    my @preliminary = (
        ((@ip_lines)
            ? 'sbgp-ipAddrBlock = critical, @ip-section'
            : ''),
        ((@as_lines)
            ? 'sbgp-autonomousSysNum = critical, @as-section'
            : '')
    );

    return
        join "\n",
            ((@preliminary), "\n", $ip_content, $as_content);
}

sub sign_ca_request
{
    my ($self, $request, $ip_resources, $as_resources) = @_;

    $self->_chdir_ca();

    $ip_resources ||= [];
    $as_resources ||= [];

    my $extra = $self->_generate_sbgp_config($ip_resources, $as_resources);

    $self->_generate_config(root_ca_ext_extra => $extra);

    my $ft_request = File::Temp->new();
    print $ft_request $request;
    $ft_request->flush();
    my $fn_request = $ft_request->filename();

    my $ft_output = File::Temp->new();
    my $fn_output = $ft_output->filename();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl ca -batch -config ca.cnf -extensions root_ca_ext ".
            "-out $fn_output ".
            "-in $fn_request -days 365");

    my $data = read_file($fn_output);
    return $data;
}

sub install_ca_certificate
{
    my ($self, $certificate) = @_;

    $self->_chdir_ca();

    my $ft_cert = File::Temp->new();
    print $ft_cert $certificate;
    $ft_cert->flush();
    my $fn_cert = $ft_cert->filename();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl x509 -in $fn_cert -out ca/ca.crt");

    return 1;
}

sub revoke_current_ee_certificate
{
    my ($self) = @_;

    $self->_chdir_ca();

    if (-e "ee.crt") {
        my $openssl = $self->{'openssl'}->get_openssl_path();
        _system("$openssl ca -batch -config ca.cnf ".
                "-revoke ".EE_CERT_FILENAME());
    }

    return 1;
}

sub issue_new_ee_certificate
{
    my ($self, $ip_resources, $as_resources) = @_;

    $self->_chdir_ca();

    $ip_resources ||= [];
    $as_resources ||= [];

    my $extra = $self->_generate_sbgp_config($ip_resources, $as_resources);

    $self->_generate_config(signing_ca_ext_extra => $extra);

    $self->revoke_current_ee_certificate();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl genrsa ".
            "-out ".EE_KEY_FILENAME()." 2048");
    _system("$openssl req -new ".
            "-key ".EE_KEY_FILENAME()." ".
            "-out ".EE_CSR_FILENAME()." ".
            "-subj '/CN=EE'");
    _system("$openssl ca -batch -config ca.cnf ".
            "-out ".EE_CERT_FILENAME()." ".
            "-extensions signing_ca_ext ".
            "-in ".EE_CSR_FILENAME()." -days 365");

    my $data = read_file(EE_CERT_FILENAME());

    return $data;
}

sub issue_crl
{
    my ($self) = @_;

    $self->_chdir_ca();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl ca -batch -crlexts crl_ext -config ca.cnf -gencrl ".
            "-out ".CRL_FILENAME());

    return 1;
}

sub get_crl
{
    my ($self) = @_;

    $self->_chdir_ca();

    my $data = read_file(CRL_FILENAME());
    return $data;
}

sub get_ee
{
    my ($self) = @_;

    $self->_chdir_ca();

    my $data = read_file(EE_CERT_FILENAME());
    return $data;
}

sub cycle
{
    my ($self) = @_;

    $self->issue_new_ee_certificate();
    $self->issue_crl();

    return 1;
}

sub sign_cms_rsc
{
    my ($self, $input) = @_;

    $self->_chdir_ca();

    my $ft_input = File::Temp->new();
    print $ft_input $input;
    $ft_input->flush();
    my $fn_input = $ft_input->filename();

    my $ft_output= File::Temp->new();
    my $fn_output = $ft_output->filename();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    my $res = _system("$openssl cms -sign -nodetach -binary -outform DER ".
                      "-nosmimecap ".
                      "-keyid -md sha256 -econtent_type ".ID_CT_RSC()." ".
                      "-signer ".EE_CERT_FILENAME()." ".
                      "-inkey ".EE_KEY_FILENAME()." ".
                      "-in $fn_input -out $fn_output");

    return read_file($fn_output);
}

sub get_ca_pem
{
    my ($self) = @_;

    $self->_chdir_ca();

    my @lines = read_file('ca/ca.crt');

    pop @lines;
    shift @lines;

    my $bpki_ta = join '', @lines;
    chomp $bpki_ta;

    return $bpki_ta;
}

sub get_issuer
{
    my ($self) = @_;

    $self->_chdir_ca();

    my $openssl_path = $self->{'openssl'}->{'path'};
    my ($issuer) = `$openssl_path x509 -in ca/ca.crt -noout -issuer`;
    chomp $issuer;
    $issuer =~ s/.*=//;
    return $issuer;
}

sub get_subject
{
    my ($self) = @_;

    $self->_chdir_ca();

    my $openssl_path = $self->{'openssl'}->{'path'};
    my ($subject) = `$openssl_path x509 -in ca/ca.crt -noout -subject`;
    chomp $subject;
    $subject =~ s/.*=//;
    return $subject;
}

1;
