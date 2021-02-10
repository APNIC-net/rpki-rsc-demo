## rpki-rsc

A proof-of-concept for constructing and validating RPKI signed checklists (RSCs).
See [https://www.ietf.org/archive/id/draft-spaghetti-sidrops-rpki-rsc-01.txt](https://www.ietf.org/archive/id/draft-spaghetti-sidrops-rpki-rsc-01.txt).

### Build

    $ docker build -t apnic/rpki-rsc .

### Usage

    $ docker run -it apnic/rpki-rsc /bin/bash

#### Basic RSC

    # setup-ca --name ca --resources 1.0.0.0/8
    # issue-ee --ca-name ca --resources 1.0.0.0/24
    # echo "asdf" > content
    # sign-rsc --ca-name ca --path content --resources 1.0.0.0/24 --out rsc
    # verify-rsc --ca-name ca --path content --in rsc
    Verification succeeded.

#### Digest mismatch

    # setup-ca --name ca --resources 1.0.0.0/8
    # issue-ee --ca-name ca --resources 1.0.0.0/24
    # echo "asdf" > content
    # sign-rsc --ca-name ca --path content --resources 1.0.0.0/24 --out rsc
    # echo "asdf2" > content
    # verify-rsc --ca-name ca --path content --in rsc
    Verification failed: Digest mismatch for 'content'.

#### Resource mismatch

    # setup-ca --name ca --resources 1.0.0.0/8
    # issue-ee --ca-name ca --resources 1.0.0.0/24
    # echo "asdf" > content
    # sign-rsc --ca-name ca --path content --resources 2.0.0.0/24 --out rsc
    # verify-rsc --ca-name ca --path content --in rsc
    Verification failed: IPv4 resource mismatch.

#### No validation path for resources

    # setup-ca --name ca --resources 1.0.0.0/8
    # issue-ee --ca-name ca --resources 2.0.0.0/24
    # echo "asdf" > content
    # sign-rsc --ca-name ca --path content --resources 2.0.0.0/24 --out rsc
    # verify-rsc --ca-name ca --path content --in rsc
    Verification failed: Verification failure ... RFC 3779 resource
    not subset of parent's resources.

#### Incorrect TA for verification

    # setup-ca --name ca --resources 1.0.0.0/8
    # issue-ee --ca-name ca --resources 1.0.0.0/24
    # echo "asdf" > content
    # sign-rsc --ca-name ca --path content --resources 1.0.0.0/24 --out rsc
    # setup-ca --name ca2 --resources 1.0.0.0/8
    # verify-rsc --ca-name ca2 --path content --in rsc
    Verification failed: Verification failure ... unable to get local
    issuer certificate.

#### RSC under tree

    # setup-ca --name ca --resources 1.0.0.0/8
    # setup-ca --name ca2 --resources 1.0.0.0/16 --parent-name ca
    # issue-ee --ca-name ca2 --resources 1.0.0.0/24
    # echo "asdf" > content
    # sign-rsc --ca-name ca2 --path content --resources 1.0.0.0/24 --out rsc
    # show-ca-cert --name ca > ca-certs.pem
    # show-ca-cert --name ca2 >> ca-certs.pem
    # verify-rsc --ca-cert-path ca-certs.pem --path content --in rsc
    Verification succeeded.

#### RSC provided out-of-band

    # verify-rsc --ca-cert-path ./ca-certs.pem --path content --in rta
    Verification succeeded.

### Todo

   - More CMS validity checks.
   - Documentation/tidying of code.

### License

See [LICENSE](./LICENSE).
