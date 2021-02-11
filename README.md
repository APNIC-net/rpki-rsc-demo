## rpki-rsc

A proof-of-concept for constructing and validating RPKI signed checklists (RSCs).
See [https://www.ietf.org/archive/id/draft-spaghetti-sidrops-rpki-rsc-01.txt](https://www.ietf.org/archive/id/draft-spaghetti-sidrops-rpki-rsc-01.txt).

For verifying RSCs, the local filename must be the same as that used
in the RSC itself: the verification script does not attempt to match
the files by hash.

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

#### Multiple files

    # setup-ca --name ca --resources 1.0.0.0/8
    # issue-ee --ca-name ca --resources 1.0.0.0/24
    # echo "asdf1" > content1
    # echo "asdf2" > content2
    # sign-rsc --ca-name ca --path content1 --path content2 --resources 1.0.0.0/24 --out rsc
    # verify-rsc --ca-name ca --path content1 --in rsc
    Verification succeeded.
    # verify-rsc --ca-name ca --path content2 --in rsc
    Verification succeeded.
    # verify-rsc --ca-name ca --path content1 --path content2 --in rsc
    Verification succeeded.
    # echo "asdf1" > content3
    # verify-rsc --ca-name ca --path content3 --in rsc
    Verification failed: Unable to find 'content3' in RSC.
    # echo "asdf3" > content1
    # verify-rsc --ca-name ca --path content3 --in rsc
    Verification failed: Digest mismatch for 'content1'.

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

    # verify-rsc --ca-cert-path ./ca-certs.pem --path content --in rsc
    Verification succeeded.

#### RSC signed using out-of-band objects

To generate objects:

    $ docker run -it apnic/rpki.net
    # rpkic create_identity {name}
    (Send {name}.identity.xml to parent RPKI engine, e.g.
    rpki-testbed.apnic.net, and save response to response.xml.)
    # rpkic -i {name} configure_parent response.xml
    (Send {name}.{parent-name}.repository-request.xml to publication
    engine, and save response to repository-response.xml.)
    # rpkic configure_publication_client {name}.{parent-name}.repository-request.xml
    # rpkic -i {name} configure_repository {name}.repository-response.xml
    # rpkic -i {name} force_run_now
    # issue-ee {name} test-ee {resources}

After starting the RSC container:

    $ export RPKI_CONTAINER={rpki.net-container}
    $ export RSC_CONTAINER={rsc-container}
    $ docker cp $RPKI_CONTAINER:/test-ee.pem .
    $ docker cp $RPKI_CONTAINER:/test-ee.pem.key .
    $ docker cp test-ee.pem $RSC_CONTAINER:/
    $ docker cp test-ee.pem.key $RSC_CONTAINER:/

To sign an RSC object:

    # echo "asdf" > content
    # sign-rsc-external \
        --ee-cert test-ee.pem \
        --ee-key test-ee.pem.key \
        --path content \
        --resources {resources} \
        --out rsc

To verify the RSC object:

    # verify-rsc --ca-cert-path ./trusted.pem --path content --in rsc
    Verification succeeded.

### Todo

   - More CMS validity checks.
   - Documentation/tidying of code.

### License

See [LICENSE](./LICENSE).
