FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y
RUN apt-get install -y \
    libhttp-daemon-perl \
    liblist-moreutils-perl \
    libwww-perl \
    libcarp-always-perl \
    libconvert-asn1-perl \
    libclass-accessor-perl \
    cpanminus \
    libssl-dev \
    libyaml-perl \
    libxml-libxml-perl \
    libio-capture-perl \
    libnet-ip-perl \
    make \
    wget \
    patch \
    gcc \
    rsync \
    vim \
    less
COPY cms.diff .
RUN wget https://github.com/openssl/openssl/releases/download/openssl-3.3.1/openssl-3.3.1.tar.gz \
    && tar xf openssl-3.3.1.tar.gz \
    && cd openssl-3.3.1 \
    && patch -p1 < /cms.diff \
    && ./config enable-rfc3779 \
    && make \
    && make install
ENV LD_LIBRARY_PATH /usr/local/lib:/usr/local/lib64
RUN ldconfig
RUN cpanm Set::IntSpan Net::CIDR::Set
COPY . /root/rpki-rsc
RUN cd /root/rpki-rsc/ && perl Makefile.PL && make && make test && make install
COPY rsyncd.conf /etc/
RUN sed -i 's/RSYNC_ENABLE=false/RSYNC_ENABLE=true/' /etc/default/rsync
RUN rm -rf /root/rpki-rsc/
