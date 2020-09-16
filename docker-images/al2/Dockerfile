ARG AL_VERSION=2

FROM amazonlinux:${AL_VERSION}

ARG OPENSSL_VERSION=openssl-1.1.1
ARG GCC_VERSION=7
ARG ZSH_THEME=cypher

ENV S2N_LIBCRYPTO=${OPENSSL_VERSION} \
    GCC_VERSION=${GCC_VERSION} \
    OPENSSL_VERSION=${OPENSSL_VERSION}

RUN set -ex; \
    yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm; \
    amazon-linux-extras install ruby2.6 rust1; \
    amazon-linux-extras enable epel;\
    amazon-linux-extras enable corretto8; \
    yum install -y openssh-clients; \
    rpm --import https://download.mono-project.com/repo/xamarin.gpg; \
    curl https://download.mono-project.com/repo/centos7-stable.repo | tee /etc/yum.repos.d/mono-centos7-stable.repo; \
    yum groupinstall -y "Development tools";

# These packages are mutually exclusive, and we need the lateset installed before depenedencies.
RUN yum erase -y openssl-devel; yum install -y openssl11-devel
RUN set -ex; \
    yum install -y --skip-broken GeoIP-devel ImageMagick asciidoc bzip2-devel bzr bzrtools cmake3 cvs cvsps \
    docbook-dtds docbook-style-xsl dpkg-dev e2fsprogs expat-devel expect fakeroot \
    glib2-devel groff gzip icu iptables jq krb5-server libargon2-devel \
    libcurl-devel libdb-devel libedit-devel libevent-devel libffi-devel \
    libicu-devel libjpeg-devel libpng-devel libserf libsqlite3x-devel \
    libtidy-devel libunwind libwebp-devel libxml2-devel libxslt libxslt-devel \
    libyaml-devel libzip-devel lsb-release mariadb-devel mercurial mlocate mono-devel \
    ncurses-devel ninja-build oniguruma-devel perl-DBD-SQLite \
    perl-DBI perl-HTTP-Date perl-IO-Pty-Easy perl-TimeDate perl-YAML-LibYAML \
    postgresql-devel procps-ng python3 python-tox readline-devel rsync shadow-utils sgml-common \
    subversion-perl sudo tar tcl tk vim wget which valgrind xfsprogs xmlto xz-devel zsh; \
    gem install bundler;

# Our scripts expect these utilities to be named a certain way.  Use symlinks to normalize them.
# Note the use of the compiled from source, not package installed, OpenSSL.
RUN set -exu; \
    update-alternatives --install /usr/bin/ninja ninja /usr/bin/ninja-build 1700; \
    update-alternatives --install /usr/bin/cmake cmake /usr/bin/cmake3 3000; \
    update-alternatives --install /usr/bin/gcc-7 gcc /usr/bin/gcc 700; \
    update-alternatives --install /usr/bin/g++-7 g++ /usr/bin/g++ 700; \
    update-alternatives --install /usr/bin/g++-7 g++ /usr/bin/g++ 700; \
    update-alternatives --install /usr/bin/openssl openssl /test-deps/$OPENSSL_VERSION/bin/openssl 10;

ADD ./bin/* /var/tmp/
ADD codebuild codebuild

# install test dependencies
RUN set -eux; \
  LD_LIBRARY_PATH="" . codebuild/bin/s2n_install_test_dependencies.sh; \
  yum clean all; rm -rf /var/cache/yum;

RUN /var/tmp/manage_users.sh
WORKDIR /home/s2n-dev
CMD ["/bin/zsh","-l"]
