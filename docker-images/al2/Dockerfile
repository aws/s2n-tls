ARG AL_VERSION=2

FROM amazonlinux:${AL_VERSION}

WORKDIR /opt/s2n

ARG OPENSSL_VERSION=openssl-1.1.1
ARG GCC_VERSION=7
ARG ZSH_THEME=cypher

ENV S2N_LIBCRYPTO=${OPENSSL_VERSION} \
    GCC_VERSION=${GCC_VERSION} \
    BUILD_S2N=true \
    TESTS=integration \

# set up user account
RUN set -ex; \
    amazon-linux-extras install ruby2.6 rust1; \
    amazon-linux-extras enable epel;\
    amazon-linux-extras enable corretto8; \
    yum install -y openssh-clients; \
    rpm --import https://download.mono-project.com/repo/xamarin.gpg; \
    curl https://download.mono-project.com/repo/centos7-stable.repo | tee /etc/yum.repos.d/mono-centos7-stable.repo; \
    yum groupinstall -y "Development tools"; \
    yum install -y GeoIP-devel ImageMagick asciidoc bzip2-devel bzr bzrtools cvs cvsps \
    docbook-dtds docbook-style-xsl dpkg-dev e2fsprogs expat-devel expect fakeroot \
    glib2-devel groff gzip icu iptables jq krb5-server libargon2-devel \
    libcurl-devel libdb-devel libedit-devel libevent-devel libffi-devel \
    libicu-devel libjpeg-devel libpng-devel libserf libsqlite3x-devel \
    libtidy-devel libunwind libwebp-devel libxml2-devel libxslt libxslt-devel \
    libyaml-devel libzip-devel mariadb-devel mercurial mlocate mono-devel \
    ncurses-devel oniguruma-devel openssl openssl-devel perl-DBD-SQLite \
    perl-DBI perl-HTTP-Date perl-IO-Pty-Easy perl-TimeDate perl-YAML-LibYAML \
    postgresql-devel procps-ng python-configobj python3 readline-devel rsync shadow-utils sgml-common \
    subversion-perl sudo tar tcl tk vim wget which xfsprogs xmlto xz-devel zsh; \
    gem install bundler;

ADD ./bin/* /var/tmp
ADD codebuild codebuild
RUN  /var/tmp/s2n_dev_setup.sh

# install dependencies
RUN set -eux; \
  export LD_LIBRARY_PATH=""; \
  . codebuild/bin/s2n_setup_env.sh; \
  echo "TODO: AL2 install test deps goes here..."; \
  yum clean all; \
  echo done

RUN ./codebuild/bin/install_clang.sh
USER s2n-dev
WORKDIR /home/s2n-dev/s2n
CMD ["/bin/zsh","-l"]
