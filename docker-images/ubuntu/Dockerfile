ARG UBUNTU_VERSION=18.04

FROM ubuntu:${UBUNTU_VERSION}

WORKDIR /opt/s2n

ARG OPENSSL_VERSION=openssl-1.1.1
ARG GCC_VERSION=9
ARG ZSH_THEME=cypher

ENV S2N_LIBCRYPTO=${OPENSSL_VERSION} \
    GCC_VERSION=${GCC_VERSION} \
    BUILD_S2N=true \
    TESTS=integration

# The `s2n_setup_env` assumes bash, not sh
SHELL ["/bin/bash", "-c"]

# set up user account
RUN set -eux; \
  apt-get update; \
  apt-get -y install --no-install-recommends\
     curl sudo zsh unzip gnupg2 software-properties-common python-pip rubygems wget; \
  gem install bundler; \
  useradd -m s2n-dev; \
  echo "s2n-dev ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/s2n-dev; \
  chmod 0440 /etc/sudoers.d/s2n-dev; \
  mkdir -p /home/s2n-dev/s2n; \
  curl -L https://github.com/ohmyzsh/ohmyzsh/archive/master.zip -o /tmp/oh-my-zsh.zip; \
  unzip /tmp/oh-my-zsh.zip -d /tmp; \
  mkdir -p /home/s2n-dev/.zsh/plugins; \
  mkdir -p /home/s2n-dev/.zsh/themes; \
  cp /tmp/ohmyzsh-master/oh-my-zsh.sh /home/s2n-dev/.zsh/init.sh; \
  cp -R /tmp/ohmyzsh-master/lib /home/s2n-dev/.zsh; \
  cp /tmp/ohmyzsh-master/themes/${ZSH_THEME}.zsh-theme /home/s2n-dev/.zsh/themes/theme.zsh-theme; \
  rm -rf /tmp/oh-my-zsh.zip /tmp/ohmyzsh-master; \
  echo $'# ZSH setup\n\
  export DISABLE_UPDATE_PROMPT=true\n\
  export DISABLE_AUTO_UPDATE=true\n\
  export ZSH="/home/s2n-dev/.zsh"\n\
  export ZSH_THEME="theme"\n\
  plugins=()\n\
  source $ZSH/init.sh\n\
  \n\
  # s2n setup\n\
  export S2N_LIBCRYPTO='"$S2N_LIBCRYPTO"$'\n\
  export BUILD_S2N=true\n\
  export GCC_VERSION='"$GCC_VERSION"$'\n\
  export TESTS=integration\n\
  export TEST_DEPS_DIR=/opt/s2n/test-deps\n\
  cd /home/s2n-dev/s2n && source /opt/s2n/codebuild/bin/s2n_setup_env.sh\n\
  ' > /home/s2n-dev/.zshrc; \
  chown -R s2n-dev:s2n-dev /home/s2n-dev; \
  rm -rf /var/lib/apt/lists/*; \
  apt-get clean; \
  echo done

ADD codebuild codebuild

# install dependencies
RUN set -eux; \
  export LD_LIBRARY_PATH=""; \
  . codebuild/bin/s2n_setup_env.sh; \
  codebuild/bin/s2n_install_test_dependencies.sh; \
  rm -rf /var/lib/apt/lists/*; \
  apt-get clean; \
  echo done

USER s2n-dev
WORKDIR /home/s2n-dev/s2n
CMD ["/bin/zsh","-l"]
