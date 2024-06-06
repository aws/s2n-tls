FROM ubuntu:bionic as c2rustsrc

ARG c2rust=9511a4f28d18d626a9b9d6fc73596f60e51e2cf7

RUN \
  set -ex; \
  apt-get update; \
  apt-get install curl unzip -y; \
  cd /opt/; \
  curl https://github.com/immunant/c2rust/archive/${c2rust}.zip -L -o c2rust.zip; \
  unzip c2rust.zip; \
  rm c2rust.zip; \
  mv c2rust-${c2rust} c2rust; \
  echo done

FROM ubuntu:bionic

ARG USER=s2n
ARG UID=1000
ARG GID=1000
ENV HOME=/home/$USER
ENV DEBIAN_FRONTEND=noninteractive

USER root
RUN groupadd -f -g $GID ${USER}
RUN useradd --create-home -u $UID -g $GID --create-home --shell /bin/bash ${USER}

# /home/$USER needs to be accessible by other users because we always run the
# cargo binary from /home/$USER/.cargo/bin
RUN chmod 755 /home/${USER}

COPY --chown=${USER}:${USER} --from=c2rustsrc /opt/c2rust /home/${USER}/c2rust

RUN \
  set -ex; \
  bash /home/${USER}/c2rust/scripts/provision_deb.sh; \
  chown ${USER}:${USER} -R /home/${USER}; \
  chmod 755 -R /home/${USER}/c2rust; \
  echo done

USER $USER

ENV HOME=/home/$USER
ARG RUST_VER=nightly-2024-05-19
ENV RUST_VER=${RUST_VER}
WORKDIR /home/$USER

# setup rust
RUN \
  set -ex; \
  cd $HOME/c2rust; \
  ./scripts/provision_rust.sh; \
  echo ". $HOME/.cargo/env" >> $HOME/.bashrc; \
  echo done

# install dependencies
RUN \
  set -ex; \
  . "$HOME/.cargo/env"; \
  rustup component add rust-analyzer; \
  cargo install bindgen-cli; \
  echo done

RUN \
  set -ex; \
  . "$HOME/.cargo/env"; \
  cd $HOME/c2rust; \
  cargo build --release; \
  echo "export PATH=\"$HOME/c2rust/target/release:\$PATH\"" >> $HOME/.bashrc; \
  echo done

COPY --chmod=766 entrypoint.sh /bin/s2n2rust

SHELL ["/bin/bash"]
ENTRYPOINT ["/bin/s2n2rust"]

