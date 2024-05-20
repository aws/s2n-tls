#!/usr/bin/env bash

set -ex

IMAGE=aws/s2n-tls-2rust
C2RUST_COMMIT=9511a4f28d18d626a9b9d6fc73596f60e51e2cf7
SCRIPT_DIR=$( cd "$( dirname $0 )" && pwd )
S2N_TLS="$(dirname "$SCRIPT_DIR")/../"

BUILD_ARGS=(
        "--file $SCRIPT_DIR/Dockerfile"
        "--tag $IMAGE"
        "--build-arg=c2rust=$C2RUST_COMMIT"
        "--build-arg=USER=$USER"
        "--build-arg=UID=$UID"
       # "--build-arg=GID=$GID"
)

sudo DOCKER_BUILDKIT=1 docker build $SCRIPT_DIR ${BUILD_ARGS[@]}

sudo docker run \
    -i \
    --rm \
    --tty \
    --volume $S2N_TLS:/home/$USER/s2n-tls \
    --user $USER \
    $IMAGE \
    /home/$USER/s2n-tls

#sudo docker run \
#    -i \
#    --rm \
#    --tty \
#    --entrypoint "/bin/bash" \
#    --volume $S2N_TLS:/home/$USER/s2n-tls \
#    --user $USER \
#    $IMAGE

echo "build available in $SCRIPT_DIR/target/s2n-tls"
