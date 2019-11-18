# Prerequistes
EC2 Ubuntu 18.04 host:
```
$ sudo apt-get update
$ sudo apt-get install -y awscli apt-transport-https ca-certificates curl gnupg-agent software-properties-common
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
$ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
$ sudo apt-get update
$ sudo apt-get install -y docker-ce
$ sudo usermod -aG docker ${USER}
# Log in and out
```

Build images locally with `build_images.sh` which will take ~15 minutes to build
all the images. To push to the main repository run `push_images.sh`. To push to
a custom repository pass in a complete ECS url such as `push_images.sh
${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${REPOSITORY}`.

To simulate the GCC-9 with OpenSSL 1.1.1 build, unit, and integ tests locally:
```
$ docker run -it ubuntu-19.04:gcc-9x_openssl-1.1.1
$ git clone git@github.com:awslabs/aws-lc.git
$ cd aws-lc
$ export CC=gcc-9
$ export CXX=g++-9
$ export GCC_VERSION=9
$ export LIBCRYPTO_ROOT=$OPENSSL_$OPENSSL_1_1_1_INSTALL_DIR
$ .ci/codebuild/scripts/run_unit_and_integ_tests.sh
```