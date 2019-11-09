# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

# Disco is the code name for the 19.04 release. The official 19.04 tag appears to act like a latest which we don't want.
# Disco gets specific versions and disco-20191030 is the latest. https://hub.docker.com/_/ubuntu/
FROM ubuntu:19.04

SHELL ["/bin/bash", "-c"]

# ENV variables are available when the image (and thus the CodeBuild build) are running and during image build time
ENV CPPCHECK_INSTALL_DIR=/test-deps/cppcheck \
    GNUTLS_INSTALL_DIR=/test-deps/gnutls \
    PYTHON_INSTALL_DIR=/test-deps/python

# ARG variables are only available while building the image
ARG GNU_TEMP=/tmp/gnutls
ARG PYTHON_TEMP=/tmp/python

RUN set -ex && \
    apt-get update && apt-get -y --no-install-recommends install  \
    curl \
    git \
    kwstyle \
    m4 \
    make \
    net-tools \
    nettle-bin \
    nettle-dev \
    perl \
    pkg-config \
    psmisc \
    sudo \
    tcpdump \
    unzip \
    valgrind \
    zlib1g-dev \
    zlibc && \
    apt-get autoremove --purge -y && \
    apt-get clean && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /tmp/* && \
    mkdir -p $PYTHON_INSTALL_DIR $PYTHON_TEMP \
        $GNUTLS_INSTALL_DIR $GNU_TEMP \
        $CPPCHECK_INSTALL_DIR

COPY bin/* /usr/local/bin/
