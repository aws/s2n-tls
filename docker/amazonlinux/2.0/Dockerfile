# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

FROM amazonlinux:2.0.20190823.1

COPY bin/* /usr/local/bin/

ENV PATH=/usr/local/bin:/usr/bin:/bin
ENV CC=/usr/bin/gcc
ENV CXX=/usr/bin/g++
ENV CFLAGS=
ENV CXXFLAGS=
ENV LDFLAGS=

ARG OPENSSL_TAG
ENV OPENSSL_TAG=${OPENSSL_TAG}
ENV OPENSSL_PLATFORM=linux-x86_64

RUN yum update -y
RUN yum groupinstall -y "Development tools" && yum install -y valgrind json-c-devel ninja-build wget openssl libtool perl-core zlib-devel cmake3 openssl-devel libcurl-devel && yum clean all && rm -rf /var/cache/yum
# Package maintainers need a sturn talking to.
RUN /usr/sbin/alternatives --install /usr/bin/cmake cmake /usr/bin/cmake3 20 \
--slave /usr/bin/ctest ctest /usr/bin/ctest3 \
--slave /usr/bin/cpack cpack /usr/bin/cpack3 \
--slave /usr/bin/ccmake ccmake /usr/bin/ccmake3 \
--family cmake


# We're going to install our own version of openssl at /deps/install/lib - this lets us test against multiple openssl versions.
# However, this also means we need to install our own version of curl, as curl links against libssl and the C++ SDK links
# against curl. What's more, we can't remove system libcurl, as we'd need to build and install our own version of git if we
# did so. Sigh.
#
# To deal with this mess, set up a bunch of -rpath overrides to ensure that all the binaries we build look in a different
# library directory first. We do this setup after configuring cmake, as we don't particularly need/want cmake to depend
# on our special versions of openssl/libcurl (or to depend on them at all for that matter).
ENV LDFLAGS="-Wl,-rpath -Wl,/deps/install/lib -Wl,-rpath -Wl,/deps/shared/install/lib -L/deps/install/lib -L/deps/shared/install/lib"

#Setting OPENSSL_TAG in the docker compose file
ARG OPENSSL_TAG
ENV OPENSSL_TAG=${OPENSSL_TAG}
ENV OPENSSL_PLATFORM=linux-x86_64

RUN /usr/local/bin/install-shared-deps.sh
RUN /usr/local/bin/install-aws-deps.sh
