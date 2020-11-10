FROM aflplusplus/aflplusplus:latest

SHELL ["/bin/bash", "-c"]
ADD codebuild codebuild

ENV DEBIAN_FRONTEND=noninteractive \
    TESTS=fuzz \
    AFL_FUZZ=true \
    FUZZ_TIMEOUT_SEC=0 \
    FUZZ_TESTS=s2n_memory_leak_negative_test

# AFLplusplus based on Ubuntu20, which ships with clang-11
RUN apt update -y; \
    apt-get install -y software-properties-common; \
    apt-get install -y --no-install-recommends curl wget; \
    apt-get install -y --no-install-recommends indent iproute2 kwstyle lcov libssl-dev m4 make net-tools nettle-bin nettle-dev pkg-config psmisc python3-pip shellcheck sudo tcpdump unzip valgrind zlib1g-dev zlibc cmake tox libtool ninja-build; \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-11 1100

RUN codebuild/bin/install_ubuntu_dependencies.sh; \
    codebuild/bin/install_default_dependencies.sh

