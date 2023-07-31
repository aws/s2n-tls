# Building s2n-tls

Obtain s2n-tls by cloning the Github repo locally:
```bash
git clone https://github.com/aws/s2n-tls.git
cd s2n-tls
```

## Building

s2n-tls can be built as follows:

<details open>
<summary>Ubuntu</summary>

```bash
# install build dependencies
sudo apt update
sudo apt install cmake ninja-build

# install a libcrypto
sudo apt install libssl-dev

# build s2n-tls
cmake . -Bbuild -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=./s2n-tls-install
ninja -C build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) ninja -C build test
ninja -C build install
```
</details>

<details>
<summary>MacOS</summary>

```bash
# install build dependencies
brew install cmake ninja

# install a libcrypto
brew install openssl@3

# build s2n-tls
cmake . -Bbuild -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=$(dirname $(dirname $(brew list openssl@3|grep libcrypto.dylib))) \
    -DCMAKE_INSTALL_PREFIX=./s2n-tls-install
ninja -C build -j $(sysctl -n hw.ncpu)
CTEST_PARALLEL_LEVEL=$(sysctl -n hw.ncpu) ninja -C build test
ninja -C build install
```
</details>

<details>
<summary>AL2</summary>

```bash
# install build dependencies
sudo yum groupinstall "Development Tools"
sudo yum install cmake3 ninja-build 

# install a libcrypto
sudo yum install openssl-devel

# build s2n-tls
cmake . -Bbuild -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=./s2n-tls-install \
    -DCMAKE_EXE_LINKER_FLAGS="-lcrypto -lz"
ninja -C build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) ninja -C build test
ninja -C build install
```
</details>

s2n-tls can be configured with the following CMake options. Each option can be set by passing a `-D<option>=<value>` flag to CMake.
- [**`CMAKE_BUILD_TYPE`**](https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html): Sets the build type. Some of the possible build types are as follows:
  - `Release`: Produce an optimized s2n-tls library artifact with no debug info. This option should be used when building s2n-tls for use in production.
  - `Debug`: Produce an unoptimized library artifact with debug info. This option can be used when developing for or with s2n-tls. The debug symbols produced with this build can be used with GDB and other utilities to help with debugging.
- [**`CMAKE_INSTALL_PREFIX`**](https://cmake.org/cmake/help/latest/variable/CMAKE_INSTALL_PREFIX.html): Specifies where the s2n-tls library artifacts are placed when installing s2n-tls.
- [**`CMAKE_PREFIX_PATH`**](https://cmake.org/cmake/help/latest/variable/CMAKE_PREFIX_PATH.html): Specifies install locations used by CMake to search for library dependencies. This option can be used to link s2n-tls to a specific libcrypto. See the [Building with a specific libcrypto](#building-with-a-specific-libcrypto) section for more information on building with different libcryptos.
- [**`BUILD_SHARED_LIBS`**](https://cmake.org/cmake/help/latest/variable/BUILD_SHARED_LIBS.html): Specifies whether a static or shared s2n-tls library artifact will be produced during the build. Defaults to `OFF`, building a static library. If set to `ON`, a shared library will be produced instead.

The entire list of s2n-tls CMake options can be viewed with the following command:

```bash
cmake . -LH
```

See the [s2n-tls usage guide](USAGE-GUIDE.md#consuming-s2n-tls-via-cmake) for instructions on how to include s2n-tls in your CMake project.

## Building with a specific libcrypto

s2n-tls has a dependency on a libcrypto library. A supported libcrypto must be linked to s2n-tls when building. The following libcrypto libraries are currently supported:
- [AWS-LC](https://github.com/aws/aws-lc)
- [OpenSSL](https://www.openssl.org/) (versions 1.0.2 - 3.0)
  - ChaChaPoly is not supported before Openssl-1.1.1.
  - RSA-PSS is not supported before Openssl-1.1.1.
  - RC4 is not supported with Openssl-3.0 or later.
- [BoringSSL](https://boringssl.googlesource.com/boringssl)
  - OCSP features are not supported with BoringSSL.
- [LibreSSL](https://www.libressl.org/)

By default, s2n-tls will attempt to find a system libcrypto to link with when building. However, this search can be overridden to any of the above libcryptos by specifying the install directory with the `CMAKE_PREFIX_PATH` flag.

For help building a desired libcrypto on your platform, please consult the project's build documentation.

### AWS-LC

[AWS-LC](https://github.com/aws/aws-lc) is the recommended libcrypto to use with s2n-tls due to increased performance and security. AWS-LC can be built with the following:

<details open>
<summary>Ubuntu</summary>

```bash
# clone aws-lc locally
git clone https://github.com/aws/aws-lc.git
cd aws-lc

# install build dependencies
sudo apt update
sudo apt install cmake ninja-build golang

# build and install aws-lc
cmake -GNinja -B build -DCMAKE_INSTALL_PREFIX=./aws-lc-install
ninja -C build -j $(nproc)
ninja -C build run_tests
ninja -C build install
```
</details>

<details>
<summary>MacOS</summary>

```bash
# clone aws-lc locally
git clone https://github.com/aws/aws-lc.git
cd aws-lc

# install build dependencies
brew install cmake ninja go

# build and install aws-lc
cmake -GNinja -B build -DCMAKE_INSTALL_PREFIX=./aws-lc-install
ninja -C build -j $(sysctl -n hw.ncpu)
ninja -C build run_tests
ninja -C build install
```
</details>

<details>
<summary>AL2</summary>

```bash
# clone aws-lc locally
git clone https://github.com/aws/aws-lc.git
cd aws-lc

# install build dependencies
sudo yum groupinstall "Development Tools"
sudo yum install cmake3 ninja-build perl golang

# build and install aws-lc
cmake -GNinja -B build -DCMAKE_INSTALL_PREFIX=./aws-lc-install
ninja -C build -j $(nproc)
ninja -C build run_tests
ninja -C build install
```
</details>

The AWS-LC install location set by `CMAKE_INSTALL_PREFIX` should be specified when building s2n-tls with the `CMAKE_PREFIX_PATH` option. This will ensure that s2n-tls finds aws-lc when building.

For more information on building AWS-LC, see the [Building AWS-LC documentation](https://github.com/aws/aws-lc/blob/main/BUILDING.md)

## Other build methods

### Non-ninja CMake

s2n-tls can be built with CMake without a dependency on Ninja:

<details open>
<summary>Ubuntu</summary>

```bash
cmake . -Bbuild \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=./s2n-tls-install
cmake --build build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) ctest --test-dir build
cmake --install build
```
</details>

### Traditional Makefile

CMake is the preferred build system for s2n-tls since it includes updated build features and supports the most platforms. However, building s2n-tls with a traditional Makefile is also supported on some platforms. With make, the desired libcrypto install path must be set with the `LIBCRYPTO_ROOT` environment variable.

<details open>
<summary>Ubuntu</summary>

```bash
LIBCRYPTO_ROOT=/usr/local/ssl make
```
</details>

### Nix

s2n-tls supports building with Nix, which can be used for s2n-tls development to set up an environment that closely matches our CI. If Nix is installed, s2n-tls can be built with the following:

```bash
nix develop
configure; build
```

For more information on installing Nix and using Nix with s2n-tls, see the [s2n-tls Nix documentation](../nix/README.md).

## mlock() and system limits

Internally s2n-tls uses mlock() to prevent memory from being swapped to disk. The
s2n-tls build tests may fail in some environments where the default limit on locked
memory is too low. To check this limit, run:

```bash
ulimit -l
```

to raise the limit, consult the documentation for your platform.

### Disabling mlock()

To disable s2n-tls's mlock behavior, run your application with the `S2N_DONT_MLOCK` environment variable set to 1.
s2n-tls also reads this for unit tests. Try setting this environment variable before running the unit tests if you're having mlock failures.

## Cross Compiling for 32 Bit Platforms

There is an example toolchain for 32 bit cross-compiling in [`cmake/toolchains/32-bit.toolchain`](../cmake/toolchains/32-bit.toolchain).

First, you will need access to a 32 bit version of libcrypto. Many linux distributions are [multi-arch](https://help.ubuntu.com/community/MultiArch) compatible which allows you to download 32 bit packages on a 64 bit platform. This can be done with the following:

<details open>
<summary>Ubuntu</summary>

```bash
# install build dependencies
sudo apt update
sudo apt install cmake clang gcc-multilib

# we're interested in i386 (32 bit) architectures
sudo dpkg --add-architecture i386

# install the 32 bit (i386) version of libcrypto
sudo apt install libssl-dev:i386

# wipe the build directory to clear the CMake cache
rm -rf build

# build with the toolchain
cmake . -Bbuild -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/32-bit.toolchain
cmake --build ./build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) ctest --test-dir build
```
</details>
