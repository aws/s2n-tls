# Building s2n-tls

To use s2n-tls, you must build the library from the source and then include it in your program.
## Requirements

s2n-tls supports and tests on **x86** and **arm** architectures.

### System requirements

* 20GB RAM availible

### Supported OS and Distributions: 

| OS     | Distros |      |        |
|--------|---------|------|--------|
| Redhat | Fedora  | AL   |
| debian | ubuntu  |
| *BSD   | free    | open | darwin |

s2n-tls does not support [Windows](https://github.com/aws/s2n-tls/issues/497).

<!-- We may want to move in this direction:

### Redhat

#### Fedora

| Version | Kernel |
|---------|--------|
| 37      | 6.0    |
| 38      | 6.2    | -->


### Software requirements

Building s2n-tls requires:

1. Git
1. GCC or Clang
1. CMake
1. OpenSSL
1. Platform-specific build tools

## Building s2n-tls from the source

Clone s2n-tls and change directories into the repo:

```bash
git clone https://github.com/aws/s2n-tls.git
cd s2n-tls
```

Follow the instructions for your platform:

<details open>
<summary>Ubuntu</summary>

```bash
# install build dependencies
sudo apt update
sudo apt install cmake

# install a libcrypto
sudo apt install libssl-dev

# build s2n-tls
cmake . -B build \
    -D CMAKE_BUILD_TYPE=Release \
    -D CMAKE_INSTALL_PREFIX=./s2n-tls-install
cmake --build build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) ctest --test-dir build
cmake --install build
```

</details>

<details>
<summary>MacOS</summary>

```bash
# install build dependencies
brew install cmake

# install a libcrypto
brew install openssl@3

# build s2n-tls
cmake . -Bbuild \
    -D CMAKE_BUILD_TYPE=Release \
    -D CMAKE_PREFIX_PATH=$(dirname $(dirname $(brew list openssl@3|grep libcrypto.dylib))) \
    -D CMAKE_INSTALL_PREFIX=./s2n-tls-install
cmake --build build -j $(sysctl -n hw.ncpu)
CTEST_PARALLEL_LEVEL=$(sysctl -n hw.ncpu) ctest --test-dir build
cmake --install build
```
</details>

<details>
<summary>AL2</summary>

```bash
# install build dependencies
sudo yum groupinstall "Development Tools"
sudo yum install cmake3

# install a libcrypto
sudo yum install openssl-devel

# build s2n-tls
cmake . -B build \
    -D CMAKE_BUILD_TYPE=Release \
    -D CMAKE_INSTALL_PREFIX=./s2n-tls-install \
    -D CMAKE_EXE_LINKER_FLAGS="-lcrypto -lz"
cmake --build build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) ctest --test-dir build
cmake --install build
```

</details>

> See the [s2n-tls usage guide](USAGE-GUIDE.md#consuming-s2n-tls-via-cmake) for instructions on how to include s2n-tls in your CMake project.

## Configuring the s2n-tls build

The following CMake options are useful for configuring s2n-tls builds. Each option can be set by passing a `-D <option>=<value>` flag to CMake.

- [**`CMAKE_BUILD_TYPE`**](https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html): Sets the build type.
  - `Release`: Produce an optimized s2n-tls library artifact without debug info. Use this option to build s2n-tls for use in production.
  - `Debug`: Produce an unoptimized library artifact with debug info. Use this option for developing s2n-tls. The debug symbols produced with this build work with GDB and other utilities for debugging.
- [**`CMAKE_INSTALL_PREFIX`**](https://cmake.org/cmake/help/latest/variable/CMAKE_INSTALL_PREFIX.html): Specifies the install directory for the s2n-tls library artifacts. Default: `/usr/local`
- [**`CMAKE_PREFIX_PATH`**](https://cmake.org/cmake/help/latest/variable/CMAKE_PREFIX_PATH.html): Specifies the directories that CMake will search for library dependencies. Use this option to link s2n-tls to a specific libcrypto. See [Building with a specific libcrypto](#building-with-a-specific-libcrypto) for more information.
- [**`BUILD_SHARED_LIBS`**](https://cmake.org/cmake/help/latest/variable/BUILD_SHARED_LIBS.html): Specifies the type of s2n-tls library artifact produced by the build, either static or shared. Default: `OFF`, for a static library. Set to `ON`, for a shared library.

The entire list of s2n-tls CMake options can be viewed with the following command:

```bash
cmake . -LH
```

## Building with a specific libcrypto

s2n-tls requires a supported libcrypto library. A supported libcrypto must be linked to s2n-tls when building. 

By default, s2n-tls searches for a system libcrypto to link with when building. 
Override the default behavior by setting the `CMAKE_PREFIX_PATH` option to the the install directory of a supported libcrypto.

## Supported libcrypto

s2n-tls supports the following libcrypto libraries:

- [AWS-LC](https://github.com/aws/aws-lc)
- [OpenSSL](https://www.openssl.org/) (versions 1.0.2 - 3.0)
  - ChaChaPoly is not supported before Openssl-1.1.1.
  - RSA-PSS is not supported before Openssl-1.1.1.
  - RC4 is not supported with Openssl-3.0 or later.
- [BoringSSL](https://boringssl.googlesource.com/boringssl)
  - OCSP features are not supported with BoringSSL.
- [LibreSSL](https://www.libressl.org/)

For help building a desired libcrypto on your platform, consult the build documentation for that libcrypto.

### AWS-LC

[AWS-LC](https://github.com/aws/aws-lc) is the recommended libcrypto to use with s2n-tls due to increased performance and security. See the [AWS-LC build documentation](https://github.com/aws/aws-lc/blob/main/BUILDING.md) for information on building AWS-LC.

Use the `CMAKE_PREFIX_PATH` option to provide the location the AWS-LC library artifact and link it to the s2n-tls build.

## Other build methods

### Ninja build system

[Ninja](https://ninja-build.org/) can be specified as the build system with CMake, which can increase build performance:

<details open>
<summary>Ubuntu</summary>

```bash
# install ninja
sudo apt update
sudo apt install ninja-build

# build s2n-tls with ninja
cmake . -Bbuild -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=./s2n-tls-install
ninja -C build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) ninja -C build test
ninja -C build install
```
</details>

### Traditional Makefile

CMake is the preferred build system for s2n-tls because it includes updated build features and supports many platforms. However, building s2n-tls with a traditional Makefile is also supported on some platforms. To use make, set the `LIBCRYPTO_ROOT` environment variable to the libcrypto install path.

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

### Cross compiling for 32-bit platforms

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
cmake . -B build -D CMAKE_TOOLCHAIN_FILE=cmake/toolchains/32-bit.toolchain
cmake --build ./build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) ctest --test-dir build
```
</details>

## Troubleshooting

### Memory managment and system limits (mlock failures)

s2n-tls uses `mlock()` to prevent memory from being swapped to disk. The
s2n-tls build tests may fail in some environments if the default limit on locked
memory is too low. To check this limit, run:

```bash
ulimit -l
```

Consult the documentation for your platform for instructions on raising the default limit on locked memory.

### Deactivate mlock()

Deactivate s2n-tls's `mlock` behavior by setting the `S2N_DONT_MLOCK` environment variable set to 1. s2n-tls also reads this for unit tests. If you're having mlock failures, try setting `S2N_DONT_MLOCK=1`.
