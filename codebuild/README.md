# Docker Image Structure
The codebuild specifications are run on a custom docker images that have the test dependencies installed. The docker image structure is described below.

### libcrypto
Various libcryptos are installed to `/usr/local/$LIBCRYPTO` directories. For example
```
# non-exhaustive list
/usr/local/openssl-1.0.2/lib/libcrypto.a
/usr/local/openssl-1.0.2/lib/libcrypto.so
/usr/local/openssl-1.0.2/lib/libcrypto.so.1.0.0
/usr/local/openssl-1.0.2/lib/pkgconfig/libcrypto.pc
/usr/local/openssl-3.0/lib64/libcrypto.a
/usr/local/openssl-3.0/lib64/libcrypto.so.3
/usr/local/openssl-3.0/lib64/libcrypto.so
/usr/local/openssl-3.0/lib64/pkgconfig/libcrypto.pc
/usr/local/boringssl/lib/libcrypto.so
/usr/local/awslc/lib/libcrypto.a
/usr/local/awslc/lib/libcrypto.so
```

Packages installed from the `apt` package manager can generally be found in `/usr/lib`. For example, our 32 bit build uses the 32 bit `i386` libcrypto, and it's artifacts are located at
```
/usr/lib/i386-linux-gnu/libcrypto.a
/usr/lib/i386-linux-gnu/libcrypto.so.3
/usr/lib/i386-linux-gnu/libcrypto.so
/usr/lib/i386-linux-gnu/pkgconfig/libcrypto.pc
```

When the docker image is available locally, the structure can be easily examined by attaching an interactive terminal to the container with the following command
```
docker run --entrypoint /bin/bash -it --privileged <image id>
```

Then the `find` command can be used to look at the various artifacts that are available.
```
sudo find / -name libcrypto* # list all libcrypto artifacts
```
or
```
sudo find / -name clang* # find all clang binaries
```