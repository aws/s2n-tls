+++
title = "User Guide"
weight = 1
+++

## Getting started with s2n-tls

{{< codeblock "C" "examples/s2n_negotiate.c" 17 30 >}}

> There's a github action that may be better for generating examples: https://github.com/marketplace/actions/markdown-autodocs
> https://github.com/marketplace/actions/hugo-for-github-pages

## Install in your project

## Building s2n-tls

See the [s2n-tls build documentation](BUILD.md) for guidance on building s2n-tls for your platform.

## Consuming s2n-tls with CMake

s2n-tls ships with modern CMake finder scripts if CMake is used for the build. To take advantage of this from your CMake script, all you need to do to compile and link against s2n-tls in your project is:

```bash
find_package(s2n)

....

target_link_libraries(yourExecutableOrLibrary AWS::s2n)
```

And when invoking CMake for your project, do one of two things:

 1. Set the `CMAKE_INSTALL_PREFIX` variable with the path to your s2n-tls build.
 2. If you have globally installed s2n-tls, do nothing, it will automatically be found.
