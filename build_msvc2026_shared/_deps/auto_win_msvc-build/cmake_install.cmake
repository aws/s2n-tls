# Install script for directory: C:/Users/samue/repos/auto-win-msvc

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "C:/Program Files (x86)/s2n")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/greatest-build/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/bsd-machine-endian/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/bsd-malloc-np/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/bsd-pthread-np/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/bsd-sys-cpuset/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/bsd-sys-endian/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/bsd-sys-event/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/bsd-sys-file/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/bsd-sys-param/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/bsd-sys-sysctl/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/bsd-vm-param/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-backtrace/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-endian/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-epoll/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-execinfo/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-features/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-getopt/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-sys-bitops/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-sys-prctl/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-sys-procfs/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-sys-statfs/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-sys-syscall/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-sys-user/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-magic/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-rdma/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-systemd/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/linux-hv-hloop/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-arpa/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-core/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-dirent/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-dlfcn/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-glob/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-inttypes/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-ipc/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-langinfo/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-libgen/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-libproc/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-mman/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-netinet/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-pthread/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-pwdgrp/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-regex/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-sched/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-signal/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-spawn/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-stat/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-strings/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-stropts/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-sys-resource/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-syslog/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-termios/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-time/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-times/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-types/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-ucontext/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-utsname/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-wait/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/solaris-port/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/solaris-sys-byteorder/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/solaris-sys-feature-tests/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-alloca/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-unwind/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/posix-netdb/cmake_install.cmake")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "C:/Users/samue/repos/s2n-tls/build_msvc2026_shared/_deps/auto_win_msvc-build/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
