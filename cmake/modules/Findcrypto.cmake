# - Try to find LibCrypto include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(crypto)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
# Variables defined by this module:
#
#  crypto_FOUND             System has libcrypto, include and library dirs found
#  crypto_INCLUDE_DIR       The crypto include directories.
#  crypto_LIBRARY           The crypto library, depending on the value of BUILD_SHARED_LIBS.
#  crypto_SHARED_LIBRARY    The path to libcrypto.so
#  crypto_STATIC_LIBRARY    The path to libcrypto.a

# the next branch exists purely for cmake compatibility with versions older than 3.15. Please do not remove it before
# we baseline on a newer version. It does not like duplicate target declarations. Work around that by checking it isn't
# defined first.
if (TARGET crypto OR TARGET AWS::crypto)
    if (TARGET crypto)
        set(TARGET_NAME "crypto")
    else()
        set(TARGET_NAME "AWS::crypto")
    endif()

    get_target_property(crypto_INCLUDE_DIR ${TARGET_NAME} INTERFACE_INCLUDE_DIRECTORIES)
    message(STATUS "S2N found target: ${TARGET_NAME}")
    message(STATUS "crypto Include Dir: ${crypto_INCLUDE_DIR}")
    set(CRYPTO_FOUND true)
    set(crypto_FOUND true)
else()
    if (S2N_AWSLC_DIST_PKG)
        # ENABLE_DIST_PKG installs suffixed names (libcrypto-awslc, include/aws-lc/)
        # that the default search cannot find. Fail rather than fall back.
        find_path(crypto_AWSLC_DIST_INCLUDE_ROOT
            NAMES aws-lc/openssl/crypto.h
            HINTS
            "${CMAKE_PREFIX_PATH}"
            "${CMAKE_INSTALL_PREFIX}"
            PATH_SUFFIXES include
        )
        if (crypto_AWSLC_DIST_INCLUDE_ROOT)
            # Sources include <openssl/...>, so point at the aws-lc/ subdirectory.
            set(crypto_INCLUDE_DIR "${crypto_AWSLC_DIST_INCLUDE_ROOT}/aws-lc")
        endif()

        find_library(crypto_SHARED_LIBRARY
            NAMES libcrypto-awslc.so libcrypto-awslc.dylib
            HINTS
            "${CMAKE_PREFIX_PATH}"
            "${CMAKE_INSTALL_PREFIX}"
            PATH_SUFFIXES lib64 lib
        )

        find_library(crypto_STATIC_LIBRARY
            NAMES libcrypto-awslc.a
            HINTS
            "${CMAKE_PREFIX_PATH}"
            "${CMAKE_INSTALL_PREFIX}"
            PATH_SUFFIXES lib64 lib
        )

        if (NOT crypto_INCLUDE_DIR OR NOT (crypto_SHARED_LIBRARY OR crypto_STATIC_LIBRARY))
            message(FATAL_ERROR
                "S2N_AWSLC_DIST_PKG is set, but a distribution-packaged AWS-LC was not found "
                "(searched for include/aws-lc/openssl/crypto.h and libcrypto-awslc). "
                "Install the AWS-LC distribution package or unset S2N_AWSLC_DIST_PKG.")
        endif()
    else()
        find_path(crypto_INCLUDE_DIR
            NAMES openssl/crypto.h
            HINTS
            "${CMAKE_PREFIX_PATH}"
            "${CMAKE_INSTALL_PREFIX}"
            PATH_SUFFIXES include
        )

        find_library(crypto_SHARED_LIBRARY
            NAMES libcrypto.so libcrypto.dylib
            HINTS
            "${CMAKE_PREFIX_PATH}"
            "${CMAKE_INSTALL_PREFIX}"
            PATH_SUFFIXES build/crypto build lib64 lib
        )

        find_library(crypto_STATIC_LIBRARY
            NAMES libcrypto.a
            HINTS
            "${CMAKE_PREFIX_PATH}"
            "${CMAKE_INSTALL_PREFIX}"
            PATH_SUFFIXES build/crypto build lib64 lib
        )
    endif()

    if (NOT crypto_LIBRARY)
        if (BUILD_SHARED_LIBS OR S2N_USE_CRYPTO_SHARED_LIBS)
            if (crypto_SHARED_LIBRARY)
                set(crypto_LIBRARY ${crypto_SHARED_LIBRARY})
            else()
                set(crypto_LIBRARY ${crypto_STATIC_LIBRARY})
            endif()
        else()
            if (crypto_STATIC_LIBRARY)
               set(crypto_LIBRARY ${crypto_STATIC_LIBRARY})
            else()
               set(crypto_LIBRARY ${crypto_SHARED_LIBRARY})
            endif()
        endif()
    endif()

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(crypto DEFAULT_MSG
        crypto_LIBRARY
        crypto_INCLUDE_DIR
    )

    mark_as_advanced(
        crypto_ROOT_DIR
        crypto_INCLUDE_DIR
        crypto_LIBRARY
        crypto_SHARED_LIBRARY
        crypto_STATIC_LIBRARY
    )

    # some versions of cmake have a super esoteric bug around capitalization differences between
    # find dependency and find package, just avoid that here by checking and
    # setting both.
    if(CRYPTO_FOUND OR crypto_FOUND)
        set(CRYPTO_FOUND true)
        set(crypto_FOUND true)

        message(STATUS "LibCrypto Include Dir: ${crypto_INCLUDE_DIR}")
        message(STATUS "LibCrypto Shared Lib:  ${crypto_SHARED_LIBRARY}")
        message(STATUS "LibCrypto Static Lib:  ${crypto_STATIC_LIBRARY}")
        if (NOT TARGET crypto AND
            (EXISTS "${crypto_LIBRARY}")
        )
            set(THREADS_PREFER_PTHREAD_FLAG ON)
            find_package(Threads REQUIRED)
            add_library(AWS::crypto UNKNOWN IMPORTED)
            set_target_properties(AWS::crypto PROPERTIES
                    INTERFACE_INCLUDE_DIRECTORIES "${crypto_INCLUDE_DIR}")
            set_target_properties(AWS::crypto PROPERTIES
                    IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                    IMPORTED_LOCATION "${crypto_LIBRARY}")
            add_dependencies(AWS::crypto Threads::Threads)
        endif()
    endif()

endif()
