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
#  Crypto_FOUND             System has libcrypto, include and library dirs found
#  Crypto_INCLUDE_DIR       The crypto include directories.
#  Crypto_LIBRARY           The crypto library, depending on the value of BUILD_SHARED_LIBS.
#  Crypto_SHARED_LIBRARY    The path to libcrypto.so
#  Crypto_STATIC_LIBRARY    The path to libcrypto.a
if (NOT crypto_FOUND AND NOT Crypto_FOUND)

    find_path(Crypto_INCLUDE_DIR
        NAMES openssl/crypto.h
        HINTS
        "${CMAKE_PREFIX_PATH}"
        "${CMAKE_INSTALL_PREFIX}"
        PATH_SUFFIXES include
    )

    find_library(Crypto_SHARED_LIBRARY
        NAMES libcrypto.so libcrypto.dylib
        HINTS
        "${CMAKE_PREFIX_PATH}"
        "${CMAKE_INSTALL_PREFIX}"
        PATH_SUFFIXES build/crypto build lib64 lib
    )

    find_library(Crypto_STATIC_LIBRARY
        NAMES libcrypto.a
        HINTS
        "${CMAKE_PREFIX_PATH}"
        "${CMAKE_INSTALL_PREFIX}"
        PATH_SUFFIXES build/crypto build lib64 lib
    )

    if (NOT Crypto_LIBRARY)
        if (BUILD_SHARED_LIBS)
            set(Crypto_LIBRARY ${Crypto_SHARED_LIBRARY})
        else()
            set(Crypto_LIBRARY ${Crypto_STATIC_LIBRARY})
        endif()
    endif()

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(crypto DEFAULT_MSG
        Crypto_LIBRARY
        Crypto_INCLUDE_DIR
    )

    mark_as_advanced(
        Crypto_ROOT_DIR
        Crypto_INCLUDE_DIR
        Crypto_LIBRARY
        Crypto_SHARED_LIBRARY
        Crypto_STATIC_LIBRARY
    )

    # some versions of cmake have a super esoteric bug around capitalization differences between
    # find dependency and find package, just avoid that here by checking and
    # setting both.
    if(Crypto_FOUND OR crypto_FOUND)
        set(Crypto_FOUND true)
        set(crypto_FOUND true)

        message(STATUS "LibCrypto Include Dir: ${Crypto_INCLUDE_DIR}")
        message(STATUS "LibCrypto Shared Lib:  ${Crypto_SHARED_LIBRARY}")
        message(STATUS "LibCrypto Static Lib:  ${Crypto_STATIC_LIBRARY}")
        if (NOT TARGET crypto AND
            (EXISTS "${Crypto_LIBRARY}")
        )
            set(THREADS_PREFER_PTHREAD_FLAG ON)
            find_package(Threads REQUIRED)
            add_library(AWS::crypto UNKNOWN IMPORTED)
            set_target_properties(AWS::crypto PROPERTIES
                    INTERFACE_INCLUDE_DIRECTORIES "${Crypto_INCLUDE_DIR}")
            set_target_properties(AWS::crypto PROPERTIES
                    IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                    IMPORTED_LOCATION "${Crypto_LIBRARY}")
            add_dependencies(AWS::crypto Threads::Threads)
        endif()
    endif()

endif()
