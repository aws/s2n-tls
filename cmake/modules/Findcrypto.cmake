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
    find_package(OpenSSL MODULE REQUIRED)
    if(OPENSSL_FOUND)
        if (TARGET OpenSSL::Crypto)
            set(crypto_LIBRARY OpenSSL::Crypto)
            get_target_property(crypto_INCLUDE_DIR OpenSSL::Crypto INTERFACE_INCLUDE_DIRECTORIES)
            # If property wasn't set, fallback to the variable
            if(NOT crypto_INCLUDE_DIR)
                set(crypto_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
            endif()
        else()
            set(crypto_LIBRARY ${OPENSSL_CRYPTO_LIBRARY})
            set(crypto_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
        endif()
        set(crypto_FOUND true)
        set(CRYPTO_FOUND true)
    endif()

    if(NOT crypto_FOUND)
        find_path(crypto_INCLUDE_DIR
            NAMES openssl/crypto.h
            HINTS
            "${CMAKE_PREFIX_PATH}"
            "${CMAKE_INSTALL_PREFIX}"
            PATH_SUFFIXES include
        )

        find_library(crypto_SHARED_LIBRARY
            NAMES libcrypto.so libcrypto.dylib libcrypto.dll.a crypto.lib libcrypto.lib
            HINTS
            "${CMAKE_PREFIX_PATH}"
            "${CMAKE_INSTALL_PREFIX}"
            PATH_SUFFIXES build/crypto build lib64 lib
        )

        find_library(crypto_STATIC_LIBRARY
            NAMES libcrypto.a libcrypto.lib crypto.lib
            HINTS
            "${CMAKE_PREFIX_PATH}"
            "${CMAKE_INSTALL_PREFIX}"
            PATH_SUFFIXES build/crypto build lib64 lib
        )

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

    if(CRYPTO_FOUND OR crypto_FOUND)
        set(CRYPTO_FOUND true)
        set(crypto_FOUND true)

        message(STATUS "LibCrypto Include Dir: ${crypto_INCLUDE_DIR}")
        message(STATUS "LibCrypto Shared Lib:  ${crypto_SHARED_LIBRARY}")
        message(STATUS "LibCrypto Static Lib:  ${crypto_STATIC_LIBRARY}")
        
        if (NOT TARGET crypto AND NOT TARGET AWS::crypto)
            set(THREADS_PREFER_PTHREAD_FLAG ON)
            find_package(Threads REQUIRED)
            if (TARGET OpenSSL::Crypto)
                add_library(AWS::crypto ALIAS OpenSSL::Crypto)
            elseif(EXISTS "${crypto_LIBRARY}")
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

endif()
