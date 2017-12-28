# - Try to find LibCrypto include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(LibCrypto)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  LibCrypto_ROOT_DIR        Set this variable to the root installation of
#                            anything using libcrypto if the module has problems finding the
#                            proper installation path.
#
# Variables defined by this module:
#
#  LibCrypto_FOUND             System has libcrypto, include and library dirs found
#  LibCrypto_INCLUDE_DIR       The crypto include directories.
#  LibCrypto_LIBRARY    The crypto library.

find_path(LibCrypto_ROOT_DIR
        NAMES include/openssl/crypto.h 
        HINTS ${LibCrypto_ROOT_DIR}
        )

find_path(LibCrypto_INCLUDE_DIR
        NAMES openssl/crypto.h
        HINTS ${LibCrypto_ROOT_DIR}/include
        )

find_library(LibCrypto_LIBRARY
        NAMES libcrypto.a libcrypto.so
        HINTS ${LibCrypto_ROOT_DIR}/build/crypto
        ${LibCrypto_ROOT_DIR}/build
        ${LibCrypto_ROOT_DIR}
        ${LibCrypto_ROOT_DIR}/lib 
       )


include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibCrypto DEFAULT_MSG
        LibCrypto_LIBRARY
        LibCrypto_INCLUDE_DIR
        )

mark_as_advanced(
        LibCrypto_ROOT_DIR
        LibCrypto_INCLUDE_DIR
        LibCrypto_LIBRARY
)

if(LibCrypto_FOUND)
  message(STATUS "Libcrypto Include Dir: ${LibCrypto_INCLUDE_DIR}")
  if(NOT TARGET LibCrypto::Crypto AND
      (EXISTS "${LibCrypto_LIBRARY}")
      )
    add_library(LibCrypto::Crypto UNKNOWN IMPORTED)
    set_target_properties(LibCrypto::Crypto PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${LibCrypto_INCLUDE_DIR}")
    set_target_properties(LibCrypto::Crypto PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES "C"
        IMPORTED_LOCATION "${LibCrypto_LIBRARY}")
  endif()
endif()
