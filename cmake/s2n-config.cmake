include(CMakeFindDependencyMacro)

find_dependency(LibCrypto)

include(${CMAKE_CURRENT_LIST_DIR}/@CMAKE_PROJECT_NAME@-targets.cmake)
