include(CMakeFindDependencyMacro)

if (NOT MSVC)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/modules")
find_dependency(LibCrypto)

if (BUILD_SHARED_LIBS)
    include(${CMAKE_CURRENT_LIST_DIR}/shared/@PROJECT_NAME@-targets.cmake)
else()
    include(${CMAKE_CURRENT_LIST_DIR}/static/@PROJECT_NAME@-targets.cmake)
endif()

