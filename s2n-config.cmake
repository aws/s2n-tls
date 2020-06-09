include(CMakeFindDependencyMacro)

if (NOT MSVC)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
endif()

find_dependency(LibCrypto)

if (BUILD_SHARED_LIBS)
    include(${CMAKE_CURRENT_LIST_DIR}/shared/s2n-targets.cmake)
else()
    include(${CMAKE_CURRENT_LIST_DIR}/static/s2n-targets.cmake)
endif()

