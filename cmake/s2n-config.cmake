include(CMakeFindDependencyMacro)

if (NOT MSVC)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/modules")
find_dependency(crypto)

# Allow static or shared lib to be used.
# If both are installed, choose based on BUILD_SHARED_LIBS.
if (BUILD_SHARED_LIBS)
    if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/shared")
        include(${CMAKE_CURRENT_LIST_DIR}/shared/@PROJECT_NAME@-targets.cmake)
    else()
        include(${CMAKE_CURRENT_LIST_DIR}/static/@PROJECT_NAME@-targets.cmake)
    endif()
else()
    if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/static")
        include(${CMAKE_CURRENT_LIST_DIR}/static/@PROJECT_NAME@-targets.cmake)
    else()
        include(${CMAKE_CURRENT_LIST_DIR}/shared/@PROJECT_NAME@-targets.cmake)
    endif()
endif()

