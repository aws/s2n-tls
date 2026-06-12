# CMake generated Testfile for 
# Source directory: C:/Users/samue/repos/auto-win-msvc/posix-mman
# Build directory: C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-mman
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(test_posix-mman "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-mman/Debug/test_posix-mman.exe")
  set_tests_properties(test_posix-mman PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-mman/CMakeLists.txt;109;add_test;C:/Users/samue/repos/auto-win-msvc/posix-mman/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(test_posix-mman "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-mman/Release/test_posix-mman.exe")
  set_tests_properties(test_posix-mman PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-mman/CMakeLists.txt;109;add_test;C:/Users/samue/repos/auto-win-msvc/posix-mman/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(test_posix-mman "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-mman/MinSizeRel/test_posix-mman.exe")
  set_tests_properties(test_posix-mman PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-mman/CMakeLists.txt;109;add_test;C:/Users/samue/repos/auto-win-msvc/posix-mman/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(test_posix-mman "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-mman/RelWithDebInfo/test_posix-mman.exe")
  set_tests_properties(test_posix-mman PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-mman/CMakeLists.txt;109;add_test;C:/Users/samue/repos/auto-win-msvc/posix-mman/CMakeLists.txt;0;")
else()
  add_test(test_posix-mman NOT_AVAILABLE)
endif()
