# CMake generated Testfile for 
# Source directory: C:/Users/samue/repos/auto-win-msvc/posix-libproc
# Build directory: C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-libproc
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(test_posix-libproc "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-libproc/Debug/test_posix-libproc.exe")
  set_tests_properties(test_posix-libproc PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-libproc/CMakeLists.txt;38;add_test;C:/Users/samue/repos/auto-win-msvc/posix-libproc/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(test_posix-libproc "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-libproc/Release/test_posix-libproc.exe")
  set_tests_properties(test_posix-libproc PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-libproc/CMakeLists.txt;38;add_test;C:/Users/samue/repos/auto-win-msvc/posix-libproc/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(test_posix-libproc "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-libproc/MinSizeRel/test_posix-libproc.exe")
  set_tests_properties(test_posix-libproc PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-libproc/CMakeLists.txt;38;add_test;C:/Users/samue/repos/auto-win-msvc/posix-libproc/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(test_posix-libproc "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-libproc/RelWithDebInfo/test_posix-libproc.exe")
  set_tests_properties(test_posix-libproc PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-libproc/CMakeLists.txt;38;add_test;C:/Users/samue/repos/auto-win-msvc/posix-libproc/CMakeLists.txt;0;")
else()
  add_test(test_posix-libproc NOT_AVAILABLE)
endif()
