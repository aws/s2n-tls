# CMake generated Testfile for 
# Source directory: C:/Users/samue/repos/auto-win-msvc/posix-time
# Build directory: C:/Users/samue/repos/s2n-tls/build_msvc2022_shared/_deps/auto_win_msvc-build/posix-time
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(test_posix-time "C:/Users/samue/repos/s2n-tls/build_msvc2022_shared/_deps/auto_win_msvc-build/posix-time/Debug/test_posix-time.exe")
  set_tests_properties(test_posix-time PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-time/CMakeLists.txt;92;add_test;C:/Users/samue/repos/auto-win-msvc/posix-time/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(test_posix-time "C:/Users/samue/repos/s2n-tls/build_msvc2022_shared/_deps/auto_win_msvc-build/posix-time/Release/test_posix-time.exe")
  set_tests_properties(test_posix-time PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-time/CMakeLists.txt;92;add_test;C:/Users/samue/repos/auto-win-msvc/posix-time/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(test_posix-time "C:/Users/samue/repos/s2n-tls/build_msvc2022_shared/_deps/auto_win_msvc-build/posix-time/MinSizeRel/test_posix-time.exe")
  set_tests_properties(test_posix-time PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-time/CMakeLists.txt;92;add_test;C:/Users/samue/repos/auto-win-msvc/posix-time/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(test_posix-time "C:/Users/samue/repos/s2n-tls/build_msvc2022_shared/_deps/auto_win_msvc-build/posix-time/RelWithDebInfo/test_posix-time.exe")
  set_tests_properties(test_posix-time PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-time/CMakeLists.txt;92;add_test;C:/Users/samue/repos/auto-win-msvc/posix-time/CMakeLists.txt;0;")
else()
  add_test(test_posix-time NOT_AVAILABLE)
endif()
