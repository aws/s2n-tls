# CMake generated Testfile for 
# Source directory: C:/Users/samue/repos/auto-win-msvc/posix-signal
# Build directory: C:/Users/samue/repos/s2n-tls/build_msvc2022_shared/_deps/auto_win_msvc-build/posix-signal
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(test_posix-signal "C:/Users/samue/repos/s2n-tls/build_msvc2022_shared/_deps/auto_win_msvc-build/posix-signal/Debug/test_posix-signal.exe")
  set_tests_properties(test_posix-signal PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-signal/CMakeLists.txt;39;add_test;C:/Users/samue/repos/auto-win-msvc/posix-signal/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(test_posix-signal "C:/Users/samue/repos/s2n-tls/build_msvc2022_shared/_deps/auto_win_msvc-build/posix-signal/Release/test_posix-signal.exe")
  set_tests_properties(test_posix-signal PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-signal/CMakeLists.txt;39;add_test;C:/Users/samue/repos/auto-win-msvc/posix-signal/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(test_posix-signal "C:/Users/samue/repos/s2n-tls/build_msvc2022_shared/_deps/auto_win_msvc-build/posix-signal/MinSizeRel/test_posix-signal.exe")
  set_tests_properties(test_posix-signal PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-signal/CMakeLists.txt;39;add_test;C:/Users/samue/repos/auto-win-msvc/posix-signal/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(test_posix-signal "C:/Users/samue/repos/s2n-tls/build_msvc2022_shared/_deps/auto_win_msvc-build/posix-signal/RelWithDebInfo/test_posix-signal.exe")
  set_tests_properties(test_posix-signal PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-signal/CMakeLists.txt;39;add_test;C:/Users/samue/repos/auto-win-msvc/posix-signal/CMakeLists.txt;0;")
else()
  add_test(test_posix-signal NOT_AVAILABLE)
endif()
