# CMake generated Testfile for 
# Source directory: C:/Users/samue/repos/auto-win-msvc/posix-spawn
# Build directory: C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-spawn
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(test_posix-spawn "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-spawn/Debug/test_posix-spawn.exe")
  set_tests_properties(test_posix-spawn PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-spawn/CMakeLists.txt;98;add_test;C:/Users/samue/repos/auto-win-msvc/posix-spawn/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(test_posix-spawn "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-spawn/Release/test_posix-spawn.exe")
  set_tests_properties(test_posix-spawn PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-spawn/CMakeLists.txt;98;add_test;C:/Users/samue/repos/auto-win-msvc/posix-spawn/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(test_posix-spawn "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-spawn/MinSizeRel/test_posix-spawn.exe")
  set_tests_properties(test_posix-spawn PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-spawn/CMakeLists.txt;98;add_test;C:/Users/samue/repos/auto-win-msvc/posix-spawn/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(test_posix-spawn "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-spawn/RelWithDebInfo/test_posix-spawn.exe")
  set_tests_properties(test_posix-spawn PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-spawn/CMakeLists.txt;98;add_test;C:/Users/samue/repos/auto-win-msvc/posix-spawn/CMakeLists.txt;0;")
else()
  add_test(test_posix-spawn NOT_AVAILABLE)
endif()
