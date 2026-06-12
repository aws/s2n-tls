# CMake generated Testfile for 
# Source directory: C:/Users/samue/repos/auto-win-msvc/bsd-sys-cpuset
# Build directory: C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/bsd-sys-cpuset
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(test_bsd-sys-cpuset "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/bsd-sys-cpuset/Debug/test_bsd-sys-cpuset.exe")
  set_tests_properties(test_bsd-sys-cpuset PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/bsd-sys-cpuset/CMakeLists.txt;95;add_test;C:/Users/samue/repos/auto-win-msvc/bsd-sys-cpuset/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(test_bsd-sys-cpuset "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/bsd-sys-cpuset/Release/test_bsd-sys-cpuset.exe")
  set_tests_properties(test_bsd-sys-cpuset PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/bsd-sys-cpuset/CMakeLists.txt;95;add_test;C:/Users/samue/repos/auto-win-msvc/bsd-sys-cpuset/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(test_bsd-sys-cpuset "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/bsd-sys-cpuset/MinSizeRel/test_bsd-sys-cpuset.exe")
  set_tests_properties(test_bsd-sys-cpuset PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/bsd-sys-cpuset/CMakeLists.txt;95;add_test;C:/Users/samue/repos/auto-win-msvc/bsd-sys-cpuset/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(test_bsd-sys-cpuset "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/bsd-sys-cpuset/RelWithDebInfo/test_bsd-sys-cpuset.exe")
  set_tests_properties(test_bsd-sys-cpuset PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/bsd-sys-cpuset/CMakeLists.txt;95;add_test;C:/Users/samue/repos/auto-win-msvc/bsd-sys-cpuset/CMakeLists.txt;0;")
else()
  add_test(test_bsd-sys-cpuset NOT_AVAILABLE)
endif()
