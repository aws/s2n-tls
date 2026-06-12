# CMake generated Testfile for 
# Source directory: C:/Users/samue/repos/auto-win-msvc/posix-alloca
# Build directory: C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-alloca
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(test_posix-alloca "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-alloca/Debug/test_posix-alloca.exe")
  set_tests_properties(test_posix-alloca PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-alloca/CMakeLists.txt;28;add_test;C:/Users/samue/repos/auto-win-msvc/posix-alloca/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(test_posix-alloca "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-alloca/Release/test_posix-alloca.exe")
  set_tests_properties(test_posix-alloca PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-alloca/CMakeLists.txt;28;add_test;C:/Users/samue/repos/auto-win-msvc/posix-alloca/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(test_posix-alloca "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-alloca/MinSizeRel/test_posix-alloca.exe")
  set_tests_properties(test_posix-alloca PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-alloca/CMakeLists.txt;28;add_test;C:/Users/samue/repos/auto-win-msvc/posix-alloca/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(test_posix-alloca "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-alloca/RelWithDebInfo/test_posix-alloca.exe")
  set_tests_properties(test_posix-alloca PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-alloca/CMakeLists.txt;28;add_test;C:/Users/samue/repos/auto-win-msvc/posix-alloca/CMakeLists.txt;0;")
else()
  add_test(test_posix-alloca NOT_AVAILABLE)
endif()
