# CMake generated Testfile for 
# Source directory: C:/Users/samue/repos/auto-win-msvc/posix-types
# Build directory: C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-types
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(test_posix-types "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-types/Debug/test_posix-types.exe")
  set_tests_properties(test_posix-types PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-types/CMakeLists.txt;101;add_test;C:/Users/samue/repos/auto-win-msvc/posix-types/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(test_posix-types "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-types/Release/test_posix-types.exe")
  set_tests_properties(test_posix-types PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-types/CMakeLists.txt;101;add_test;C:/Users/samue/repos/auto-win-msvc/posix-types/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(test_posix-types "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-types/MinSizeRel/test_posix-types.exe")
  set_tests_properties(test_posix-types PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-types/CMakeLists.txt;101;add_test;C:/Users/samue/repos/auto-win-msvc/posix-types/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(test_posix-types "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/posix-types/RelWithDebInfo/test_posix-types.exe")
  set_tests_properties(test_posix-types PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/posix-types/CMakeLists.txt;101;add_test;C:/Users/samue/repos/auto-win-msvc/posix-types/CMakeLists.txt;0;")
else()
  add_test(test_posix-types NOT_AVAILABLE)
endif()
