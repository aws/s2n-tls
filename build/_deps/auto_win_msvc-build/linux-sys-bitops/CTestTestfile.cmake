# CMake generated Testfile for 
# Source directory: C:/Users/samue/repos/auto-win-msvc/linux-sys-bitops
# Build directory: C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/linux-sys-bitops
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(test_linux-sys-bitops "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/linux-sys-bitops/Debug/test_linux-sys-bitops.exe")
  set_tests_properties(test_linux-sys-bitops PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/linux-sys-bitops/CMakeLists.txt;35;add_test;C:/Users/samue/repos/auto-win-msvc/linux-sys-bitops/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(test_linux-sys-bitops "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/linux-sys-bitops/Release/test_linux-sys-bitops.exe")
  set_tests_properties(test_linux-sys-bitops PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/linux-sys-bitops/CMakeLists.txt;35;add_test;C:/Users/samue/repos/auto-win-msvc/linux-sys-bitops/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(test_linux-sys-bitops "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/linux-sys-bitops/MinSizeRel/test_linux-sys-bitops.exe")
  set_tests_properties(test_linux-sys-bitops PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/linux-sys-bitops/CMakeLists.txt;35;add_test;C:/Users/samue/repos/auto-win-msvc/linux-sys-bitops/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(test_linux-sys-bitops "C:/Users/samue/repos/s2n-tls/build/_deps/auto_win_msvc-build/linux-sys-bitops/RelWithDebInfo/test_linux-sys-bitops.exe")
  set_tests_properties(test_linux-sys-bitops PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/samue/repos/auto-win-msvc/linux-sys-bitops/CMakeLists.txt;35;add_test;C:/Users/samue/repos/auto-win-msvc/linux-sys-bitops/CMakeLists.txt;0;")
else()
  add_test(test_linux-sys-bitops NOT_AVAILABLE)
endif()
