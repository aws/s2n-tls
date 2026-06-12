#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "AWS::auto-win-msvc" for configuration "Debug"
set_property(TARGET AWS::auto-win-msvc APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(AWS::auto-win-msvc PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${_IMPORT_PREFIX}/lib/libauto-win-msvc.dll.a"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/bin/libauto-win-msvc.dll"
  )

list(APPEND _cmake_import_check_targets AWS::auto-win-msvc )
list(APPEND _cmake_import_check_files_for_AWS::auto-win-msvc "${_IMPORT_PREFIX}/lib/libauto-win-msvc.dll.a" "${_IMPORT_PREFIX}/bin/libauto-win-msvc.dll" )

# Import target "AWS::wepoll" for configuration "Debug"
set_property(TARGET AWS::wepoll APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(AWS::wepoll PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "C"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib/libwepoll.a"
  )

list(APPEND _cmake_import_check_targets AWS::wepoll )
list(APPEND _cmake_import_check_files_for_AWS::wepoll "${_IMPORT_PREFIX}/lib/libwepoll.a" )

# Import target "AWS::s2n" for configuration "Debug"
set_property(TARGET AWS::s2n APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(AWS::s2n PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${_IMPORT_PREFIX}/lib/libs2n.dll.a"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/bin/libs2n.dll"
  )

list(APPEND _cmake_import_check_targets AWS::s2n )
list(APPEND _cmake_import_check_files_for_AWS::s2n "${_IMPORT_PREFIX}/lib/libs2n.dll.a" "${_IMPORT_PREFIX}/bin/libs2n.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
