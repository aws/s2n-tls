#----------------------------------------------------------------
# Generated CMake target import file for configuration "MinSizeRel".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "AWS::auto-win-msvc" for configuration "MinSizeRel"
set_property(TARGET AWS::auto-win-msvc APPEND PROPERTY IMPORTED_CONFIGURATIONS MINSIZEREL)
set_target_properties(AWS::auto-win-msvc PROPERTIES
  IMPORTED_IMPLIB_MINSIZEREL "${_IMPORT_PREFIX}/lib/auto-win-msvc.lib"
  IMPORTED_LOCATION_MINSIZEREL "${_IMPORT_PREFIX}/bin/auto-win-msvc.dll"
  )

list(APPEND _cmake_import_check_targets AWS::auto-win-msvc )
list(APPEND _cmake_import_check_files_for_AWS::auto-win-msvc "${_IMPORT_PREFIX}/lib/auto-win-msvc.lib" "${_IMPORT_PREFIX}/bin/auto-win-msvc.dll" )

# Import target "AWS::wepoll" for configuration "MinSizeRel"
set_property(TARGET AWS::wepoll APPEND PROPERTY IMPORTED_CONFIGURATIONS MINSIZEREL)
set_target_properties(AWS::wepoll PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_MINSIZEREL "C"
  IMPORTED_LOCATION_MINSIZEREL "${_IMPORT_PREFIX}/lib/wepoll.lib"
  )

list(APPEND _cmake_import_check_targets AWS::wepoll )
list(APPEND _cmake_import_check_files_for_AWS::wepoll "${_IMPORT_PREFIX}/lib/wepoll.lib" )

# Import target "AWS::s2n" for configuration "MinSizeRel"
set_property(TARGET AWS::s2n APPEND PROPERTY IMPORTED_CONFIGURATIONS MINSIZEREL)
set_target_properties(AWS::s2n PROPERTIES
  IMPORTED_IMPLIB_MINSIZEREL "${_IMPORT_PREFIX}/lib/s2n.lib"
  IMPORTED_LOCATION_MINSIZEREL "${_IMPORT_PREFIX}/bin/s2n.dll"
  )

list(APPEND _cmake_import_check_targets AWS::s2n )
list(APPEND _cmake_import_check_files_for_AWS::s2n "${_IMPORT_PREFIX}/lib/s2n.lib" "${_IMPORT_PREFIX}/bin/s2n.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
