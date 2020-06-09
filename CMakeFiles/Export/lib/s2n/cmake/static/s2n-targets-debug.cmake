#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "AWS::s2n" for configuration "Debug"
set_property(TARGET AWS::s2n APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(AWS::s2n PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "C"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib/libs2n.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS AWS::s2n )
list(APPEND _IMPORT_CHECK_FILES_FOR_AWS::s2n "${_IMPORT_PREFIX}/lib/libs2n.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
