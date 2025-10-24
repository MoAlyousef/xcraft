cmake_minimum_required(VERSION 3.28)
set(XCFT_PROJECT_VERSION 0.1.0)

project(xcraft
  VERSION ${XCFT_PROJECT_VERSION}
  DESCRIPTION "Binary exploitation library"
  LANGUAGES C CXX
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(XCFT_TOPLEVEL_PROJECT TRUE)
else()
    set(XCFT_TOPLEVEL_PROJECT FALSE)
endif()

option(XCFT_FETCH_DEPS "Fetches dependencies via CMake" ON)
option(XCFT_BUILD_SHARED "Build xcraft as a shared library" ON)
option(XCFT_BUILD_EXAMPLES "Builds xcraft examples" OFF)
option(XCFT_BUILD_TESTS "Builds xcraft tests" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if (XCFT_FETCH_DEPS)
  include(fetch_deps)
endif()


find_package(fmt CONFIG REQUIRED)
find_package(cornerstone CONFIG REQUIRED)
find_package(LLVM REQUIRED CONFIG)
find_package(googletest CONFIG)

# Set up LLVM
llvm_map_components_to_libnames(llvm_libs Object Support BinaryFormat)

set(XCFT_LIB_FORM)
if (XCFT_BUILD_SHARED)
  set(XCFT_LIB_FORM SHARED)
  set_target_properties(fmt PROPERTIES POSITION_INDEPENDENT_CODE ON)
  set_target_properties(cornerstone PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

# set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")

set(XCFT_HEADER_FILES 
  include/xcraft/binary.hpp
  include/xcraft/context.hpp
  include/xcraft/xcraft.hpp
  include/xcraft/elf.hpp
  include/xcraft/enums.hpp
  include/xcraft/macho.hpp
  include/xcraft/pe.hpp
  include/xcraft/rop.hpp
  include/xcraft/shellcraft.hpp
  include/xcraft/tube.hpp
  include/xcraft/utils.hpp
)

set(XCFT_SOURCES
  src/utils.cpp 
  src/tube.cpp 
  src/binary.cpp 
  src/elf.cpp 
  src/pe.cpp 
  src/macho.cpp 
  src/shellcraft.cpp 
  src/rop.cpp 
  src/context.cpp
  src/bin_utils.cpp
  src/llvm_object_utils.cpp)

add_library(xcraft ${XCFT_LIB_FORM})

target_sources(xcraft
    PRIVATE 
      ${XCFT_SOURCES}
  PUBLIC 
      FILE_SET HEADERS
      BASE_DIRS ${CMAKE_CURRENT_LIST_DIR}/include
      FILES ${XCFT_HEADER_FILES}
)


add_library(xcft::xcft ALIAS xcraft)
target_compile_features(xcraft PUBLIC cxx_std_20)
target_include_directories(xcraft PRIVATE 
  ${asio_SOURCE_DIR}/asio/include
  ${subprocess_SOURCE_DIR}
  ${magic_enum_SOURCE_DIR}/include/magic_enum
  ${LLVM_INCLUDE_DIRS}
)
target_link_libraries(xcraft PRIVATE 
  fmt::fmt 
  cornerstone::cornerstone
  ${llvm_libs}
)
if(MINGW)
  target_link_libraries(xcraft PUBLIC ws2_32)
endif()
set_target_properties(xcraft PROPERTIES VERSION ${XCFT_PROJECT_VERSION})

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set(xcraft_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/xcraft")

install(
  TARGETS xcraft
  EXPORT xcraftTargets
  FILE_SET HEADERS DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
  EXPORT xcraftTargets
  FILE xcraftTargets.cmake
  NAMESPACE xcft::
  DESTINATION "${xcraft_INSTALL_CMAKEDIR}"
)

configure_package_config_file(
  "${CMAKE_CURRENT_LIST_DIR}/cmake/xcraftConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/xcraftConfig.cmake"
  INSTALL_DESTINATION "${xcraft_INSTALL_CMAKEDIR}"
  NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/xcraftConfigVersion.cmake"
  VERSION ${XCFT_PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/xcraftConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/xcraftConfigVersion.cmake"
  DESTINATION "${xcraft_INSTALL_CMAKEDIR}"
)

if(XCFT_BUILD_EXAMPLES)
  add_executable(shellcode examples/shellcode.cpp)
  target_link_libraries(shellcode PRIVATE xcft::xcft)
  target_compile_options(shellcode PRIVATE -g)
  add_executable(ret2libc examples/ret2libc.cpp)
  target_link_libraries(ret2libc PRIVATE xcft::xcft)
  add_executable(bof_local examples/bof_local.cpp)
  target_link_libraries(bof_local PRIVATE xcft::xcft)
  add_executable(bof_remote examples/bof_remote.cpp)
  target_link_libraries(bof_remote PRIVATE xcft::xcft)
  add_executable(rop examples/rop.cpp)
  target_link_libraries(rop PRIVATE xcft::xcft)
  # add_executable(debug_libc_test debug_libc_test.cpp)
  # target_link_libraries(debug_libc_test PRIVATE xcft::xcft)
endif()

if(XCFT_BUILD_TESTS AND googletest_FOUND)
  enable_testing()
  add_executable(utils tests/utils.cpp)
  target_link_libraries(utils PRIVATE xcft::xcft GTest::gtest_main)
  add_executable(elf tests/elf.cpp)
  target_link_libraries(elf PRIVATE xcft::xcft GTest::gtest_main)
  # add_executable(rop tests/rop.cpp)
  # target_link_libraries(rop PRIVATE xcft::xcft GTest::gtest_main)
  add_executable(proc tests/proc.cpp)
  target_link_libraries(proc PRIVATE xcft::xcft GTest::gtest_main)
  add_executable(shellcraft tests/shellcraft.cpp)
  target_link_libraries(shellcraft PRIVATE xcft::xcft GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(utils)
  gtest_discover_tests(elf)
  # gtest_discover_tests(rop)
  gtest_discover_tests(proc)
  gtest_discover_tests(shellcraft)
endif()
