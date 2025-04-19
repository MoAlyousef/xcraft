cmake_minimum_required(VERSION 3.18)
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
find_package(LIEF CONFIG REQUIRED)
find_package(capstone CONFIG REQUIRED)
find_package(keystone CONFIG REQUIRED)
find_package(googletest CONFIG)

set(XCFT_LIB_FORM)
if (XCFT_BUILD_SHARED)
  set(XCFT_LIB_FORM SHARED)
  set_target_properties(fmt PROPERTIES POSITION_INDEPENDENT_CODE ON)
  set_target_properties(capstone PROPERTIES POSITION_INDEPENDENT_CODE ON)
  set_target_properties(keystone PROPERTIES POSITION_INDEPENDENT_CODE ON)
  set_target_properties(LIB_LIEF PROPERTIES POSITION_INDEPENDENT_CODE ON)
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
add_library(xcraft ${XCFT_LIB_FORM}
  src/utils.cpp 
  src/tube.cpp 
  src/binary.cpp 
  src/elf.cpp 
  src/pe.cpp 
  src/macho.cpp 
  src/shellcraft.cpp 
  src/rop.cpp 
  src/context.cpp
  src/bin_utils.cpp)

add_library(xcft::xcft ALIAS xcraft)
target_compile_features(xcraft PUBLIC cxx_std_20)
target_include_directories(xcraft PUBLIC 
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include>
)
target_include_directories(xcraft PRIVATE 
  ${keystone_SOURCE_DIR}/include 
  ${asio_SOURCE_DIR}/asio/include
  ${subprocess_SOURCE_DIR}
  ${magic_enum_SOURCE_DIR}/include/magic_enum
)
target_link_libraries(xcraft PRIVATE 
  fmt::fmt 
  LIEF::LIEF 
  capstone
  keystone
)
if(MINGW)
  target_link_libraries(xcraft PUBLIC ws2_32)
endif()
set_target_properties(xcraft PROPERTIES VERSION ${XCFT_PROJECT_VERSION} PUBLIC_HEADER "${XCFT_HEADER_FILES}")

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/xcraftConfigVersion.cmake
  VERSION ${XCFT_PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

if(XCFT_BUILD_SHARED)
  install(
    TARGETS xcraft
    EXPORT xcraftConfig
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include/xcraft
  )

  export(
    TARGETS xcraft
    NAMESPACE xcft::
    FILE "${CMAKE_CURRENT_BINARY_DIR}/xcraftConfig.cmake"
  )
else()
  install(
    TARGETS fmt capstone keystone LIB_LIEF
    EXPORT xcraftConfig
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
  )

  install(
    TARGETS xcraft
    EXPORT xcraftConfig
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include/xcraft
  )

  export(
    TARGETS xcraft fmt capstone keystone LIB_LIEF
    NAMESPACE xcft::
    FILE "${CMAKE_CURRENT_BINARY_DIR}/xcraftConfig.cmake"
  )
endif()

install(
  EXPORT xcraftConfig
  DESTINATION "${CMAKE_INSTALL_PREFIX}/share/cmake/xcraft"
  NAMESPACE xcft::
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/xcraftConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_PREFIX}/share/cmake/xcraft
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
endif()

if(XCFT_BUILD_TESTS AND googletest_FOUND)
  enable_testing()
  add_executable(utils tests/utils.cpp)
  target_link_libraries(utils PRIVATE xcft::xcft GTest::gtest_main)
  add_executable(elf tests/elf.cpp)
  target_link_libraries(elf PRIVATE xcft::xcft GTest::gtest_main)
  add_executable(rop tests/rop.cpp)
  target_link_libraries(rop PRIVATE xcft::xcft GTest::gtest_main)
  add_executable(proc tests/proc.cpp)
  target_link_libraries(proc PRIVATE xcft::xcft GTest::gtest_main)
  add_executable(shellcraft tests/shellcraft.cpp)
  target_link_libraries(shellcraft PRIVATE xcft::xcft GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(utils)
  gtest_discover_tests(elf)
  gtest_discover_tests(rop)
  gtest_discover_tests(proc)
  gtest_discover_tests(shellcraft)
endif()
