cmake_minimum_required(VERSION 3.18)
set(CTF_PROJECT_VERSION 0.1.0)
include(FetchContent)

# header only libs: asio, subprocess.h magic_enum
FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio
  GIT_TAG        asio-1-30-2
  GIT_SHALLOW    True
)

FetchContent_Declare(
  subprocess
  GIT_REPOSITORY https://github.com/sheredom/subprocess.h
  GIT_SHALLOW    True
)

FetchContent_Declare(
  magic_enum
  GIT_REPOSITORY https://github.com/Neargye/magic_enum
  GIT_TAG        v0.9.5
  GIT_SHALLOW    True
)

project(ctf
  VERSION ${CTF_PROJECT_VERSION}
  DESCRIPTION "Binary exploitation library"
  LANGUAGES C CXX
)

# source libs: fmt LIEF capstone keystone
FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt
  GIT_TAG        11.0.2
  GIT_SHALLOW    True
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(CTF_TOPLEVEL_PROJECT TRUE)
else()
    set(CTF_TOPLEVEL_PROJECT FALSE)
endif()
option(CTF_BUILD_EXAMPLES "Builds ctf examples" OFF)
option(CTF_BUILD_TESTS "Builds ctf tests" OFF)
option(CTF_BUILD_SHARED "Build ctf as a shared library" ON)

set(LIEF_USE_CCACHE OFF)
set(LIEF_C_API OFF)
set(LIEF_EXAMPLES OFF)
set(LIEF_LOGGING OFF)
set(LIEF_LOGGING_DEBUG OFF)
set(LIEF_ENABLE_JSON OFF)
set(LIEF_DEX OFF)
set(LIEF_ART OFF)
set(LIEF_OAT OFF)
set(LIEF_VDEX OFF)
set(LIEF_OAT_SUPPORT OFF)
set(LIEF_DEX_SUPPORT OFF)
set(LIEF_VDEX_SUPPORT OFF)
set(LIEF_ART_SUPPORT OFF)
FetchContent_Declare(
  lief
  GIT_REPOSITORY https://github.com/lief-project/LIEF
  GIT_TAG        0.14.1
  GIT_SHALLOW    True
)

set(CAPSTONE_X86_ATT_DISABLE ON)
set(CAPSTONE_BUILD_TESTS OFF)
set(CAPSTONE_BUILD_CSTOOL OFF)
set(CAPSTONE_BUILD_STATIC_LIBS ON)
FetchContent_Declare(
  capstone
  GIT_REPOSITORY https://github.com/capstone-engine/capstone
  GIT_TAG        6.0.0-Alpha2
  GIT_SHALLOW    True
)

set(BUILD_LIBS_ONLY ON CACHE BOOL " " FORCE)
FetchContent_Declare(
  keystone
  GIT_REPOSITORY https://github.com/keystone-engine/keystone
  GIT_TAG        master
  GIT_SHALLOW    True
)

FetchContent_MakeAvailable(asio subprocess magic_enum capstone keystone lief fmt)

if (CTF_BUILD_TESTS)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
endif()

set(CTF_LIB_FORM)
if (CTF_BUILD_SHARED)
  set(CTF_LIB_FORM SHARED)
  set_target_properties(fmt PROPERTIES POSITION_INDEPENDENT_CODE ON)
  set_target_properties(capstone PROPERTIES POSITION_INDEPENDENT_CODE ON)
  set_target_properties(keystone PROPERTIES POSITION_INDEPENDENT_CODE ON)
  set_target_properties(LIB_LIEF PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

# set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")

set(CTF_HEADER_FILES 
  include/ctf/binary.hpp
  include/ctf/context.hpp
  include/ctf/ctf.hpp
  include/ctf/elf.hpp
  include/ctf/enums.hpp
  include/ctf/macho.hpp
  include/ctf/pe.hpp
  include/ctf/rop.hpp
  include/ctf/shellcraft.hpp
  include/ctf/tube.hpp
  include/ctf/utils.hpp
)
add_library(ctf ${CTF_LIB_FORM}
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

add_library(ctf::ctf ALIAS ctf)
target_compile_features(ctf PUBLIC cxx_std_20)
target_include_directories(ctf PUBLIC 
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include>
)
target_include_directories(ctf PRIVATE 
  ${keystone_SOURCE_DIR}/include 
  ${asio_SOURCE_DIR}/asio/include
  ${subprocess_SOURCE_DIR}
  ${magic_enum_SOURCE_DIR}/include/magic_enum
)
target_link_libraries(ctf PRIVATE 
  fmt::fmt 
  LIEF::LIEF 
  capstone_static
  keystone
)
if(MINGW)
  target_link_libraries(ctf PUBLIC ws2_32)
endif()
set_target_properties(ctf PROPERTIES VERSION ${CTF_PROJECT_VERSION} PUBLIC_HEADER "${CTF_HEADER_FILES}")

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/ctfConfigVersion.cmake
  VERSION ${CTF_PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

if(CTF_BUILD_SHARED)
  install(
    TARGETS ctf
    EXPORT ctfConfig
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include/ctf
  )

  export(
    TARGETS ctf
    NAMESPACE ctf::
    FILE "${CMAKE_CURRENT_BINARY_DIR}/ctfConfig.cmake"
  )
else()
  install(
    TARGETS fmt capstone keystone LIB_LIEF
    EXPORT ctfConfig
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
  )

  install(
    TARGETS ctf
    EXPORT ctfConfig
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include/ctf
  )

  export(
    TARGETS ctf fmt capstone keystone LIB_LIEF
    NAMESPACE ctf::
    FILE "${CMAKE_CURRENT_BINARY_DIR}/ctfConfig.cmake"
  )
endif()

install(
  EXPORT ctfConfig
  DESTINATION "${CMAKE_INSTALL_PREFIX}/share/cmake/ctf"
  NAMESPACE ctf::
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ctfConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_PREFIX}/share/cmake/ctf
)

if(CTF_BUILD_EXAMPLES)
  add_executable(shellcode examples/shellcode.cpp)
  target_link_libraries(shellcode PRIVATE ctf::ctf)
  target_compile_options(shellcode PRIVATE -g)
  add_executable(ret2libc examples/ret2libc.cpp)
  target_link_libraries(ret2libc PRIVATE ctf::ctf)
  add_executable(bof_local examples/bof_local.cpp)
  target_link_libraries(bof_local PRIVATE ctf::ctf)
  add_executable(bof_remote examples/bof_remote.cpp)
  target_link_libraries(bof_remote PRIVATE ctf::ctf)
endif()

if(CTF_BUILD_TESTS)
  enable_testing()
  add_executable(utils tests/utils.cpp)
  target_link_libraries(utils PRIVATE ctf::ctf GTest::gtest_main)
  add_executable(elf tests/elf.cpp)
  target_link_libraries(elf PRIVATE ctf::ctf GTest::gtest_main)
  add_executable(rop tests/rop.cpp)
  target_link_libraries(rop PRIVATE ctf::ctf GTest::gtest_main)
  add_executable(proc tests/proc.cpp)
  target_link_libraries(proc PRIVATE ctf::ctf GTest::gtest_main)
  add_executable(shellcraft tests/shellcraft.cpp)
  target_link_libraries(shellcraft PRIVATE ctf::ctf GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(utils)
  gtest_discover_tests(elf)
  gtest_discover_tests(rop)
  gtest_discover_tests(proc)
  gtest_discover_tests(shellcraft)
endif()
