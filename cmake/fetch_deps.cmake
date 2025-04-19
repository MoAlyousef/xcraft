include(FetchContent)

# header only libs: asio, subprocess.h magic_enum
FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio
  GIT_TAG        asio-1-30-2
  GIT_SHALLOW    True
  SOURCE_SUBDIR  blah
)

FetchContent_Declare(
  subprocess
  GIT_REPOSITORY https://github.com/sheredom/subprocess.h
  GIT_SHALLOW    True
  SOURCE_SUBDIR  blah
)

FetchContent_Declare(
  magic_enum
  GIT_REPOSITORY https://github.com/Neargye/magic_enum
  GIT_TAG        v0.9.5
  GIT_SHALLOW    True
  SOURCE_SUBDIR  blah
)

# source libs: fmt LIEF capstone keystone
FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt
  GIT_TAG        11.0.2
  GIT_SHALLOW    True
  OVERRIDE_FIND_PACKAGE
)

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
  OVERRIDE_FIND_PACKAGE
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
  OVERRIDE_FIND_PACKAGE
)

set(BUILD_LIBS_ONLY ON CACHE BOOL " " FORCE)
FetchContent_Declare(
  keystone
  GIT_REPOSITORY https://github.com/keystone-engine/keystone
  GIT_TAG        master
  GIT_SHALLOW    True
  OVERRIDE_FIND_PACKAGE
)

FetchContent_MakeAvailable(asio subprocess magic_enum capstone keystone lief fmt)

if (XCFT_BUILD_TESTS)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
  OVERRIDE_FIND_PACKAGE
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
endif()