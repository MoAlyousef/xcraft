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

# source libs: fmt cornerstone LLVM
FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt
  GIT_TAG        11.0.2
  GIT_SHALLOW    True
  OVERRIDE_FIND_PACKAGE
)

set(CORNERSTONE_BUILD_SHARED OFF)
FetchContent_Declare(
  cornerstone
  GIT_REPOSITORY https://github.com/MoAlyousef/cornerstone
  GIT_TAG main
  GIT_SHALLOW    True
  OVERRIDE_FIND_PACKAGE
)

FetchContent_MakeAvailable(asio subprocess magic_enum cornerstone fmt)

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