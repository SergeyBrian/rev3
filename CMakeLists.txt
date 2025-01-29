cmake_minimum_required(VERSION 3.26)
project(rev3)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

FetchContent_Declare(
    cxxopts
    GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
    GIT_TAG        v3.2.0
)

FetchContent_MakeAvailable(cxxopts)

FetchContent_Declare(
    LIEF
    GIT_REPOSITORY https://github.com/lief-project/LIEF
    GIT_TAG        0.16.2
)

FetchContent_MakeAvailable(LIEF)

set(common
    src/utils/logger.hpp
    src/utils/logger.cpp
    src/utils/alias.hpp
    src/config/config.hpp
    src/config/config.cpp
    src/common/pre_checks.hpp
    src/common/pre_checks.cpp
)

set(core
    src/core/core.hpp
    src/core/core.cpp
    src/core/target.hpp
    src/core/target.cpp
    src/core/static/parser/parser.hpp
    src/core/static/parser/parser.cpp
    src/core/output.hpp
    src/core/output.cpp
)

add_executable(${CMAKE_PROJECT_NAME} src/main.cpp
    ${common}
    ${core}
)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE cxxopts LIEF::LIEF)
