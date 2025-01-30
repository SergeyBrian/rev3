cmake_minimum_required(VERSION 3.26)
project(rev3)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

set(CONFIG_SOURCE_DIR "${CMAKE_SOURCE_DIR}/config")
set(CONFIG_DEST_DIR "${CMAKE_BINARY_DIR}")

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

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json
    GIT_TAG        v3.11.3
)

FetchContent_MakeAvailable(nlohmann_json)

set(common
    src/utils/logger.hpp
    src/utils/logger.cpp
    src/utils/alias.hpp
    src/config/config.hpp
    src/config/config.cpp
    src/common/pre_checks.hpp
    src/common/pre_checks.cpp
    src/utils/system.hpp
    src/utils/system.cpp
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

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE cxxopts LIEF::LIEF nlohmann_json::nlohmann_json)


add_custom_target(copy_config ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory "${CONFIG_SOURCE_DIR}" "${CONFIG_DEST_DIR}"
    COMMENT "Copying config files to build directory"
)
