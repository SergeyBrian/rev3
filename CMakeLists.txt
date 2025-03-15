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

FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone
    GIT_TAG        5.0.5
)

FetchContent_MakeAvailable(capstone)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.16.0.zip
)

FetchContent_MakeAvailable(googletest)

FetchContent_Declare(
    z3
    GIT_REPOSITORY https://github.com/Z3Prover/z3
    GIT_TAG z3-4.14.0
)
FetchContent_MakeAvailable(z3)

set(Z3_DIR "${CMAKE_BINARY_DIR}/_deps/z3-build")
set(Z3_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/z3-src/src/api")
set(Z3_CXX_INCLUDE_DIR "${Z3_INCLUDE_DIR}/c++")
set(Z3_LIBRARIES "${Z3_LIBRARY}")
set(Z3_VERSION_HEADER "${CMAKE_BINARY_DIR}/_deps/z3-src/src/util/z3_version.h.in")
# Z3_INCLUDE_DIRS is for triton
set(Z3_INCLUDE_DIRS "${Z3_CXX_INCLUDE_DIR}")
include_directories(${Z3_INCLUDE_DIR} ${Z3_CXX_INCLUDE_DIR})


set(CAPSTONE_DIR "${CMAKE_BINARY_DIR}/_deps/capstone-build")
set(CAPSTONE_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/capstone-src/include")
set(CAPSTONE_LIBRARY "${CAPSTONE_DIR}/libcapstone.a")
set(CAPSTONE_LIBRARIES "${CAPSTONE_LIBRARY}")
set(CAPSTONE_INCLUDE_DIRS "${CAPSTONE_INCLUDE_DIR}")

FetchContent_Declare(
    triton
    GIT_REPOSITORY https://github.com/JonathanSalwan/Triton.git
    GIT_TAG e312eaf

)
FetchContent_MakeAvailable(triton)

set(TRITON_DIR "${CMAKE_BINARY_DIR}/_deps/triton-src")

include_directories("${TRITON_DIR}/src/libtriton/includes")

if (MSVC)
else()
    add_compile_options(-Wno-format -Wno-macro-redefined)
endif()


find_package(OpenGL REQUIRED)

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
    src/utils/utils.hpp
    src/utils/utils.cpp
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
    src/core/static/disas/disassembler.hpp
    src/core/static/disas/disassembler.cpp
    src/core/static/control/control.hpp
    src/core/static/control/control.cpp
    src/core/bin.hpp
    src/core/bin.cpp
    src/core/static/parser/lief_bin.hpp
    src/core/static/parser/lief_bin.cpp
    src/core/static/strings/strings.hpp
    src/core/static/strings/strings.cpp
    src/core/static/calls/calls.hpp
    src/core/static/calls/calls.cpp
    src/core/dynamic/strings/strings.hpp
    src/core/dynamic/strings/strings.cpp
    src/core/dynamic/solver/solver.hpp
    src/core/dynamic/solver/solver.cpp
    src/core/static/patterns/patterns.hpp
    src/core/static/patterns/patterns.cpp
    src/core/static/patterns/signatures.hpp
    src/core/static/patterns/signatures.cpp
)

set(cli
    src/cli/cli.hpp
    src/cli/cli.cpp
)

add_executable(${CMAKE_PROJECT_NAME} src/main.cpp
    ${common}
    ${core}
    ${cli}
)

add_executable(${CMAKE_PROJECT_NAME}x32 src/main.cpp
    ${common}
    ${core}
    ${cli}
)

set(libs
cxxopts LIEF::LIEF nlohmann_json::nlohmann_json capstone_static libz3 triton
)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${libs})

target_link_libraries(${CMAKE_PROJECT_NAME}x32 PRIVATE ${libs})
target_compile_definitions(${CMAKE_PROJECT_NAME}x32 PRIVATE X86_BUILD)

add_compile_definitions(IMGUI_ENABLE_DOCKING IMGUI_DEFINE_MATH_OPERATORS)

add_custom_target(copy_config ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory "${CONFIG_SOURCE_DIR}" "${CONFIG_DEST_DIR}"
    COMMENT "Copying config files to build directory"
)

enable_testing()

set(tests 
    tests/static/control/test_control.cpp
    tests/static/disassembly/test_disassembler.cpp
)

add_executable(runTests 
    ${tests}
    ${common}
    ${core}
)
target_link_libraries(runTests gtest_main gmock_main ${libs})
target_compile_definitions(runTests PRIVATE X86_BUILD)
add_test(NAME Tests COMMAND runTests)
