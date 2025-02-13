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
    GIT_TAG        6.0.0-Alpha3
)

FetchContent_MakeAvailable(capstone)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.16.0.zip
)

FetchContent_MakeAvailable(googletest)

FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG v1.89.7-docking
)

FetchContent_MakeAvailable(imgui)

FetchContent_Declare(
    glfw
    GIT_REPOSITORY https://github.com/glfw/glfw.git
    GIT_TAG 3.3.8
)
FetchContent_MakeAvailable(glfw)

FetchContent_Declare(
    imnodes
    GIT_REPOSITORY https://github.com/Nelarius/imnodes
    GIT_TAG v0.5
)

FetchContent_MakeAvailable(imnodes)

if (MSVC)
    add_compile_options(/W4 /WX /wd4477 /wd4005)
else()
    add_compile_options(-Wall -Wextra -pedantic -Werror -Wno-format -Wno-macro-redefined)
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
)

set(ui
    src/ui/ui.hpp
    src/ui/ui.cpp
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
)

set(imgui_source
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_demo.cpp

    ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp

    ${imnodes_SOURCE_DIR}/imnodes.cpp
    ${imnodes_SOURCE_DIR}/imnodes.h
    ${imnodes_SOURCE_DIR}/imnodes_internal.h
)

add_executable(${CMAKE_PROJECT_NAME} src/main.cpp
    ${common}
    ${core}
    ${ui}
    ${imgui_source}
)

add_executable(${CMAKE_PROJECT_NAME}x32 src/main.cpp
    ${common}
    ${core}
    ${ui}
    ${imgui_source}
)

set(libs
cxxopts LIEF::LIEF nlohmann_json::nlohmann_json capstone glfw OpenGL::GL
)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${libs})
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${imgui_SOURCE_DIR} ${imnodes_SOURCE_DIR})

target_link_libraries(${CMAKE_PROJECT_NAME}x32 PRIVATE ${libs})
target_include_directories(${CMAKE_PROJECT_NAME}x32 PRIVATE ${imgui_SOURCE_DIR} ${imnodes_SOURCE_DIR})
target_compile_definitions(${CMAKE_PROJECT_NAME}x32 PRIVATE X86_BUILD)

add_compile_definitions(IMGUI_ENABLE_DOCKING IMGUI_DEFINE_MATH_OPERATORS)

add_custom_target(copy_config ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory "${CONFIG_SOURCE_DIR}" "${CONFIG_DEST_DIR}"
    COMMENT "Copying config files to build directory"
)

enable_testing()

set(tests 
    tests/static/control/test_control.cpp
)

add_executable(runTests 
    ${tests}
    ${common}
    ${core}
)
target_link_libraries(runTests gtest_main gmock_main ${libs})
add_test(NAME Tests COMMAND runTests)
