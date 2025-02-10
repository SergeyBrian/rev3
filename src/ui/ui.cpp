#include "ui.hpp"

#include <iostream>

#include "imgui.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

#include "../core/core.hpp"
#include "../config/config.hpp"

namespace ui {

static const ImVec4 ImGuiColorRed(0.8f, 0, 0, 1.0f);
static const ImVec4 ImGuiColorGreen(0, 0.8f, 0, 1.0f);
static const ImVec4 ImGuiColorYellow(0.8f, 0.8f, 0, 1.0f);
static const ImVec4 ImGuiColorBlue(0.2f, 0.59f, 0.9f, 1.0f);

static std::map<u64, bool> active_imports{};
static std::map<u64, bool> active_nodes{};

core::Target *target{};

void OnImportClick(const core::Function &func) {
    active_imports[func.address] = !active_imports[func.address];
}

void OnRefClick(u64 addr) {
    if (!target->cfg.FindNodeContaining(addr)) return;
    active_nodes[addr] = !active_nodes[addr];
}

void Run() {
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return;
    }

    if (config::Get().static_analysis.inspect_address) {
        active_nodes[config::Get().static_analysis.inspect_address] = true;
    }

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 2);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 1);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_ANY_PROFILE);

    glfwWindowHint(GLFW_RESIZABLE, GLFW_TRUE);
    glfwWindowHint(GLFW_TRANSPARENT_FRAMEBUFFER, GLFW_TRUE);
    glfwWindowHint(GLFW_DECORATED, GLFW_FALSE);
    glfwWindowHint(GLFW_FLOATING, GLFW_TRUE);

#if __APPLE__
    glfwWindowHint(GLFW_SCALE_TO_MONITOR, GLFW_TRUE);
#endif

    target = &core::GetActiveTarget();
    std::string win_name = "Rev3 GUI - " + target->display_name;

    GLFWwindow *window =
        glfwCreateWindow(800, 600, win_name.c_str(), nullptr, nullptr);
    if (!window) {
        std::cerr << "Failed to create GLFW window" << std::endl;
        glfwTerminate();
        return;
    }

    glfwMaximizeWindow(window);
    glfwMakeContextCurrent(window);
    glfwFocusWindow(window);
    glfwSetInputMode(window, GLFW_STICKY_KEYS, GLFW_TRUE);
    glfwSetInputMode(window, GLFW_CURSOR, GLFW_CURSOR_NORMAL);

#if __APPLE__
    auto win_mode = glfwGetVideoMode(glfwGetPrimaryMonitor());
    glfwSetWindowSize(window, win_mode->width, win_mode->height);
    glfwSetWindowPos(window, 0, 0);
#endif

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    (void)io;

    io.Fonts->Clear();
#if __APPLE__
    float font_size = 36.0f;
    float gfont_size = .5f;
#else
    float font_size = 18.0f;
    float gfont_size = 1.0f;
#endif

    io.Fonts->AddFontFromFileTTF("./fonts/JetBrainsMono-Medium.ttf", font_size);
    ImGui::GetIO().FontGlobalScale = gfont_size;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
#if __APPLE__
    ImGui_ImplOpenGL3_Init("#version 120");
#else
    ImGui_ImplOpenGL3_Init("#version 130");
#endif

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::Begin("Imports table", nullptr,
                     ImGuiWindowFlags_AlwaysAutoResize);
        if (ImGui::BeginTable(
                "Imports", 3,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
            ImGui::TableSetupColumn("DLL");
            ImGui::TableSetupColumn("Name");
            ImGui::TableSetupColumn("Address");
            ImGui::TableHeadersRow();
            for (const auto &[dll, funcs] : target->imports) {
                for (const auto &func : funcs) {
                    if (func.tags) {
                        if (func.tags & static_cast<u8>(core::Tag::Sink)) {
                            ImGui::PushStyleColor(ImGuiCol_Text,
                                                  ImGuiColorGreen);
                        } else if (func.tags &
                                   static_cast<u8>(core::Tag::Source)) {
                            ImGui::PushStyleColor(ImGuiCol_Text,
                                                  ImGuiColorYellow);
                        } else if (func.tags &
                                   (static_cast<u8>(core::Tag::Trigger) |
                                    static_cast<u8>(core::Tag::Masking))) {
                            ImGui::PushStyleColor(ImGuiCol_Text, ImGuiColorRed);
                        }
                    }
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("%s", dll.c_str());
                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%s", func.display_name.c_str());

                    if (ImGui::IsItemClicked()) {
                        OnImportClick(func);
                    }
                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("0x%llx", func.address);
                    if (func.tags) {
                        ImGui::PopStyleColor();
                    }
                }
            }
            ImGui::EndTable();
        }
        ImGui::End();

        for (const auto &[addr, active] : active_nodes) {
            if (!active) continue;

            auto node = target->cfg.FindNodeContaining(addr);
            std::stringstream ss;
            ss << "0x" << std::hex << std::uppercase << node->block.address;
            auto name = ss.str();
            ImVec2 title_size = ImGui::CalcTextSize(name.c_str());
            ImGui::SetNextWindowSizeConstraints(ImVec2(title_size.x + 20, 0),
                                                ImVec2(FLT_MAX, FLT_MAX));
            ImGui::Begin(name.c_str(), nullptr, ImGuiWindowFlags_None);
            ImGui::Text("Node 0x%llx (size: %llu)", node->block.address,
                        node->block.size);
            if (!node->callers.empty()) {
                ImGui::Text("%zu callers:", node->callers.size());
                for (const auto &caller : node->callers) {
                    ImGui::TextColored(ImGuiColorBlue, "\t> 0x%llx",
                                       caller->block.address);
                    if (ImGui::IsItemClicked() && node) {
                        OnRefClick(caller->block.address);
                    }
                }
            }
            for (const auto &edge : node->in_edges) {
                ImGui::TextColored(
                    ImGuiColorBlue, "0x%llx (%s)", edge.source->block.address,
                    core::static_analysis::EdgeTypeStr(edge.type).c_str());
                if (ImGui::IsItemClicked() && node) {
                    OnRefClick(edge.source->block.address);
                }
            }
            ImGui::Text("%s",
                        target->disassembly
                            .GetString(node->block.address, node->block.size)
                            .c_str());

            for (const auto &edge : node->out_edges) {
                ImGui::TextColored(
                    ImGuiColorBlue, "0x%llx (%s)", edge.target->block.address,
                    core::static_analysis::EdgeTypeStr(edge.type).c_str());
                if (ImGui::IsItemClicked() && node) {
                    OnRefClick(edge.target->block.address);
                }
            }
            ImGui::End();
        }

        for (const auto &[_, funcs] : target->imports) {
            for (const auto &func : funcs) {
                if (!active_imports.contains(func.address) ||
                    !active_imports.at(func.address))
                    continue;
                std::string name = "Function `" + func.display_name + "`";
                ImVec2 title_size = ImGui::CalcTextSize(name.c_str());
                ImGui::SetNextWindowSizeConstraints(
                    ImVec2(title_size.x + 20, 0), ImVec2(FLT_MAX, FLT_MAX));
                ImGui::Begin(name.c_str(), nullptr, ImGuiWindowFlags_None);
                std::string msg = "Found " + std::to_string(func.xrefs.size()) +
                                  " references";

                ImGui::Text("%s", msg.c_str());
                if (ImGui::BeginTable(
                        "References", 2,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                    ImGui::TableSetupColumn("Address");
                    ImGui::TableSetupColumn("Section");
                    ImGui::TableHeadersRow();
                    for (const auto &xref : func.xrefs) {
                        auto node = target->cfg.FindNodeContaining(xref);

                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        if (node) {
                            ImGui::PushStyleColor(ImGuiCol_Text,
                                                  ImGuiColorGreen);
                        }
                        ImGui::Text("0x%llx", xref);
                        if (node) {
                            ImGui::PopStyleColor();
                        }
                        if (ImGui::IsItemClicked() && node) {
                            OnRefClick(xref);
                        }
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text(
                            "%s",
                            target->bin_info->SectionFromRva(xref).c_str());
                    }
                    ImGui::EndTable();
                }
                ImGui::End();
            }
        }

        if (glfwGetKey(window, GLFW_KEY_LEFT_CONTROL) == GLFW_PRESS &&
            glfwGetKey(window, GLFW_KEY_Q) == GLFW_PRESS) {
            glfwSetWindowShouldClose(window, true);
        }

        ImGui::Render();
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
}
}  // namespace ui
