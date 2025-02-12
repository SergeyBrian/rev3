#include "ui.hpp"

#include <iostream>
#include <queue>

#include "imnodes.h"
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
static std::map<u64, u64> nodes_map{};
static std::map<u64, ImVec2> positions{};

core::Target *target{};
u64 unique_id{};

void OnImportClick(const core::Function &func) {
    active_imports[func.address] = !active_imports[func.address];
}

void OnRefClick(u64 addr) {
    if (!target->cfg.FindNodeContaining(addr)) return;
    active_nodes[addr] = !active_nodes[addr];
}

void DrawImportsTable() {
    ImGui::Begin("Imports table", nullptr, ImGuiWindowFlags_AlwaysAutoResize);
    if (ImGui::BeginTable("Imports", 3,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("DLL");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Address");
        ImGui::TableHeadersRow();
        for (const auto &[dll, funcs] : target->imports) {
            for (const auto &func : funcs) {
                if (func.tags) {
                    if (func.tags & static_cast<u8>(core::Tag::Sink)) {
                        ImGui::PushStyleColor(ImGuiCol_Text, ImGuiColorGreen);
                    } else if (func.tags & static_cast<u8>(core::Tag::Source)) {
                        ImGui::PushStyleColor(ImGuiCol_Text, ImGuiColorYellow);
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
}

std::map<u64, ImVec2> GenerateNodePositions(
    const std::map<u64, std::unique_ptr<core::static_analysis::CFGNode>> &nodes,
    u64 entryNodeId) {
    std::map<u64, ImVec2> positions;
    std::unordered_map<u64, int> levels;
    std::unordered_map<int, int>
        column_count;  // Количество нод на каждом уровне

    // Очередь для обхода в ширину
    std::queue<std::pair<u64, int>> q;
    q.push({entryNodeId, 0});
    levels[entryNodeId] = 0;

    // BFS для вычисления уровней
    while (!q.empty()) {
        auto [nodeId, level] = q.front();
        q.pop();

        auto node = nodes.at(nodeId).get();
        if (!node) continue;

        int next_x = column_count[level] * 250;  // Смещение вправо
        int next_y = level * 200;                // Смещение вниз
        column_count[level]++;

        // Сохраняем позицию текущей ноды
        positions[nodeId] = ImVec2(next_x, next_y);

        // Обрабатываем выходные рёбра (первую связь — вправо, вторую — вниз)
        int child_index = 0;
        for (auto &edge : node->out_edges) {
            u64 targetId = 0;
            for (auto &[id, n] : nodes) {
                if (n.get() == edge.target) {
                    targetId = id;
                    break;
                }
            }
            if (targetId == 0 || levels.count(targetId))
                continue;  // Пропускаем, если уже обработали

            if (child_index == 0) {
                // Основная связь (направляем её вправо)
                levels[targetId] = level;
                positions[targetId] = ImVec2(next_x + 250, next_y);
            } else {
                // Альтернативная связь (направляем её вниз)
                levels[targetId] = level + 1;
                positions[targetId] = ImVec2(next_x, next_y + 200);
            }

            q.push({targetId, levels[targetId]});
            child_index++;
        }
    }

    return positions;
}

void DrawNodes() {
    ImGui::Begin("Graph view");
    ImNodes::BeginNodeEditor();
    for (const auto &[addr, node] : target->cfg.nodes) {
        nodes_map[addr] = unique_id;
        ImNodes::BeginNode(unique_id++);
        ImNodes::BeginNodeTitleBar();
        ImGui::Text("Node 0x%llx", addr);
        ImNodes::EndNodeTitleBar();
        ImNodes::BeginInputAttribute(unique_id++);
        ImNodes::EndInputAttribute();
        ImGui::Text("%s", target->disassembly
                              .GetString(node->block.address, node->block.size)
                              .c_str());
        for (const auto &edge : node->out_edges) {
            ImNodes::BeginOutputAttribute(unique_id++);
            ImGui::Text("%s -> 0x%llx",
                        core::static_analysis::EdgeTypeStr(edge.type).c_str(),
                        edge.target->block.address);
            ImNodes::EndOutputAttribute();
        }
        ImNodes::EndNode();
    }
    for (const auto &[_, node] : target->cfg.nodes) {
        u64 edge_id = nodes_map.at(node->block.address) + 1;
        for (const auto &edge : node->out_edges) {
            u64 dest_node_id = nodes_map.at(edge.target->block.address);

            ImNodes::Link(unique_id++, ++edge_id, dest_node_id + 1);
        }
    }

    u64 entryNodeId = target->cfg.nodes.at(0x1000)->block.address;

    if (positions.empty()) {
        positions = GenerateNodePositions(target->cfg.nodes, entryNodeId);

        for (auto &[nodeId, pos] : positions) {
            ImNodes::SetNodeGridSpacePos(nodes_map.at(nodeId), pos);
        }
    }

    ImNodes::EndNodeEditor();
    ImGui::End();
}

void DrawCode() {
    ImGui::Begin("Disasm view");
    for (const auto &[addr, node] : target->cfg.nodes) {
        ImGui::Text("=== 0x%llx ===", node->block.address);
        ImGui::Text("%s", target->disassembly
                              .GetString(node->block.address, node->block.size)
                              .c_str());
    }
    ImGui::End();
}

void OnFrame() {
    unique_id = 0;
    auto viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->Pos);
    ImGui::SetNextWindowSize(viewport->Size);
    ImGui::SetNextWindowViewport(viewport->ID);
    ImGui::Begin("Main", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                     ImGuiWindowFlags_NoResize |
                     ImGuiWindowFlags_NoBringToFrontOnFocus |
                     ImGuiWindowFlags_NoNavFocus);
    ImGui::DockSpace(ImGui::GetID("MainDockspace"));
    DrawImportsTable();
    DrawNodes();
    DrawCode();
    ImGui::End();
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
    /*glfwWindowHint(GLFW_TRANSPARENT_FRAMEBUFFER, GLFW_TRUE);*/
    /*glfwWindowHint(GLFW_DECORATED, GLFW_FALSE);*/
    /*glfwWindowHint(GLFW_FLOATING, GLFW_TRUE);*/

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
    ImNodes::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    (void)io;

    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

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

        OnFrame();

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
    ImNodes::DestroyContext();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
}
}  // namespace ui
