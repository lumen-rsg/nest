#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <algorithm>
#include <map>
#include <mutex>
#include <zmq.hpp>
#include "../common/json.hpp"

// Use Nectar namespace to keep things clean
namespace nest {
    using json = nlohmann::json;

    struct Message {
        std::string sender;
        std::string content;
        bool is_mine;
        std::string timestamp; // Keep as string for display for now
        bool is_file;          // Is this a file attachment?
    };

    struct Contact {
        std::string username;
        std::vector<Message> history;
        int unread_count = 0;
    };
}

// --- Styling Constants (Preserved from original) ---
ImVec4 col_bg;
ImVec4 col_sidebar;
ImVec4 col_accent;
ImVec4 col_input_bg;
ImVec4 col_text;

ImU32 col_lira_bg; // Reused for "Friend" bubble
ImU32 col_lira_text;
ImU32 col_user_bg; // Reused for "Me" bubble
ImU32 col_user_text;
ImU32 col_shadow = IM_COL32(0, 0, 0, 80);

// --- IPC Client (Talks to nestd) ---
class NectarClient {
public:
    NectarClient() : ctx_(), sock_(ctx_, zmq::socket_type::pair) {
        // Connect to the Daemon IPC
        try {
            sock_.connect("tcp://127.0.0.1:9002");
            std::cout << "[Nectar] Connected to Daemon IPC." << std::endl;
        } catch(const std::exception& e) {
            std::cerr << "[Nectar] IPC Connect Failed: " << e.what() << std::endl;
        }
    }

    void send_command(const std::string& cmd, const nest::json& payload) {
        nest::json j;
        j["command"] = cmd;
        j["payload"] = payload;
        std::string s = j.dump();
        sock_.send(zmq::buffer(s), zmq::send_flags::dontwait);
    }

    // Non-blocking check for new events from Daemon
    std::vector<nest::json> poll_events() {
        std::vector<nest::json> events;
        while (true) {
            zmq::message_t msg;
            if (sock_.recv(msg, zmq::recv_flags::dontwait)) {
                try {
                    auto j = nest::json::parse(msg.to_string());
                    events.push_back(j);
                } catch (...) {}
            } else {
                break; // No more messages
            }
        }
        return events;
    }

private:
    zmq::context_t ctx_;
    zmq::socket_t sock_;
};

// --- Global State ---
struct AppState {
    // Settings
    bool settings_open = false;
    int current_theme = 1;
    char my_username[128] = "Unknown";

    // Session Management
    bool add_contact_open = false;
    char new_contact_buf[64] = "";

    // Data
    std::vector<std::string> contact_list; // List of usernames
    std::map<std::string, nest::Contact> contacts_map; // Data storage
    std::string active_contact_name;

    NectarClient client;

    AppState() {
        // Init with a placeholder
        // In real app, we wait for 'ready' event from daemon
    }

    void switch_contact(const std::string& name) {
        active_contact_name = name;
        contacts_map[name].unread_count = 0;
    }

    void add_contact(const std::string& name) {
        if (contacts_map.find(name) == contacts_map.end()) {
            nest::Contact c;
            c.username = name;
            contacts_map[name] = c;
            contact_list.push_back(name);
            std::sort(contact_list.begin(), contact_list.end());
        }
    }

    void receive_message(const std::string& sender, const std::string& body, bool is_file) {
        // Ensure contact exists
        add_contact(sender);

        nest::Message msg;
        msg.sender = sender;
        msg.content = body;
        msg.is_mine = false;
        msg.is_file = is_file;

        contacts_map[sender].history.push_back(msg);

        if (active_contact_name != sender) {
            contacts_map[sender].unread_count++;
        }
    }

    void sent_message_local(const std::string& target, const std::string& body, bool is_file) {
        nest::Message msg;
        msg.sender = "Me";
        msg.content = body;
        msg.is_mine = true;
        msg.is_file = is_file;

        // Ensure contact exists just in case
        if (contacts_map.find(target) == contacts_map.end()) {
            add_contact(target);
        }
        contacts_map[target].history.push_back(msg);
    }
};

AppState app;
ImFont* font_regular = nullptr;
ImFont* font_input   = nullptr;

// --- Theme System ---
void SetTheme(int index) {
    app.current_theme = index;
    switch (index) {
        case 0: // Kawaii
            col_bg = ImVec4(0.98f, 0.94f, 0.96f, 1.00f); col_sidebar = ImVec4(0.95f, 0.90f, 0.94f, 1.00f); col_accent = ImVec4(1.00f, 0.60f, 0.75f, 1.00f); col_input_bg = ImVec4(1.00f, 1.00f, 1.00f, 1.00f); col_text = ImVec4(0.30f, 0.20f, 0.25f, 1.00f);
            col_lira_bg = IM_COL32(255, 255, 255, 255); col_lira_text = IM_COL32(80, 50, 70, 255); col_user_bg = IM_COL32(255, 153, 190, 255); col_user_text = IM_COL32(255, 255, 255, 255);
            break;
        case 1: // Nectar (Dark / Lira)
            col_bg = ImVec4(0.12f, 0.12f, 0.14f, 1.00f); col_sidebar = ImVec4(0.08f, 0.08f, 0.09f, 1.00f); col_accent = ImVec4(0.86f, 0.58f, 0.94f, 1.00f); col_input_bg = ImVec4(0.18f, 0.18f, 0.20f, 1.00f); col_text = ImVec4(0.90f, 0.90f, 0.90f, 1.00f);
            col_lira_bg = IM_COL32(45, 45, 48, 255); col_lira_text = IM_COL32(240, 240, 240, 255); col_user_bg = IM_COL32(0, 100, 160, 255); col_user_text = IM_COL32(255, 255, 255, 255);
            break;
        case 2: // Cyber (Aria)
            col_bg = ImVec4(0.05f, 0.08f, 0.12f, 1.00f); col_sidebar = ImVec4(0.03f, 0.05f, 0.08f, 1.00f); col_accent = ImVec4(0.00f, 0.80f, 0.90f, 1.00f); col_input_bg = ImVec4(0.08f, 0.12f, 0.18f, 1.00f); col_text = ImVec4(0.90f, 0.95f, 1.00f, 1.00f);
            col_lira_bg = IM_COL32(20, 30, 45, 255); col_lira_text = IM_COL32(220, 240, 255, 255); col_user_bg = IM_COL32(0, 150, 180, 255); col_user_text = IM_COL32(255, 255, 255, 255);
            break;
        case 3: // Solar (Lumina)
            col_bg = ImVec4(0.94f, 0.94f, 0.92f, 1.00f); col_sidebar = ImVec4(0.90f, 0.90f, 0.88f, 1.00f); col_accent = ImVec4(0.95f, 0.60f, 0.00f, 1.00f); col_input_bg = ImVec4(1.00f, 1.00f, 1.00f, 1.00f); col_text = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
            col_lira_bg = IM_COL32(255, 255, 255, 255); col_lira_text = IM_COL32(40, 40, 40, 255); col_user_bg = IM_COL32(230, 230, 230, 255); col_user_text = IM_COL32(20, 20, 20, 255);
            break;
    }
    ImGuiStyle& style = ImGui::GetStyle();
    style.Colors[ImGuiCol_WindowBg] = col_bg; style.Colors[ImGuiCol_ChildBg] = col_bg; style.Colors[ImGuiCol_Text] = col_text;
    style.Colors[ImGuiCol_Button] = ImVec4(col_accent.x, col_accent.y, col_accent.z, 0.6f);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(col_accent.x, col_accent.y, col_accent.z, 0.8f);
    style.Colors[ImGuiCol_ButtonActive] = col_accent;
    style.Colors[ImGuiCol_FrameBg] = col_input_bg; style.Colors[ImGuiCol_Header] = col_accent;
}

// --- Renderers ---

void RenderMessageBubble(const nest::Message& msg, float width_avail) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    bool is_me = msg.is_mine;

    // In original code, "is_lira" was Left, "User" was Right.
    // Here: Friend (Not Me) is Left, Me is Right.
    bool align_left = !is_me;

    float pad_x = 20.0f, pad_y = 15.0f;
    float max_w = (width_avail * 0.75f) - (pad_x * 2);

    std::string display_text = msg.content;
    if (msg.is_file) display_text = "[FILE] " + msg.content;

    ImVec2 txt_sz = ImGui::CalcTextSize(display_text.c_str(), nullptr, false, max_w);
    ImVec2 bubble_sz(txt_sz.x + (pad_x * 2), txt_sz.y + (pad_y * 2) + 20.0f);

    float shift_x = align_left ? 0.0f : width_avail - bubble_sz.x;
    ImVec2 start = ImGui::GetCursorScreenPos();
    ImGui::Dummy(bubble_sz);

    ImVec2 box_min(start.x + shift_x, start.y);
    ImVec2 box_max(box_min.x + bubble_sz.x, box_min.y + bubble_sz.y);

    dl->AddRectFilled(ImVec2(box_min.x+5, box_min.y+5), ImVec2(box_max.x+5, box_max.y+5), col_shadow, 6.0f);
    dl->AddRectFilled(box_min, box_max, align_left ? col_lira_bg : col_user_bg, 6.0f);

    ImGui::SetCursorScreenPos(ImVec2(box_min.x + pad_x, box_min.y + 10));
    ImGui::PushStyleColor(ImGuiCol_Text, align_left ? IM_COL32(140,140,140,255) : IM_COL32(200,200,200,255));
    ImGui::Text("%s", msg.sender.c_str());
    ImGui::PopStyleColor();

    ImGui::SetCursorScreenPos(ImVec2(box_min.x + pad_x, box_min.y + 30));
    ImGui::PushStyleColor(ImGuiCol_Text, align_left ? col_lira_text : col_user_text);
    ImGui::PushTextWrapPos(ImGui::GetCursorScreenPos().x + max_w + 1.0f);
    ImGui::TextUnformatted(display_text.c_str());
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();

    // Reset
    ImGui::SetCursorScreenPos(ImVec2(start.x, start.y + bubble_sz.y));
    ImGui::Dummy(ImVec2(0.0f, 20.0f));
}

void RenderSettingsPopup(float width) {
    if (!app.settings_open) return;
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(400, 320));

    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(col_sidebar.x+0.05f, col_sidebar.y+0.05f, col_sidebar.z+0.05f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Border, col_accent);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20,20));

    if (ImGui::Begin("##Settings", &app.settings_open, ImGuiWindowFlags_NoDecoration)) {
        ImGui::TextColored(col_accent, "NECTAR SETTINGS");
        ImGui::Separator();
        ImGui::Dummy(ImVec2(0, 10));

        ImGui::PushItemWidth(-1);
        ImGui::TextDisabled("Theme");
        const char* themes[] = { "Kawaii", "Dark", "Cyber", "Solar" };
        if (ImGui::Combo("##Theme", &app.current_theme, themes, 4)) SetTheme(app.current_theme);

        ImGui::Dummy(ImVec2(0, 10));
        ImGui::TextDisabled("Connected as:");
        ImGui::TextColored(col_accent, "@%s", app.my_username);

        ImGui::Dummy(ImVec2(0, 10));
        ImGui::TextDisabled("Daemon Status");
        ImGui::Text("Connected (Port 9002)");

        ImGui::PopItemWidth();

        ImGui::Dummy(ImVec2(0, 20));
        if (ImGui::Button("Close", ImVec2(360, 35))) app.settings_open = false;
    }
    ImGui::End();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);
}

void RenderAddContactPopup() {
    if (!app.add_contact_open) return;
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(350, 180));

    ImGui::PushStyleColor(ImGuiCol_WindowBg, col_sidebar);
    ImGui::PushStyleColor(ImGuiCol_Border, col_accent);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);

    ImGui::OpenPopup("Add Contact");
    if (ImGui::BeginPopupModal("Add Contact", nullptr, ImGuiWindowFlags_NoDecoration)) {
        ImGui::Text("Enter Username (e.g. bob):");
        ImGui::Dummy(ImVec2(0, 10));

        ImGui::PushItemWidth(-1);
        bool enter = ImGui::InputText("##Name", app.new_contact_buf, 64, ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::PopItemWidth();

        ImGui::Dummy(ImVec2(0, 20));
        if (ImGui::Button("Add", ImVec2(150, 35)) || enter) {
            if (strlen(app.new_contact_buf) > 0) {
                app.add_contact(app.new_contact_buf);
                app.switch_contact(app.new_contact_buf);

                app.add_contact_open = false;
                app.new_contact_buf[0] = '\0';
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(150, 35))) {
            app.add_contact_open = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}

void RenderSidebarItem(const std::string& label, bool selected) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    float width = ImGui::GetContentRegionAvail().x;
    float height = 35.0f;

    bool hovered = ImGui::IsMouseHoveringRect(p, ImVec2(p.x + width, p.y + height));
    if (hovered || selected) {
        ImVec4 c = selected ? col_accent : col_accent;
        c.w = selected ? 0.2f : 0.1f;
        ImGui::GetWindowDrawList()->AddRectFilled(p, ImVec2(p.x+width, p.y+height), ImGui::ColorConvertFloat4ToU32(c), 6.0f);
    }

    ImGui::SetCursorScreenPos(ImVec2(p.x+10, p.y+8));
    if (selected) ImGui::PushStyleColor(ImGuiCol_Text, col_accent);

    // Add unread indicator if needed
    int unread = app.contacts_map[label].unread_count;
    if (unread > 0) {
        std::string lbl = label + " (" + std::to_string(unread) + ")";
        ImGui::Text("%s", lbl.c_str());
    } else {
        ImGui::Text("%s", label.c_str());
    }

    if (selected) ImGui::PopStyleColor();

    ImGui::SetCursorScreenPos(p);
    if (ImGui::InvisibleButton(label.c_str(), ImVec2(width, height))) {
        app.switch_contact(label);
    }
    ImGui::SetCursorScreenPos(ImVec2(p.x, p.y + height + 5.0f));
}

void ApplyStyle() {
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0.0f; style.ChildRounding = 0.0f; style.FrameRounding = 6.0f;
    style.ItemSpacing = ImVec2(8, 8); style.WindowPadding = ImVec2(0, 0);
    style.ScrollbarRounding = 12.0f; style.ScrollbarSize = 10.0f;
}

// --- Main ---
int main(int, char**) {
    if (!glfwInit()) return 1;
    const char* glsl_version = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3); glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);

    GLFWwindow* window = glfwCreateWindow(1280, 900, "Nectar Secure Client", NULL, NULL);
    if (!window) return 1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImFontConfig config; config.SizePixels = 15.0f; font_regular = io.Fonts->AddFontDefault(&config);
    ImFontConfig config_lg; config_lg.SizePixels = 24.0f; font_input = io.Fonts->AddFontDefault(&config_lg);

    ApplyStyle();
    SetTheme(1); // Set default theme (Dark)
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    char input_buffer[4096] = "";

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        // --- IPC EVENT POLLING ---
        auto events = app.client.poll_events();
        for (const auto& ev : events) {
            std::string type = ev.value("event", "");
            auto payload = ev["payload"];

            if (type == "new_message") {
                // { "sender": "bob", "body": "hi", "type": "text" }
                std::string sender = payload.value("sender", "Unknown");
                std::string body = payload.value("body", "");
                if (payload.value("type", "") == "media") {
                    body = payload.value("filename", "File");
                    app.receive_message(sender, body, true);
                } else {
                    app.receive_message(sender, body, false);
                }
            }
            else if (type == "ready") {
                std::string u = payload.value("username", "Unknown");
                strncpy(app.my_username, u.c_str(), sizeof(app.my_username) - 1);
            }
        }
        // -------------------------

        ImGui_ImplOpenGL3_NewFrame(); ImGui_ImplGlfw_NewFrame(); ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0,0)); ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("Root", nullptr, ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoResize|ImGuiWindowFlags_NoMove|ImGuiWindowFlags_NoScrollbar|ImGuiWindowFlags_NoScrollWithMouse);

        float sidebar_w = 250.0f;
        float input_h = 120.0f;
        float content_h = ImGui::GetContentRegionAvail().y;
        float content_w = ImGui::GetContentRegionAvail().x;

        // --- Sidebar ---
        ImGui::PushStyleColor(ImGuiCol_ChildBg, col_sidebar);
        ImGui::BeginChild("Sidebar", ImVec2(sidebar_w, content_h));
        {
            ImGui::SetCursorPos(ImVec2(15, 20));
            ImGui::BeginGroup();
            ImGui::PushFont(font_input); ImGui::TextColored(col_accent, "NECTAR"); ImGui::PopFont();
            ImGui::Dummy(ImVec2(0, 20));
            if (ImGui::Button(" + Add Contact ", ImVec2(sidebar_w - 30, 40))) { app.add_contact_open = true; }
            ImGui::Dummy(ImVec2(0, 20));
            ImGui::TextDisabled("CONTACTS");
            ImGui::Dummy(ImVec2(0, 10));
            ImGui::EndGroup();

            ImGui::SetCursorPosX(10);
            ImGui::PushItemWidth(sidebar_w - 20);

            // Render Contact List
            for (const auto& contact : app.contact_list) {
                bool is_active = (contact == app.active_contact_name);
                RenderSidebarItem(contact, is_active);
            }
            ImGui::PopItemWidth();

            // Footer
            float foot_h = 70.0f, foot_m = 15.0f;
            ImGui::SetCursorPos(ImVec2(foot_m, content_h - foot_h - foot_m));
            ImVec2 p = ImGui::GetCursorScreenPos();
            float card_w = sidebar_w - (foot_m * 2);

            ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(p.x+3, p.y+3), ImVec2(p.x+card_w+3, p.y+foot_h+3), col_shadow, 10.0f);
            ImU32 foot_bg = ImGui::ColorConvertFloat4ToU32(ImVec4(col_sidebar.x+0.05f, col_sidebar.y+0.05f, col_sidebar.z+0.05f, 1.0f));
            ImGui::GetWindowDrawList()->AddRectFilled(p, ImVec2(p.x+card_w, p.y+foot_h), foot_bg, 10.0f);

            ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(p.x+25, p.y+35), 18.0f, IM_COL32(220,170,220,255));
            ImGui::GetWindowDrawList()->AddText(ImVec2(p.x+20, p.y+28), IM_COL32(20,20,20,255), "Me");

            ImGui::SetCursorPos(ImVec2(foot_m + 55, content_h - foot_h - foot_m + 17));
            ImGui::BeginGroup();
            ImGui::Text("%s", app.my_username);
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetColorU32(ImGuiCol_TextDisabled));
            ImGui::Text("Online");
            ImGui::PopStyleColor();
            ImGui::EndGroup();

            ImGui::SameLine();
            ImGui::SetCursorPos(ImVec2(foot_m + card_w - 40, content_h - foot_h - foot_m + 20));
            if (ImGui::Button("*", ImVec2(30, 30))) app.settings_open = !app.settings_open;
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();

        // Render Popups (Z-Order Top)
        RenderSettingsPopup(sidebar_w);
        RenderAddContactPopup();

        ImGui::SameLine();

        // --- Main ---
        ImGui::BeginGroup();
        float chat_h = content_h - input_h;
        float chat_w = content_w - sidebar_w;

        ImGui::BeginChild("ChatHistory", ImVec2(chat_w, chat_h));
        {
            ImGui::Dummy(ImVec2(0, 40));
            ImGui::Indent(50);

            if (app.active_contact_name.empty()) {
                ImGui::TextDisabled("Select a contact to start chatting.");
            } else {
                const auto& history = app.contacts_map[app.active_contact_name].history;
                if (history.empty()) {
                    ImGui::TextDisabled("No messages yet. Say hello!");
                }
                for (const auto& msg : history) {
                    RenderMessageBubble(msg, chat_w - 100);
                }
            }

            ImGui::Unindent(50);
            if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(1.0f);
        }
        ImGui::EndChild();

        // Input Area
        ImGui::BeginChild("InputArea", ImVec2(chat_w, input_h));
        {
            float bar_h = 60.0f, btn_w = 70.0f, pad_x = 50.0f;
            ImGui::SetCursorPos(ImVec2(pad_x, (input_h - bar_h) / 2.0f - 10.0f));

            ImGui::PushStyleColor(ImGuiCol_FrameBg, col_input_bg);
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(15, 15));
            ImGui::PushFont(font_input);

            // File Upload Button (New)
            if (ImGui::Button("+", ImVec2(40, bar_h))) {
                 // In a real app, open file dialog here.
                 // For now, we can hack it to send a test command or open a popup input
                 // For simplicity V1: Just print to console or command line
                 std::cout << "Use CLI for uploads in V1" << std::endl;
            }
            ImGui::SameLine();

            bool enter = ImGui::InputTextMultiline("##Input", input_buffer, sizeof(input_buffer), ImVec2(chat_w - (pad_x*2) - btn_w - 60, bar_h), ImGuiInputTextFlags_CtrlEnterForNewLine|ImGuiInputTextFlags_EnterReturnsTrue);

            ImGui::PopFont(); ImGui::PopStyleVar(2); ImGui::PopStyleColor();
            ImGui::SameLine();
            ImGui::PushFont(font_input);
            if (ImGui::Button(" > ", ImVec2(btn_w, bar_h)) || enter) {
                if (strlen(input_buffer) > 0 && !app.active_contact_name.empty()) {
                    std::string text = input_buffer;

                    // 1. Send via IPC
                    nest::json p;
                    p["target"] = app.active_contact_name;
                    p["text"] = text;
                    app.client.send_command("send_text", p);

                    // 2. Add to Local UI (Optimistic)
                    app.sent_message_local(app.active_contact_name, text, false);

                    // Clear input
                    input_buffer[0] = '\0';
                    ImGui::SetKeyboardFocusHere(-1);
                }
            }
            ImGui::PopFont();
        }
        ImGui::EndChild();
        ImGui::EndGroup();
        ImGui::End();

        ImGui::Render();
        int w, h; glfwGetFramebufferSize(window, &w, &h); glViewport(0,0,w,h);
        glClearColor(col_bg.x, col_bg.y, col_bg.z, col_bg.w); glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown(); ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext(); glfwDestroyWindow(window); glfwTerminate();
    return 0;
}