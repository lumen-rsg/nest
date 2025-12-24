// --- Include C++ Wrappers FIRST ---
#include <zmq.hpp>
#include <nlohmann/json.hpp>

// --- Standard C++ Libs ---
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <chrono>
#include <thread>
#include <iomanip>

// --- C Libs (Ncurses) LAST ---
#include <ncurses.h>
#include <locale.h>

#ifdef timeout
#undef timeout
#endif

using json = nlohmann::json;

// --- Data Structures ---

struct Message {
    std::string sender;
    std::string content;
    bool is_mine;
    bool is_file;
};

struct Contact {
    std::string username;
    std::vector<Message> history;
    int unread_count = 0;
};

// --- Network Layer ---

class TuiClient {
public:
    TuiClient() : ctx_(), sock_(ctx_, zmq::socket_type::pair) {
        try {
            sock_.connect("tcp://127.0.0.1:9002");
        } catch(...) {}
    }

    void send(const std::string& cmd, const json& payload) {
        json j; j["command"] = cmd; j["payload"] = payload;
        std::string s = j.dump();
        sock_.send(zmq::buffer(s), zmq::send_flags::dontwait);
    }

    std::vector<json> poll() {
        std::vector<json> events;
        while (true) {
            zmq::message_t msg;
            if (sock_.recv(msg, zmq::recv_flags::dontwait)) {
                try { events.push_back(json::parse(msg.to_string())); } catch (...) {}
            } else break;
        }
        return events;
    }
private:
    zmq::context_t ctx_;
    zmq::socket_t sock_;
};

// --- App State ---

enum class View {
    Main,
    AddContact,
    Settings
};

struct AppState {
    // Auth
    bool logged_in = false;
    std::string my_username = "Unknown";
    std::string my_pubkey = "";

    // UI State
    View current_view = View::Main;
    std::string input_buffer;
    std::string modal_buffer; // For Add Contact input

    // Data
    std::vector<std::string> contact_list;
    std::map<std::string, Contact> contacts;
    std::string active_contact;

    int selected_contact_idx = 0;
    bool focus_input = true;

    TuiClient client;

    void add_msg(const std::string& user, const std::string& body, bool mine, bool file) {
        if (contacts.find(user) == contacts.end()) {
            contacts[user] = {user, {}, 0};
            contact_list.push_back(user);
            std::sort(contact_list.begin(), contact_list.end());
        }
        contacts[user].history.push_back({mine ? "Me" : user, body, mine, file});
        if (active_contact != user && !mine) contacts[user].unread_count++;
    }

    void switch_contact(const std::string& name) {
        active_contact = name;
        contacts[name].unread_count = 0;
        focus_input = true;
    }
};

AppState app;

// --- Rendering Helpers ---

void draw_box(WINDOW* win, const std::string& title, bool active) {
    box(win, 0, 0);
    if (active) wattron(win, A_BOLD | COLOR_PAIR(4));
    mvwprintw(win, 0, 2, " %s ", title.c_str());
    if (active) wattroff(win, A_BOLD | COLOR_PAIR(4));
    wrefresh(win);
}

void draw_centered_modal(int h, int w, const std::string& title, const std::vector<std::string>& lines, bool has_input = false, const std::string& input_val = "") {
    int modal_h = lines.size() + 4;
    int modal_w = 60;
    int start_y = (h - modal_h) / 2;
    int start_x = (w - modal_w) / 2;

    WINDOW* win = newwin(modal_h, modal_w, start_y, start_x);
    wbkgd(win, COLOR_PAIR(1));
    box(win, 0, 0);
    mvwprintw(win, 0, 2, " %s ", title.c_str());

    for (size_t i = 0; i < lines.size(); ++i) {
        mvwprintw(win, i + 2, 4, "%s", lines[i].c_str());
    }

    if (has_input) {
        mvwprintw(win, lines.size() + 2, 4, "> %s_", input_val.c_str());
    }

    wrefresh(win);
    delwin(win);
}

// --- Main Loop ---

int main() {
    setlocale(LC_ALL, "");
    initscr();
    cbreak();
    noecho();
    curs_set(0); // Hide cursor generally (we fake it)
    keypad(stdscr, TRUE);
    wtimeout(stdscr, 50);

    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_WHITE, -1);
        init_pair(2, COLOR_GREEN, -1);
        init_pair(3, COLOR_CYAN, -1);
        init_pair(4, COLOR_YELLOW, -1);
        init_pair(5, COLOR_RED, -1);
        init_pair(6, COLOR_BLACK, COLOR_WHITE); // Status Bar
    }

    app.client.send("get_status", {});

    int h, w;
    getmaxyx(stdscr, h, w);

    int sidebar_w = w / 4;
    int chat_w = w - sidebar_w;
    int chat_h = h - 4; // Leave room for input (3) + status bar (1)

    WINDOW* win_sidebar = newwin(h - 1, sidebar_w, 0, 0);
    WINDOW* win_chat    = newwin(chat_h, chat_w, 0, sidebar_w);
    WINDOW* win_input   = newwin(3, chat_w, h - 4, sidebar_w);
    WINDOW* win_status  = newwin(1, w, h - 1, 0);

    bool running = true;
    bool need_redraw = true;

    while (running) {
        // 1. Network
        auto events = app.client.poll();
        for (const auto& ev : events) {
            std::string type = ev.value("event", "");
            auto p = ev["payload"];

            if (type == "status" || type == "ready") {
                if (p.contains("username")) {
                    app.my_username = p["username"];
                    app.my_pubkey = p.value("pubkey", "");
                    app.logged_in = true;
                    app.client.send("sync_request", {});
                }
            }
            else if (type == "sync_response") {
                if (p.contains("contacts")) {
                    app.contacts.clear();
                    app.contact_list.clear();
                    for (const auto& c : p["contacts"]) {
                        std::string name = c["username"];
                        app.contact_list.push_back(name);
                        Contact& ct = app.contacts[name];
                        ct.username = name;
                        for (const auto& m : c["history"]) {
                            std::string m_type = m.value("type", "text");
                            ct.history.push_back({m["sender"], m["content"], m["is_mine"], m_type == "media"});
                        }
                    }
                    if (!app.contact_list.empty() && app.active_contact.empty()) {
                        app.active_contact = app.contact_list[0];
                    }
                }
                need_redraw = true;
            }
            else if (type == "new_message") {
                std::string sender = p.value("sender", "Unknown");
                std::string body = p.value("body", "");
                if (p.value("type", "") == "media") body = "[File] " + p.value("filename", "File");
                app.add_msg(sender, body, false, p.value("type", "") == "media");
                need_redraw = true;
            }
        }

        // 2. Input
        int ch = getch();
        if (ch != ERR) {
            need_redraw = true;

            // Global Hotkeys
            if (ch == 17) { // Ctrl+Q
                running = false;
            }
            else if (ch == 19) { // Ctrl+S (Settings)
                app.current_view = (app.current_view == View::Settings) ? View::Main : View::Settings;
            }
            else if (ch == 14) { // Ctrl+N (New Contact)
                app.current_view = (app.current_view == View::AddContact) ? View::Main : View::AddContact;
                app.modal_buffer.clear();
            }

            // View Specific Input
            if (app.current_view == View::Main) {
                if (ch == 9) { // TAB
                    app.focus_input = !app.focus_input;
                }
                else if (!app.focus_input) {
                    if (ch == KEY_UP && app.selected_contact_idx > 0) app.selected_contact_idx--;
                    else if (ch == KEY_DOWN && app.selected_contact_idx < (int)app.contact_list.size() - 1) app.selected_contact_idx++;
                    else if (ch == 10 && !app.contact_list.empty()) {
                        app.switch_contact(app.contact_list[app.selected_contact_idx]);
                    }
                }
                else {
                    if (ch == 10) { // Enter
                        if (!app.input_buffer.empty() && !app.active_contact.empty()) {
                            if (app.input_buffer == "/quit") running = false;
                            else {
                                json p; p["target"] = app.active_contact; p["text"] = app.input_buffer;
                                app.client.send("send_text", p);
                                app.add_msg(app.active_contact, app.input_buffer, true, false);
                                app.input_buffer.clear();
                            }
                        }
                    }
                    else if (ch == KEY_BACKSPACE || ch == 127) {
                        if (!app.input_buffer.empty()) app.input_buffer.pop_back();
                    }
                    else if (ch >= 32 && ch <= 126) app.input_buffer += (char)ch;
                }
            }
            else if (app.current_view == View::AddContact) {
                if (ch == 27) app.current_view = View::Main; // ESC
                else if (ch == 10) { // Enter
                    if (!app.modal_buffer.empty()) {
                        // Strip @
                        if (app.modal_buffer[0] == '@') app.modal_buffer.erase(0,1);
                        app.add_msg(app.modal_buffer, "", true, false); // Hack to add contact
                        app.switch_contact(app.modal_buffer);
                        app.current_view = View::Main;
                    }
                }
                else if (ch == KEY_BACKSPACE || ch == 127) {
                    if (!app.modal_buffer.empty()) app.modal_buffer.pop_back();
                }
                else if (ch >= 32 && ch <= 126) app.modal_buffer += (char)ch;
            }
            else if (app.current_view == View::Settings) {
                if (ch == 27) app.current_view = View::Main;
            }
        }

        // 3. Render
        if (need_redraw) {
            // Check Resize
            int new_h, new_w; getmaxyx(stdscr, new_h, new_w);
            if (new_h != h || new_w != w) {
                h = new_h; w = new_w;
                sidebar_w = w / 4; chat_w = w - sidebar_w; chat_h = h - 4;
                wresize(win_sidebar, h-1, sidebar_w);
                wresize(win_chat, chat_h, chat_w); mvwin(win_chat, 0, sidebar_w);
                wresize(win_input, 3, chat_w); mvwin(win_input, h-4, sidebar_w);
                wresize(win_status, 1, w); mvwin(win_status, h-1, 0);
                wclear(stdscr); refresh();
            }

            // A. Sidebar
            werase(win_sidebar);
            draw_box(win_sidebar, "Nectar", !app.focus_input && app.current_view == View::Main);
            for (size_t i = 0; i < app.contact_list.size(); ++i) {
                std::string name = app.contact_list[i];
                if (i == (size_t)app.selected_contact_idx && !app.focus_input) wattron(win_sidebar, A_REVERSE);
                if (name == app.active_contact) wattron(win_sidebar, A_BOLD);

                std::string label = (app.contacts[name].unread_count > 0) ? name + " (!)" : name;
                mvwprintw(win_sidebar, i+1, 2, "%s", label.c_str());

                wattroff(win_sidebar, A_BOLD);
                if (i == (size_t)app.selected_contact_idx && !app.focus_input) wattroff(win_sidebar, A_REVERSE);
            }
            wrefresh(win_sidebar);

            // B. Chat Area
            werase(win_chat);
            draw_box(win_chat, app.active_contact.empty() ? "Chat" : "@" + app.active_contact, false);
            if (!app.active_contact.empty()) {
                const auto& hist = app.contacts[app.active_contact].history;
                int max_lines = chat_h - 2;
                int start_idx = (int)hist.size() - max_lines;
                if (start_idx < 0) start_idx = 0;
                int y = 1;
                for (size_t i = start_idx; i < hist.size(); ++i) {
                    const auto& msg = hist[i];
                    if (msg.content.empty()) continue; // Skip empty init msgs
                    if (msg.is_mine) {
                        wattron(win_chat, COLOR_PAIR(2)); mvwprintw(win_chat, y, 2, "Me: "); wattroff(win_chat, COLOR_PAIR(2));
                    } else {
                        wattron(win_chat, COLOR_PAIR(3)); mvwprintw(win_chat, y, 2, "%s: ", msg.sender.c_str()); wattroff(win_chat, COLOR_PAIR(3));
                    }
                    wprintw(win_chat, "%s", msg.content.c_str());
                    y++;
                }
            }
            wrefresh(win_chat);

            // C. Input Area
            werase(win_input);
            draw_box(win_input, "Input", app.focus_input && app.current_view == View::Main);
            mvwprintw(win_input, 1, 2, "> %s", app.input_buffer.c_str());
            if (app.focus_input && app.current_view == View::Main) waddch(win_input, '_');
            wrefresh(win_input);

            // D. Status Bar
            werase(win_status);
            wbkgd(win_status, COLOR_PAIR(6));
            mvwprintw(win_status, 0, 1, "^N New Contact  ^S Settings  TAB Switch  ^Q Quit");
            wrefresh(win_status);

            // E. Modals (Draw on top of everything)
            if (app.current_view == View::AddContact) {
                std::vector<std::string> lines = { "Enter username to add:", "" };
                draw_centered_modal(h, w, "Add Contact", lines, true, app.modal_buffer);
            }
            else if (app.current_view == View::Settings) {
                std::vector<std::string> lines;
                lines.push_back("Connected as: @" + app.my_username);
                lines.push_back("");
                lines.push_back("Public Key:");
                lines.push_back(app.my_pubkey.substr(0, 32));
                lines.push_back(app.my_pubkey.substr(32));
                lines.push_back("");
                lines.push_back("Press ESC to close");
                draw_centered_modal(h, w, "Settings", lines);
            }

            need_redraw = false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    endwin();
    return 0;
}