# client_gui_V3.py (V3.6 - The Final Corrected Version with Download Links)
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading, logging, os
from datetime import datetime
from client_enhanced import SMPEnhancedClient
from protocol import SMPProtocol


class LoginWindow:
    def __init__(self, root):
        self.root = root;
        self.root.title("SMP Chat");
        self.root.geometry("300x280");
        self.root.resizable(False, False)
        self.client = None
        self.main_frame = ttk.Frame(self.root, padding="10");
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.create_register_widgets()

    def create_login_widgets(self):
        self._clear_frame();
        self.root.title("SMP Chat - Login")
        ttk.Label(self.main_frame, text="Username:").pack(fill=tk.X, pady=(0, 5));
        self.username_var = tk.StringVar()
        ttk.Entry(self.main_frame, textvariable=self.username_var).pack(fill=tk.X)
        ttk.Label(self.main_frame, text="Password:").pack(fill=tk.X, pady=(10, 5));
        self.password_var = tk.StringVar()
        ttk.Entry(self.main_frame, textvariable=self.password_var, show="*").pack(fill=tk.X)
        self.login_btn = ttk.Button(self.main_frame, text="Login", command=self.handle_login);
        self.login_btn.pack(fill=tk.X, pady=(15, 5))
        ttk.Button(self.main_frame, text="Don't have an account? Register", style="Link.TButton",
                   command=self.create_register_widgets).pack()
        self._add_server_entry()

    def create_register_widgets(self):
        self._clear_frame();
        self.root.title("SMP Chat - Register")
        ttk.Label(self.main_frame, text="Username (min 3 chars):").pack(fill=tk.X, pady=(0, 5));
        self.username_var = tk.StringVar()
        ttk.Entry(self.main_frame, textvariable=self.username_var).pack(fill=tk.X)
        ttk.Label(self.main_frame, text="Password (min 8 chars):").pack(fill=tk.X, pady=(10, 5));
        self.password_var = tk.StringVar()
        ttk.Entry(self.main_frame, textvariable=self.password_var, show="*").pack(fill=tk.X)
        self.register_btn = ttk.Button(self.main_frame, text="Register", command=self.handle_register);
        self.register_btn.pack(fill=tk.X, pady=(15, 5))
        ttk.Button(self.main_frame, text="Already have an account? Login", style="Link.TButton",
                   command=self.create_login_widgets).pack()
        self._add_server_entry()

    def _add_server_entry(self):
        ttk.Label(self.main_frame, text="Server:").pack(fill=tk.X, pady=(10, 0));
        self.server_var = tk.StringVar(value="localhost:8899")
        ttk.Entry(self.main_frame, textvariable=self.server_var).pack(fill=tk.X)

    def handle_login(self):
        username, password, (host,
                             port) = self.username_var.get().strip(), self.password_var.get(), self._get_server_addr()
        if not all([host, username, password]): return messagebox.showerror("Error", "All fields are required.")
        self.login_btn.config(text="Logging in...", state=tk.DISABLED);
        self.client = SMPEnhancedClient(server_host=host, server_port=port)
        threading.Thread(
            target=lambda: self.root.after(0, self.on_login_success, self.client.user_data) if self.client.connect(
                username, password) else self.root.after(0,
                                                         lambda: self.login_btn.config(text="Login", state=tk.NORMAL)),
            daemon=True).start()

    def handle_register(self):
        username, password, (host,
                             port) = self.username_var.get().strip(), self.password_var.get(), self._get_server_addr()
        if not host or len(username) < 3 or len(password) < 8: return messagebox.showerror("Error",
                                                                                           "Check requirements.")
        self.register_btn.config(text="Registering...", state=tk.DISABLED);
        temp_client = SMPEnhancedClient(server_host=host, server_port=port)
        threading.Thread(target=lambda: self.root.after(0, self.create_login_widgets) if temp_client.register(username,
                                                                                                              password) else self.root.after(
            0, lambda: self.register_btn.config(text="Register", state=tk.NORMAL)), daemon=True).start()

    def on_login_success(self, user_data):
        self.root.destroy(); root = tk.Tk(); MainChatWindow(root, self.client, user_data); root.mainloop()

    def _get_server_addr(self):
        try:
            host, port = self.server_var.get().strip().split(':'); return host, int(port)
        except:
            messagebox.showerror("Error", "Invalid server address."); return None, None

    def _clear_frame(self):
        [w.destroy() for w in self.main_frame.winfo_children()]


class MainChatWindow:
    def __init__(self, root, client: SMPEnhancedClient, user_data: dict):
        self.root, self.client, self.user_data = root, client, user_data
        self.username, self.user_id = user_data.get('username'), user_data.get('user_id')
        self.root.title(f"SMP Chat V3.6 - Welcome, {self.username} (ID: {self.user_id})")
        self.root.geometry("800x600");
        self.chat_sessions, self.active_session_key = {}, None;
        self.loaded_history = set()
        self.setup_ui();
        self.setup_event_handlers();
        self.client.start_heartbeat()
        self.after_id = self.root.after(100, self.process_messages)

    def setup_ui(self):
        self.paned_window = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED);
        self.paned_window.pack(fill=tk.BOTH, expand=True)
        session_pane = ttk.Frame(self.paned_window, width=220);
        self.paned_window.add(session_pane)
        add_friend_frame = ttk.LabelFrame(session_pane, text="Find Friends");
        add_friend_frame.pack(fill=tk.X, padx=5, pady=5)
        self.search_id_var = tk.StringVar();
        ttk.Entry(add_friend_frame, textvariable=self.search_id_var).pack(side=tk.LEFT, fill=tk.X, expand=True,
                                                                          padx=(0, 5))
        ttk.Button(add_friend_frame, text="Add", command=self.add_friend).pack(side=tk.RIGHT)
        chats_frame = ttk.LabelFrame(session_pane, text="Chats");
        chats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.session_tree = ttk.Treeview(chats_frame, show="tree", selectmode="browse");
        self.session_tree.pack(fill=tk.BOTH, expand=True)
        self.friends_node = self.session_tree.insert("", "end", "friends_node", text="Friends", open=True)
        self.groups_node = self.session_tree.insert("", "end", "groups_node", text="My Groups", open=True)
        group_actions_frame = ttk.LabelFrame(session_pane, text="Group Actions");
        group_actions_frame.pack(fill=tk.X, padx=5, pady=5)
        self.group_var = tk.StringVar();
        ttk.Entry(group_actions_frame, textvariable=self.group_var).grid(row=0, column=0, columnspan=2, sticky="ew",
                                                                         pady=(0, 5))
        ttk.Button(group_actions_frame, text="Create", command=self.create_group).grid(row=1, column=0, sticky="ew")
        ttk.Button(group_actions_frame, text="Join", command=self.join_group).grid(row=1, column=1, sticky="ew")
        main_pane = ttk.Frame(self.paned_window);
        self.paned_window.add(main_pane);
        self.chat_title_var = tk.StringVar()
        ttk.Label(main_pane, textvariable=self.chat_title_var, font=("Segoe UI", 12, "bold")).pack(fill=tk.X, padx=10,
                                                                                                   pady=(5, 0))
        self.chat_container = ttk.Frame(main_pane);
        self.chat_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        input_frame = ttk.Frame(main_pane);
        input_frame.pack(fill=tk.X, padx=10, pady=(0, 10));
        input_frame.columnconfigure(0, weight=1)
        self.message_var = tk.StringVar();
        self.message_entry = ttk.Entry(input_frame, textvariable=self.message_var);
        self.message_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(input_frame, text="Send", command=self.send_message).grid(row=0, column=1, padx=5)
        ttk.Button(input_frame, text="Send File", command=self.send_file).grid(row=0, column=2)

    def setup_event_handlers(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing);
        self.session_tree.bind("<<TreeviewSelect>>", self.on_session_select)
        self.message_entry.bind('<Return>', self.send_message);
        self.session_tree.bind("<Button-3>", self.show_item_info)

    def on_session_select(self, _=None):
        if not (sel := self.session_tree.selection()): return
        key = sel[0]
        if not key.startswith(('user_', 'group_')):
            if self.active_session_key in self.chat_sessions: self.chat_sessions[self.active_session_key][
                'widget'].pack_forget()
            self.active_session_key = key;
            self.chat_title_var.set(self.session_tree.item(key, "text"));
            return
        if self.active_session_key == key: return
        if self.active_session_key in self.chat_sessions: self.chat_sessions[self.active_session_key][
            'widget'].pack_forget()
        self.active_session_key = key
        if key in self.chat_sessions:
            self.chat_sessions[key]['widget'].pack(fill=tk.BOTH, expand=True)
            self.chat_title_var.set(self.session_tree.item(key, "text"));
            self.session_tree.item(key, tags=())
            if key not in self.loaded_history:
                target_type, target_id = key.split('_', 1)
                threading.Thread(target=lambda: self.client.socket.send(
                    SMPProtocol.encode(SMPProtocol.HISTORY_REQUEST, 0,
                                       {'target_type': target_type, 'target_id': target_id})), daemon=True).start()
        self.message_entry.focus_set()

    def process_messages(self):
        if msg := self.client.get_message(): self.handle_received_message(msg)
        self.after_id = self.root.after(100, self.process_messages)

    def handle_received_message(self, msg: dict):
        msg_type = msg.get('type')

        if msg_type == 'message':
            if msg.get('from_id') == 'system':
                context_uid = msg.get('context_uid')
                if context_uid:
                    session_key = f"user_{context_uid}"
                    self.add_message_to_session(session_key, "System", msg.get('message'), system=True)
            else:
                self.add_live_message(key=f"user_{msg['from_id']}", sender=msg.get('from_username'),
                                      message=msg.get('message'), uid=msg.get('from_id'),
                                      uname=msg.get('from_username'))

        elif msg_type == 'file_ready_for_download':
            from_user = msg.get('from_username')
            filename = msg.get('filename')
            filesize = msg.get('size')
            transfer_id = msg.get('transfer_id')
            session_key_found = None
            for key, session_data in self.chat_sessions.items():
                if key.startswith("user_") and f"{from_user} (" in session_data['name']:
                    session_key_found = key
                    break
            if session_key_found:
                cd = self.chat_sessions[session_key_found]['widget']
                cd.config(state=tk.NORMAL)
                download_tag = f"download_{transfer_id}"
                cd.insert(tk.END, f"\nSystem: You received '{filename}'.\n", ("system",))
                cd.insert(tk.END, "[Click here to download]", (download_tag, "system"))
                cd.insert(tk.END, "\n\n", ("system",))
                cd.tag_config(download_tag, foreground="blue", underline=True)
                cd.tag_bind(download_tag, "<Button-1>",
                            lambda e, t_id=transfer_id, f_name=filename, f_size=filesize: self.client.download_file(
                                t_id, f_name, f_size))
                cd.config(state=tk.DISABLED);
                cd.see(tk.END)
            else:
                messagebox.showinfo("File Received",
                                    f"You received a file '{filename}' from {from_user}. Open your chat with them to download it.")

        elif msg_type == 'friend_list':
            [self.add_friend_to_list(f['user_id'], f['username']) for f in msg.get('friends', [])]
        elif msg_type == 'group_list':
            [self.add_session(f"group_{g['group_id']}", f"{g.get('group_name', g['group_id'])} ({g['group_id']})",
                              self.groups_node) for g in msg.get('groups', [])]
        elif msg_type == 'friend_request_received':
            if messagebox.askyesno("Friend Request",
                                   f"User '{msg['from_username']}' ({msg['from_id']}) wants to be your friend. Accept?"): self.client.accept_friend_request(
                msg['from_id'])
        elif msg_type == 'friend_status_update' and msg.get('status') in ('added', 'accepted_your_request'):
            self.add_friend_to_list(msg['friend_id'], msg['friend_name'])
            if msg['status'] == 'accepted_your_request': messagebox.showinfo("Friend Added",
                                                                             f"'{msg['friend_name']}' has accepted your request!")
        elif msg_type == 'group_message':
            self.add_live_message(f"group_{msg.get('group')}", msg.get('from'), msg.get('message'), is_group=True,
                                  gname=msg.get('group_name'), gid=msg.get('group'))
        elif msg_type == 'history_response':
            session_key = f"{msg['target_type']}_{msg['target_id']}"
            if session_key in self.chat_sessions and session_key not in self.loaded_history:
                self.clear_session_messages(session_key)
                for hist_msg in msg.get('messages', []): self.add_message_to_session(session_key,
                                                                                     hist_msg.get('sender_name'),
                                                                                     hist_msg.get('content'),
                                                                                     history_msg=hist_msg)
                self.loaded_history.add(session_key)
        elif msg_type == 'file_notification':
            messagebox.showinfo("Incoming File",
                                f"User '{msg['from_username']}' is sending you the file '{msg['filename']}' ({msg['size'] / 1024:.2f} KB).")
        else:
            logging.warning(f"GUI received unhandled message: {msg}")

    def add_live_message(self, key, sender, message, uid=None, uname=None, is_group=False, gname=None, gid=None):
        if is_group:
            self.add_session(key, f"{gname} ({gid})", self.groups_node)
        else:
            self.add_friend_to_list(uid, uname)
        self.add_message_to_session(key, sender, message)
        if key != self.active_session_key: self.session_tree.item(key, tags=('new_message',))

    def add_friend_to_list(self, user_id, username):
        self.add_session(f"user_{user_id}", f"{username} ({user_id})", self.friends_node)

    def add_session(self, key, dname, parent):
        if key not in self.chat_sessions:
            self.session_tree.insert(parent, "end", iid=key, text=dname)
            cd = scrolledtext.ScrolledText(self.chat_container, wrap=tk.WORD, state=tk.DISABLED, padx=5, pady=5)
            cd.tag_config("own", justify='right', background="#E1FFC7", rmargin=10);
            cd.tag_config("other", justify='left', background="#FFFFFF", lmargin1=10, lmargin2=10);
            cd.tag_config("system", justify='center', foreground="gray")
            self.chat_sessions[key] = {'widget': cd, 'name': dname}

    def add_message_to_session(self, key, sender, msg, system=False, history_msg=None):
        if key not in self.chat_sessions or not sender: return
        cd = self.chat_sessions[key]['widget'];
        cd.config(state=tk.NORMAL)
        tag = "system" if system or sender == "System" else ("own" if sender == self.username else "other")
        ts = datetime.fromisoformat(history_msg['timestamp']).strftime(
            '%Y-%m-%d %H:%M:%S') if history_msg else datetime.now().strftime('%H:%M:%S')
        header = f"{sender} {ts}\n"
        if tag == "system":
            cd.insert(tk.END, f"--- {msg} ---\n", tag)
        else:
            cd.insert(tk.END, header, ("system",)); cd.insert(tk.END, f"{msg}\n\n", tag)
        cd.config(state=tk.DISABLED);
        cd.see(tk.END)

    def clear_session_messages(self, key):
        if key in self.chat_sessions: self.chat_sessions[key]['widget'].config(state=tk.NORMAL);
        self.chat_sessions[key]['widget'].delete('1.0', tk.END); self.chat_sessions[key]['widget'].config(
            state=tk.DISABLED)

    def send_message(self, _=None):
        if not (msg := self.message_var.get().strip()) or not self.active_session_key: return
        stype, tid = self.active_session_key.split('_', 1)
        success = (stype == "user" and self.client.send_private_message(tid, msg)) or (
                    stype == "group" and self.client.send_group_message(tid, msg))
        if success:
            self.add_message_to_session(self.active_session_key, self.username, msg); self.message_var.set("")
        else:
            messagebox.showerror("Error", "Failed to send message.")

    def create_group(self):
        if name := self.group_var.get().strip(): threading.Thread(
            target=lambda: self.root.after(0, self.handle_create_group_response, self.client.create_group(name)),
            daemon=True).start()

    def handle_create_group_response(self, resp):
        if resp and resp.get('status') == 'success':
            self.add_session(f"group_{resp['group_id']}", f"{resp['group_name']} ({resp['group_id']})",
                             self.groups_node);
            self.group_var.set("")
            messagebox.showinfo("Success", f"Group '{resp['group_name']}' created!\nID: {resp['group_id']}")
        else:
            messagebox.showerror("Error", resp.get('message', 'Failed') if resp else "Request timed out")

    def join_group(self):
        if gid := self.group_var.get().strip(): threading.Thread(
            target=lambda: self.root.after(0, self.handle_join_group_response, self.client.join_group(gid)),
            daemon=True).start()

    def handle_join_group_response(self, resp):
        if resp and resp.get('status') == 'success':
            self.add_session(f"group_{resp['group_id']}", f"{resp['group_name']} ({resp['group_id']})",
                             self.groups_node);
            self.group_var.set("")
            messagebox.showinfo("Success", f"Joined '{resp['group_name']}'")
        else:
            messagebox.showerror("Error", resp.get('message', 'Failed') if resp else "Request timed out")

    def send_file(self):
        if not self.active_session_key or not self.active_session_key.startswith(
            "user_"): return messagebox.showwarning("Warning", "Please select a friend to send the file to.")
        target_id = self.active_session_key.split('_', 1)[1]
        if file_path := filedialog.askopenfilename(title="Select a file to send"):
            threading.Thread(target=self.client.initiate_file_transfer, args=(file_path, target_id),
                             daemon=True).start()

    def show_item_info(self, event):
        if (iid := self.session_tree.identify_row(event.y)) and iid.startswith("group_"):
            gid = iid.split('_', 1)[1];
            messagebox.showinfo("Group Info", f"Group Name: {self.session_tree.item(iid, 'text')}\nGroup ID: {gid}")

    def add_friend(self):
        if not (tid := self.search_id_var.get().strip()): return messagebox.showwarning("Warning",
                                                                                        "Please enter a User ID.")
        if tid == self.user_id: return messagebox.showwarning("Warning", "You cannot add yourself.")
        threading.Thread(
            target=lambda: self.root.after(0, self.handle_add_friend_response, self.client.add_friend(tid)),
            daemon=True).start()

    def handle_add_friend_response(self, resp):
        if resp:
            messagebox.showinfo("Success", resp['message']) if resp.get(
                'status') == 'success' else messagebox.showerror("Error", resp['message'])
        else:
            messagebox.showerror("Error", "Request timed out.")

    def on_closing(self):
        if self.after_id: self.root.after_cancel(self.after_id)
        if self.client: self.client.disconnect()
        self.root.destroy()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    root = tk.Tk();
    style = ttk.Style();
    style.configure("Link.TButton", foreground="blue");
    app = LoginWindow(root);
    root.mainloop()