import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import time
import threading

# --- Configuration ---
REFRESH_RATE = 2000  # Milliseconds
ANOMALY_CPU_THRESHOLD = 80.0  # Alert if CPU > 80%
ANOMALY_MEM_THRESHOLD = 1024 * 1024 * 1024  # Alert if Mem > 1GB (1024MB)

class ProcessSentinelApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Process Sentinel [REAL-TIME MONITOR]")
        self.root.geometry("1100x700")
        
        # Color Palette (Dark Mode / Hacker Theme)
        self.bg_color = "#1e1e2e"
        self.fg_color = "#cdd6f4"
        self.accent_color = "#89b4fa"
        self.alert_color = "#f38ba8"
        self.panel_bg = "#313244"

        self.root.configure(bg=self.bg_color)
        self.setup_styles()

        # Data Containers
        self.sort_col = "cpu"
        self.sort_desc = True
        self.running = True

        # --- UI Layout ---
        
        # 1. Header Stats
        self.header_frame = tk.Frame(root, bg=self.panel_bg, height=80)
        self.header_frame.pack(fill="x", padx=10, pady=10)
        
        self.stats_label = tk.Label(
            self.header_frame, 
            text="Initializing System Link...", 
            font=("Consolas", 14, "bold"), 
            bg=self.panel_bg, 
            fg=self.accent_color
        )
        self.stats_label.pack(side="left", padx=20, pady=20)

        # 2. Main Content Area (Split Panes)
        self.main_pane = tk.PanedWindow(root, orient="horizontal", bg=self.bg_color, sashwidth=4)
        self.main_pane.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Left: Process Table
        self.tree_frame = tk.Frame(self.main_pane, bg=self.bg_color)
        self.main_pane.add(self.tree_frame, width=750)

        scrollbar = ttk.Scrollbar(self.tree_frame)
        scrollbar.pack(side="right", fill="y")

        cols = ("pid", "name", "user", "cpu", "mem", "status")
        self.tree = ttk.Treeview(
            self.tree_frame, 
            columns=cols, 
            show="headings", 
            yscrollcommand=scrollbar.set,
            selectmode="browse"
        )
        
        self.tree.heading("pid", text="PID", command=lambda: self.sort_by("pid"))
        self.tree.heading("name", text="Process Name", command=lambda: self.sort_by("name"))
        self.tree.heading("user", text="User", command=lambda: self.sort_by("user"))
        self.tree.heading("cpu", text="CPU %", command=lambda: self.sort_by("cpu"))
        self.tree.heading("mem", text="Memory (MB)", command=lambda: self.sort_by("mem"))
        self.tree.heading("status", text="Status", command=lambda: self.sort_by("status"))

        self.tree.column("pid", width=60, anchor="center")
        self.tree.column("name", width=200)
        self.tree.column("user", width=100)
        self.tree.column("cpu", width=80, anchor="e")
        self.tree.column("mem", width=100, anchor="e")
        self.tree.column("status", width=100)

        self.tree.pack(fill="both", expand=True)
        scrollbar.config(command=self.tree.yview)

        # Right: Anomaly & Control Panel
        self.side_panel = tk.Frame(self.main_pane, bg=self.panel_bg)
        self.main_pane.add(self.side_panel)

        tk.Label(self.side_panel, text="⚠ DETECTED ANOMALIES", bg=self.panel_bg, fg=self.alert_color, font=("Consolas", 12, "bold")).pack(pady=(15, 5))
        
        self.anomaly_list = tk.Listbox(
            self.side_panel, 
            bg="#45475a", 
            fg=self.fg_color, 
            borderwidth=0, 
            highlightthickness=0,
            font=("Consolas", 9)
        )
        self.anomaly_list.pack(fill="both", expand=True, padx=10, pady=5)

        # Actions
        btn_frame = tk.Frame(self.side_panel, bg=self.panel_bg)
        btn_frame.pack(fill="x", padx=10, pady=15)

        self.kill_btn = tk.Button(
            btn_frame, 
            text="KILL SELECTED PROCESS", 
            bg=self.alert_color, 
            fg="#11111b", 
            font=("Segoe UI", 10, "bold"),
            command=self.kill_process
        )
        self.kill_btn.pack(fill="x", pady=5)
        
        tk.Button(
            btn_frame,
            text="Refresh Now",
            bg=self.accent_color,
            fg="#11111b",
            command=self.refresh_processes
        ).pack(fill="x", pady=5)

        # Start Loop
        self.update_thread = threading.Thread(target=self.loop_update, daemon=True)
        self.update_thread.start()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=self.bg_color, foreground=self.fg_color, fieldbackground=self.bg_color, rowheight=25, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background=self.panel_bg, foreground="white", font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", self.accent_color)], foreground=[("selected", "#11111b")])

    def loop_update(self):
        while self.running:
            self.refresh_processes()
            time.sleep(REFRESH_RATE / 1000)

    def refresh_processes(self):
        cpu_total = psutil.cpu_percent()
        mem = psutil.virtual_memory()
        
        new_data = []
        anomalies_found = []

        # Iterate processes
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info', 'status']):
            try:
                pinfo = proc.info
                
                # --- FIX: IGNORE IDLE PROCESSES FIRST ---
                # Check for "System Idle Process" (Windows) or "idle" (Linux) or PID 0
                name_lower = pinfo['name'].lower()
                if "idle" in name_lower or pinfo['pid'] == 0:
                    continue
                # ----------------------------------------

                mem_mb = pinfo['memory_info'].rss / (1024 * 1024)
                
                # Anomaly Detection Logic
                if pinfo['cpu_percent'] > ANOMALY_CPU_THRESHOLD:
                    anomalies_found.append(f"[HIGH CPU] {pinfo['name']} ({pinfo['pid']}) - {pinfo['cpu_percent']}%")
                
                if pinfo['memory_info'].rss > ANOMALY_MEM_THRESHOLD:
                    anomalies_found.append(f"[MEM LEAK] {pinfo['name']} ({pinfo['pid']}) - {int(mem_mb)}MB")

                new_data.append({
                    "pid": pinfo['pid'],
                    "name": pinfo['name'],
                    "user": pinfo['username'] or "System",
                    "cpu": pinfo['cpu_percent'],
                    "mem": mem_mb,
                    "status": pinfo['status']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        self.root.after(0, lambda: self.update_ui(new_data, cpu_total, mem.percent, anomalies_found))

    def update_ui(self, data, cpu_total, mem_percent, anomalies):
        self.stats_label.config(text=f"CPU: {cpu_total}%   |   RAM: {mem_percent}%   |   PROCS: {len(data)}")

        key = self.sort_col
        data.sort(key=lambda x: x[key], reverse=self.sort_desc)

        self.tree.delete(*self.tree.get_children())
        for item in data:
            tags = ()
            if item['cpu'] > 50: tags = ('high_load',)
            self.tree.insert("", "end", values=(
                item['pid'], item['name'], item['user'], f"{item['cpu']:.1f}", f"{item['mem']:.1f}", item['status']
            ), tags=tags)

        self.tree.tag_configure('high_load', foreground=self.alert_color)

        self.anomaly_list.delete(0, tk.END)
        if not anomalies:
            self.anomaly_list.insert(tk.END, ">> System Nominal")
        else:
            for alert in anomalies:
                self.anomaly_list.insert(tk.END, f"⚠ {alert}")
                self.anomaly_list.itemconfig(tk.END, {'fg': self.alert_color})

    def sort_by(self, col):
        if self.sort_col == col:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_col = col
            self.sort_desc = True
        self.refresh_processes()

    def kill_process(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Selection Error", "Please select a process to terminate.")
            return

        item = self.tree.item(selected[0])
        pid = item['values'][0]
        name = item['values'][1]

        confirm = messagebox.askyesno("Confirm Kill", f"Are you sure you want to terminate:\n\n{name} (PID: {pid})?")
        if confirm:
            try:
                p = psutil.Process(pid)
                p.terminate()
                messagebox.showinfo("Success", f"Process {pid} terminated.")
                self.refresh_processes() 
            except Exception as e:
                messagebox.showerror("Error", f"Failed: {str(e)}")

    def on_close(self):
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ProcessSentinelApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()