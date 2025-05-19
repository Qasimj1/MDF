import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
from ppadb.client import Client as AdbClient
import os
import re
import time
from datetime import datetime
from PIL import Image, ImageTk
from scapy.all import rdpcap, IP, DNS
import threading
import queue
import subprocess

# Set appearance mode and default color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class AdvancedAndroidForensicsTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Android Forensics Tool")
        self.root.geometry("1000x700")
        self.root.minsize(600, 400)

        # Fonts
        self.header_font = ("Roboto", 18, "bold")
        self.body_font = ("Roboto", 12)
        self.mono_font = ("Roboto Mono", 11)

        # Initialize ADB client
        try:
            self.client = AdbClient(host="127.0.0.1", port=5037)
        except RuntimeError as e:
            messagebox.showerror("ADB Error", f"Failed to connect to ADB server: {str(e)}\nPlease ensure ADB is running (adb start-server) and try again.")
            self.root.destroy()
            return
        
        self.device = None
        self.current_path = "/"
        self.extracted_data = {
            "logs": "",
            "call_logs": "",
            "messages": "",
            "network": "",
            "packages": [],
            "files": [],
            "realtime_logs": []
        }
        
        # Real-time logging control
        self.is_capturing_logs = False
        self.log_queue = queue.Queue()
        self.realtime_thread = None
        
        # Create GUI elements
        self.create_widgets()
        
        # Check for connected devices periodically
        self.check_device_connection()

    def create_widgets(self):
        # Main container
        self.main_frame = ctk.CTkFrame(self.root, fg_color="#1e1e1e")
        self.main_frame.pack(fill="both", expand=True)
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)

        # Top bar
        top_bar = ctk.CTkFrame(self.main_frame, fg_color="#2a2a2a", height=50, corner_radius=0)
        top_bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        top_bar.grid_columnconfigure(1, weight=1)

        title_label = ctk.CTkLabel(top_bar, text="Android Forensics Tool", font=self.header_font, text_color="#00b7eb")
        title_label.grid(row=0, column=0, padx=20, pady=10, sticky="w")

        self.status_label = ctk.CTkLabel(top_bar, text="No device connected", font=self.body_font, text_color="#ffffff")
        self.status_label.grid(row=0, column=1, padx=20, pady=10, sticky="e")

        # Left sidebar - File Explorer
        sidebar = ctk.CTkFrame(self.main_frame, fg_color="#252525", width=300, corner_radius=10)
        sidebar.grid(row=1, column=0, sticky="nsew", padx=(10, 5), pady=10)
        sidebar.grid_rowconfigure(2, weight=1)

        self.path_label = ctk.CTkLabel(sidebar, text=f"Path: {self.current_path}", font=self.body_font, text_color="#bbbbbb")
        self.path_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="w")

        # File explorer treeview
        style = ttk.Style()
        style.configure("Treeview", background="#252525", foreground="#ffffff", fieldbackground="#252525", font=self.body_font)
        style.configure("Treeview.Heading", background="#3c3c3c", foreground="#00b7eb", font=self.body_font)

        self.tree = ttk.Treeview(sidebar, columns=("size", "type"), style="Treeview", height=15)
        self.tree.heading("#0", text="Name")
        self.tree.heading("size", text="Size")
        self.tree.heading("type", text="Type")
        self.tree.column("#0", width=150, stretch=True)
        self.tree.column("size", width=80, stretch=True)
        self.tree.column("type", width=80, stretch=True)
        self.tree.grid(row=2, column=0, padx=10, pady=5, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self.show_file_metadata)
        self.tree.bind("<Double-1>", self.on_double_click)

        # Sidebar buttons
        button_frame = ctk.CTkFrame(sidebar, fg_color="#252525")
        button_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

        buttons = [
            ("Up", self.go_up, None),
            ("Download", self.download_file, None),
            ("/sdcard", self.go_to_sdcard, None),
            ("Refresh", self.load_files, None)
        ]
        for idx, (text, cmd, icon) in enumerate(buttons):
            btn = ctk.CTkButton(button_frame, text=text, command=cmd, compound="left",
                               fg_color="#3c3c3c", hover_color="#00b7eb", font=self.body_font, width=70)
            btn.grid(row=0, column=idx, padx=2)

        # Main content area
        content_frame = ctk.CTkFrame(self.main_frame, fg_color="#252525", corner_radius=10)
        content_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 10), pady=10)
        content_frame.grid_rowconfigure(1, weight=1)
        content_frame.grid_columnconfigure(0, weight=1)

        # Action buttons
        action_frame = ctk.CTkFrame(content_frame, fg_color="#252525")
        action_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        action_buttons = [
            ("Device Info", self.get_device_info, None),
            ("System Logs", self.collect_logs, None),
            ("Call Logs", self.get_call_logs, None),
            ("Messages", self.get_messages, None),
            ("Network", self.monitor_network, None),
            ("Packages", self.get_installed_packages, None),
            ("Real-Time Logs", self.toggle_realtime_logs, None),
            ("Analyze Data", self.analyze_data, None)
        ]
        for idx, (text, cmd, icon) in enumerate(action_buttons):
            btn = ctk.CTkButton(action_frame, text=text, command=cmd, compound="left",
                               fg_color="#3c3c3c", hover_color="#00b7eb", font=self.body_font, width=100)
            btn.grid(row=0, column=idx, padx=5)

        # Tabbed output
        self.tab_view = ctk.CTkTabview(content_frame, fg_color="#1e1e1e", segmented_button_selected_color="#00b7eb")
        self.tab_view.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.tab_view.add("Output")
        self.tab_view.add("Metadata")
        self.tab_view.add("Analysis")
        self.tab_view.add("Real-Time Logs")

        self.output_text = ctk.CTkTextbox(self.tab_view.tab("Output"), font=self.mono_font, text_color="#ffffff",
                                        fg_color="#1e1e1e", wrap="word")
        self.output_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.metadata_text = ctk.CTkTextbox(self.tab_view.tab("Metadata"), font=self.mono_font, text_color="#ffffff",
                                          fg_color="#1e1e1e", wrap="word")
        self.metadata_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.analysis_text = ctk.CTkTextbox(self.tab_view.tab("Analysis"), font=self.mono_font, text_color="#ffffff",
                                          fg_color="#1e1e1e", wrap="word")
        self.analysis_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.realtime_text = ctk.CTkTextbox(self.tab_view.tab("Real-Time Logs"), font=self.mono_font, text_color="#ffffff",
                                           fg_color="#1e1e1e", wrap="word")
        self.realtime_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Status bar
        status_bar = ctk.CTkFrame(self.main_frame, fg_color="#2a2a2a", height=30, corner_radius=0)
        status_bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        status_bar.grid_columnconfigure(1, weight=1)

        self.status_text = ctk.CTkLabel(status_bar, text="Ready", font=self.body_font, text_color="#888888")
        self.status_text.grid(row=0, column=0, padx=10, sticky="w")

        copyright_text = ctk.CTkLabel(status_bar, text="© 2025 - Developed by Alpha", font=self.body_font, text_color="#888888")
        copyright_text.grid(row=0, column=1, padx=10, sticky="e")

        # Exit button
        exit_btn = ctk.CTkButton(self.main_frame, text="Exit", command=self.root.quit, fg_color="#d32f2f",
                                 hover_color="#3c3c3c", font=self.body_font, width=100)
        exit_btn.grid(row=3, column=1, padx=10, pady=10, sticky="e")

    def is_rooted(self):
        if not self.device:
            return False
        try:
            result = self.run_adb_command("whoami")
            if "root" in result.lower():
                return True
            su_check = self.run_adb_command("which su")
            return bool(su_check and "su" in su_check)
        except Exception:
            return False

    def check_device_connection(self):
        try:
            devices = self.client.devices()
            if devices:
                self.device = devices[0]
                is_rooted = self.is_rooted()
                self.status_label.configure(text=f"Connected: {self.device.serial}{' (Rooted)' if is_rooted else ''}")
                self.status_text.configure(text=f"Device: {self.device.serial}{' (Rooted)' if is_rooted else ''}")
                self.load_files()
            else:
                self.device = None
                self.status_label.configure(text="No device connected")
                self.status_text.configure(text="No device connected")
                self.tree.delete(*self.tree.get_children())
                if self.is_capturing_logs:
                    self.stop_realtime_logs()
        except RuntimeError as e:
            self.status_label.configure(text=f"ADB Error: {str(e)}")
            self.status_text.configure(text=f"ADB Error: {str(e)}")
            if self.is_capturing_logs:
                self.stop_realtime_logs()
        self.root.after(2000, self.check_device_connection)

    def run_adb_command(self, command):
        if not self.device:
            return ""
        try:
            return self.device.shell(command).strip()
        except Exception as e:
            return f"Error: {str(e)}"

    def save_to_file(self, data, filename, extension="txt"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = "forensic_data"
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, f"{filename}_{timestamp}.{extension}")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(data)
        return filepath

    def toggle_realtime_logs(self):
        if not self.device:
            self.realtime_text.delete("1.0", "end")
            self.realtime_text.insert("1.0", "No device connected.\n")
            return
        if self.is_capturing_logs:
            self.stop_realtime_logs()
        else:
            self.start_realtime_logs()

    def start_realtime_logs(self):
        self.is_capturing_logs = True
        self.extracted_data["realtime_logs"] = []
        self.realtime_text.delete("1.0", "end")
        self.realtime_text.insert("1.0", "Starting real-time log capture...\n")
        self.status_text.configure(text="Capturing real-time logs...")
        self.realtime_thread = threading.Thread(target=self.capture_realtime_logs)
        self.realtime_thread.daemon = True
        self.realtime_thread.start()
        self.root.after(100, self.update_realtime_logs)

    def stop_realtime_logs(self):
        self.is_capturing_logs = False
        self.status_text.configure(text="Real-time log capture stopped")
        self.realtime_text.insert("end", "\nReal-time log capture stopped.\n")
        if self.extracted_data["realtime_logs"]:
            logs = "\n".join([entry["raw"] for entry in self.extracted_data["realtime_logs"]])
            filepath = self.save_to_file(logs, "realtime_logs")
            self.realtime_text.insert("end", f"Saved to: {filepath}\n")

    def capture_realtime_logs(self):
        if not self.device:
            self.log_queue.put({"raw": "Error: No device connected"})
            self.is_capturing_logs = False
            return
        try:
            # Use main buffer for non-rooted devices, all buffers for rooted
            cmd = ["adb", "-s", self.device.serial, "logcat", "-b", "main"] if not self.is_rooted() else ["adb", "-s", self.device.serial, "logcat"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="ignore")
            while self.is_capturing_logs:
                line = process.stdout.readline().strip()
                if not line:
                    # Check if process has terminated
                    if process.poll() is not None:
                        error = process.stderr.read().strip()
                        self.log_queue.put({"raw": f"Error capturing logs: {error or 'ADB process terminated'}"})
                        break
                entry = {"raw": line}
                match = re.match(r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+(\w+)/(\S+):\s+(.+)', line)
                if match:
                    timestamp, level, tag, message = match.groups()
                    entry.update({
                        "timestamp": timestamp,
                        "level": level,
                        "tag": tag,
                        "message": message
                    })
                self.log_queue.put(entry)
            # Cleanup
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
        except Exception as e:
            self.log_queue.put({"raw": f"Error capturing logs: {str(e)}"})
            self.is_capturing_logs = False

    def update_realtime_logs(self):
        try:
            while True:
                entry = self.log_queue.get_nowait()
                self.extracted_data["realtime_logs"].append(entry)
                self.realtime_text.insert("end", entry["raw"] + "\n")
                self.realtime_text.see("end")
                # Analyze log entry for suspicious activity
                self.analyze_realtime_log_entry(entry)
        except queue.Empty:
            pass
        if self.is_capturing_logs:
            self.root.after(100, self.update_realtime_logs)

    def analyze_realtime_log_entry(self, entry):
        if "message" not in entry:
            return
        log_patterns = [
            (r"Permission denied", "Unauthorized access attempt", "Check app permissions or SELinux policies"),
            (r"SELinux.*denied", "SELinux policy violation", "Investigate restricted operations"),
            (r"error.*crash", "Application crash", "Review app stability and logs"),
            (r"suspicious|malware|exploit|unauthorized", "Potential malicious activity", "Perform deeper malware scan"),
            (r"exception", "Runtime exception", "Check app behavior and stack traces"),
            (r"root|su", "Root access attempt", "Verify if root access is authorized"),
            (r"network.*error", "Network connectivity issue", "Check network configuration"),
            (r"authentication.*failed", "Authentication failure", "Investigate potential brute-force attempts")
        ]
        for pattern, desc, action in log_patterns:
            if re.search(pattern, entry["message"], re.IGNORECASE):
                finding = {
                    "type": "Real-Time Logs",
                    "description": f"{desc} at {entry.get('timestamp', 'Unknown')} ({entry.get('tag', 'Unknown')}): {entry['message'][:100]}...",
                    "action": action
                }
                self.analysis_text.insert("end", f"[Real-Time] {finding['description']}\n  Action: {finding['action']}\n\n")
                self.analysis_text.see("end")
                # Save finding to file
                filepath = self.save_to_file(f"{finding['description']}\nAction: {finding['action']}", "realtime_suspicious")
                self.realtime_text.insert("end", f"Suspicious activity logged to: {filepath}\n")

    def get_installed_packages(self):
        if not self.device:
            return
        packages = self.run_adb_command("pm list packages")
        self.extracted_data["packages"] = packages.split('\n') if packages and "Error" not in packages else []
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", "Installed Packages:\n" + "="*20 + "\n")
        if self.extracted_data["packages"]:
            self.output_text.insert("end", "\n".join(self.extracted_data["packages"]) + "\n")
            filepath = self.save_to_file("\n".join(self.extracted_data["packages"]), "packages")
            self.output_text.insert("end", f"\nSaved to: {filepath}")
        else:
            self.output_text.insert("end", "Failed to retrieve packages. Possible permission issue.\n")

    def load_files(self):
        if not self.device:
            return
        self.tree.delete(*self.tree.get_children())
        self.path_label.configure(text=f"Path: {self.current_path}")
        files = self.run_adb_command(f"ls -la {self.current_path}")
        self.extracted_data["files"] = []
        if "Error" in files or "permission denied" in files.lower() or "not found" in files.lower():
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", f"Unable to list files in {self.current_path}: {files}\n")
            self.output_text.insert("end", "Try 'Go to /sdcard' if root access is unavailable.")
            return
        for line in files.split('\n'):
            if line.strip() and not line.startswith('total'):
                parts = line.split()
                if len(parts) >= 8:
                    perms = parts[0]
                    size = parts[4]
                    name = " ".join(parts[7:])
                    is_dir = perms.startswith('d')
                    if name not in [".", ".."]:
                        self.tree.insert("", "end", text=name, values=(size, "Directory" if is_dir else "File"))
                        self.extracted_data["files"].append({"name": name, "perms": perms, "size": size, "is_dir": is_dir})

    def go_up(self):
        if self.current_path != "/":
            self.current_path = os.path.dirname(self.current_path.rstrip('/'))
            if not self.current_path:
                self.current_path = "/"
            self.load_files()

    def go_to_sdcard(self):
        self.current_path = "/sdcard"
        self.load_files()

    def on_double_click(self, event):
        item = self.tree.selection()
        if not item:
            return
        filename = self.tree.item(item[0], "text")
        item_type = self.tree.item(item[0], "values")[1]
        if item_type == "Directory":
            self.current_path = os.path.join(self.current_path, filename)
            self.load_files()

    def show_file_metadata(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        item = selection[0]
        filename = self.tree.item(item, "text")
        file_path = os.path.join(self.current_path, filename)
        metadata = {}
        stat_output = self.run_adb_command(f"stat {file_path}")
        if "Error" not in stat_output:
            for line in stat_output.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    metadata[key.strip()] = value.strip()
        ls_output = self.run_adb_command(f"ls -l {file_path}")
        if "Error" not in ls_output and ls_output:
            parts = ls_output.split()
            if len(parts) >= 8:
                metadata["Permissions"] = parts[0]
                metadata["Size"] = parts[4]
                metadata["Modification Time"] = " ".join(parts[5:8])
        file_type = self.run_adb_command(f"file {file_path}")
        if "Error" not in file_type:
            metadata["File Type"] = file_type.split(':', 1)[-1].strip()
        self.metadata_text.delete("1.0", "end")
        self.metadata_text.insert("1.0", f"Metadata for {file_path}:\n" + "="*40 + "\n")
        if metadata:
            for key, value in metadata.items():
                self.metadata_text.insert("end", f"{key}: {value}\n")
        else:
            self.metadata_text.insert("end", "Unable to retrieve metadata. Possible permission issue or file not found.\n")
            self.metadata_text.insert("end", f"Raw ls -l output: {ls_output}")

    def download_file(self):
        item = self.tree.selection()
        if not item:
            messagebox.showwarning("Warning", "Please select a file to download")
            return
        filename = self.tree.item(item[0], "text")
        file_path = os.path.join(self.current_path, filename)
        local_path = filedialog.asksaveasfilename(initialfile=filename)
        if local_path:
            try:
                self.device.pull(file_path, local_path)
                messagebox.showinfo("Success", f"File downloaded to: {local_path}")
                self.output_text.insert("end", f"File downloaded to: {local_path}\n")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to download file: {str(e)}")

    def get_device_info(self):
        if not self.device:
            return
        info = "Device Information:\n" + "="*20 + "\n"
        info += f"Model: {self.run_adb_command('getprop ro.product.model')}\n"
        info += f"Manufacturer: {self.run_adb_command('getprop ro.product.manufacturer')}\n"
        info += f"Android Version: {self.run_adb_command('getprop ro.build.version.release')}\n"
        info += f"Serial Number: {self.device.serial}\n"
        info += f"IMEI: {self.run_adb_command('dumpsys iphonesubinfo')}\n"
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", info)
        filepath = self.save_to_file(info, "device_info")
        self.output_text.insert("end", f"\nSaved to: {filepath}")

    def collect_logs(self):
        if not self.device:
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", "No device connected.\n")
            return
        
        self.output_text.delete("1.0", "end")
        self.status_text.configure(text="Collecting logs...")

        is_rooted = self.is_rooted()
        logs = ""
        error_msg = ""

        if is_rooted:
            logs = self.run_adb_command("logcat -d")
            if "Error" in logs or not logs:
                error_msg = f"Failed to retrieve logs with root access: {logs}\n"
        else:
            logs = self.run_adb_command("logcat -d -b main")
            if "Error" in logs or not logs:
                error_msg = f"Failed to retrieve logs (non-rooted device): {logs}\n"
                self.run_adb_command("pm grant com.android.shell android.permission.READ_LOGS")
                logs = self.run_adb_command("logcat -d -b main")
                if "Error" in logs or not logs:
                    error_msg = f"Failed to retrieve logs after attempting permission grant: {logs}\n"

        if error_msg or not logs:
            self.output_text.insert("1.0", error_msg or "No logs retrieved.\n")
            self.output_text.insert("end", "Troubleshooting:\n"
                                          "- Ensure USB debugging is enabled in Developer Options.\n"
                                          "- For non-rooted devices, try enabling 'View system logs' in Developer Options (if available).\n"
                                          "- Use a rooted device or emulator for full logcat access.\n"
                                          "- Check ADB server status (run 'adb start-server').\n"
                                          "- Restart the device and reconnect via ADB.\n")
            self.extracted_data["logs"] = ""
            self.status_text.configure(text="Log collection failed")
            return

        self.extracted_data["logs"] = logs
        self.output_text.insert("1.0", logs[:5000] + "\n[Truncated - full logs saved to file]")
        filepath = self.save_to_file(logs, "system_logs")
        self.output_text.insert("end", f"\nSaved to: {filepath}")
        self.status_text.configure(text="Log collection complete")

    def get_call_logs(self):
        if not self.device:
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", "No device connected.\n")
            return
        call_logs = self.run_adb_command("content query --uri content://call_log/calls")
        if "Error" in call_logs or not call_logs:
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", "Failed to retrieve call logs.\nPossible reasons:\n"
                                          "- Insufficient permissions (requires READ_CALL_LOG permission)\n"
                                          "- Call log access restricted on this device\n"
                                          "- Try running with elevated privileges or on a rooted device\n")
            return
        self.extracted_data["call_logs"] = call_logs
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", call_logs[:5000] + "\n[Truncated - full logs saved to file]")
        filepath = self.save_to_file(call_logs, "call_logs")
        self.output_text.insert("end", f"\nSaved to: {filepath}")

    def get_messages(self):
        if not self.device:
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", "No device connected.\n")
            return
        messages = self.run_adb_command("content query --uri content://sms/")
        if "Error" in messages or not messages:
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", "Failed to retrieve messages.\nPossible reasons:\n"
                                          "- Insufficient permissions (requires READ_SMS permission)\n"
                                          "- SMS access restricted on this device\n"
                                          "- Try running with elevated privileges or on a rooted device\n")
            return
        self.extracted_data["messages"] = messages
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", messages[:5000] + "\n[Truncated - full logs saved to file]")
        filepath = self.save_to_file(messages, "messages")
        self.output_text.insert("end", f"\nSaved to: {filepath}")

    def monitor_network(self):
        if not self.device:
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", "No device connected.\n")
            return
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", "Starting network monitoring...\n")
        try:
            self.device.shell("tcpdump -i any -s 0 -w /sdcard/network.pcap &")
            self.output_text.insert("end", "Network capture started. Wait 5 seconds...\n")
            time.sleep(5)
            self.device.shell("pkill tcpdump")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            local_path = f"forensic_data/network_{timestamp}.pcap"
            os.makedirs("forensic_data", exist_ok=True)
            self.device.pull("/sdcard/network.pcap", local_path)
            self.extracted_data["network"] = local_path
            self.output_text.insert("end", f"Network capture saved to: {local_path}")
            filepath = self.save_to_file(f"Captured network data saved to: {local_path}", "network", "txt")
            self.output_text.insert("end", f"\nSaved metadata to: {filepath}")
        except Exception as e:
            self.output_text.insert("end", f"Error capturing network: {str(e)}")
            self.extracted_data["network"] = f"Error: {str(e)}"

    def analyze_data(self):
        if not self.device:
            self.analysis_text.delete("1.0", "end")
            self.analysis_text.insert("1.0", "No device connected. Please connect a device and extract data first.\n")
            return
        
        self.status_text.configure(text="Analyzing data...")
        self.analysis_text.delete("1.0", "end")
        report = ["Forensic Data Analysis Report", "="*40, ""]
        suspicious_findings = []
        
        # Data Summary
        report.append("Data Summary:")
        report.append("-" * 20)
        log_count = len(self.extracted_data["logs"].split('\n')) if self.extracted_data["logs"] else 0
        report.append(f"System Logs: {log_count} entries")
        call_log_count = len(self.extracted_data["call_logs"].split('\n')) if self.extracted_data["call_logs"] and "Error" not in self.extracted_data["call_logs"] else 0
        report.append(f"Call Logs: {call_log_count} records")
        message_count = len(self.extracted_data["messages"].split('\n')) if self.extracted_data["messages"] and "Error" not in self.extracted_data["messages"] else 0
        report.append(f"Messages: {message_count} messages")
        network_status = "Captured" if self.extracted_data["network"] and "Error" not in self.extracted_data["network"] else "Not captured"
        report.append(f"Network Data: {network_status}")
        package_count = len(self.extracted_data["packages"])
        report.append(f"Installed Packages: {package_count} packages")
        file_count = len(self.extracted_data["files"])
        report.append(f"Files (current directory): {file_count} items")
        realtime_log_count = len(self.extracted_data["realtime_logs"])
        report.append(f"Real-Time Logs: {realtime_log_count} entries")
        report.append("")

        # Real-Time Logs Analysis
        report.append("Real-Time Logs Analysis:")
        report.append("-" * 20)
        if self.extracted_data["realtime_logs"]:
            report.append("Detailed Real-Time Log Analysis:")
            log_entries = self.extracted_data["realtime_logs"]
            log_patterns = [
                (r"Permission denied", "Unauthorized access attempt", "Check app permissions or SELinux policies"),
                (r"SELinux.*denied", "SELinux policy violation", "Investigate restricted operations"),
                (r"error.*crash", "Application crash", "Review app stability and logs"),
                (r"suspicious|malware|exploit|unauthorized", "Potential malicious activity", "Perform deeper malware scan"),
                (r"exception", "Runtime exception", "Check app behavior and stack traces"),
                (r"root|su", "Root access attempt", "Verify if root access is authorized"),
                (r"network.*error", "Network connectivity issue", "Check network configuration"),
                (r"authentication.*failed", "Authentication failure", "Investigate potential brute-force attempts")
            ]
            for entry in log_entries:
                if "message" not in entry:
                    continue
                for pattern, desc, action in log_patterns:
                    if re.search(pattern, entry["message"], re.IGNORECASE):
                        suspicious_findings.append({
                            "type": "Real-Time Logs",
                            "description": f"{desc} at {entry.get('timestamp', 'Unknown')} ({entry.get('tag', 'Unknown')}): {entry['message'][:100]}...",
                            "action": action
                        })
            report.append(f"Total Real-Time Log Entries: {len(log_entries)}")
            report.append("Sample Real-Time Log Entries:")
            for entry in log_entries[:5]:
                report.append(f"  - {entry.get('timestamp', 'Unknown')} {entry.get('level', 'Unknown')}/{entry.get('tag', 'Unknown')}: {entry['message'][:100] if 'message' in entry else entry['raw'][:100]}...")
        else:
            report.append("No real-time logs available for analysis.")
        report.append("")

        # Call Logs Analysis
        report.append("Call Logs Analysis:")
        report.append("-" * 20)
        if self.extracted_data["call_logs"] and "Error" not in self.extracted_data["call_logs"]:
            report.append("Detailed Call Records:")
            call_records = []
            frequent_numbers = {}
            international_calls = []
            for line in self.extracted_data["call_logs"].split('\n'):
                if not line.strip():
                    continue
                record = {}
                for item in line.split(','):
                    if '=' in item:
                        key, value = item.split('=', 1)
                        record[key.strip()] = value.strip()
                if 'number' in record and 'date' in record and 'type' in record:
                    call_records.append(record)
                    number = record['number']
                    frequent_numbers[number] = frequent_numbers.get(number, 0) + 1
                    if number.startswith('+') and number[1:3] != '1':
                        international_calls.append(record)

            for idx, record in enumerate(call_records, 1):
                call_type = {'1': 'Incoming', '2': 'Outgoing', '3': 'Missed'}.get(record.get('type'), 'Unknown')
                date = datetime.fromtimestamp(int(record['date']) / 1000).strftime('%Y-%m-%d %H:%M:%S')
                duration = int(record.get('duration', 0))
                number = record['number']
                report.append(f"Call {idx}:")
                report.append(f"  Number: {number}")
                report.append(f"  Type: {call_type}")
                report.append(f"  Date: {date}")
                report.append(f"  Duration: {duration} seconds")
                if frequent_numbers[number] > 5:
                    suspicious_findings.append({
                        "type": "Call Logs",
                        "description": f"Frequent calls to {number} ({frequent_numbers[number]} times)",
                        "action": "Investigate frequent contact for potential unauthorized communication"
                    })
                if number.startswith('+') and number[1:3] != '1':
                    suspicious_findings.append({
                        "type": "Call Logs",
                        "description": f"International call to {number} at {date}",
                        "action": "Verify legitimacy of international contact"
                    })
                if duration > 3600:
                    suspicious_findings.append({
                        "type": "Call Logs",
                        "description": f"Unusually long call to {number} ({duration} seconds) at {date}",
                        "action": "Investigate purpose of extended call"
                    })
                report.append("")

            report.append(f"Total Calls: {len(call_records)}")
            report.append(f"International Calls: {len(international_calls)}")
            report.append(f"Unique Numbers: {len(frequent_numbers)}")
            if frequent_numbers:
                report.append("Top 5 Frequent Numbers:")
                for number, count in sorted(frequent_numbers.items(), key=lambda x: x[1], reverse=True)[:5]:
                    report.append(f"  - {number}: {count} calls")
        else:
            report.append("No call logs available for analysis. Possible permission issue.")
        report.append("")

        # System Logs Analysis
        report.append("System Logs Analysis:")
        report.append("-" * 20)
        if self.extracted_data["logs"]:
            report.append("Detailed Log Analysis:")
            log_patterns = [
                (r"Permission denied", "Unauthorized access attempt", "Check app permissions or SELinux policies"),
                (r"SELinux.*denied", "SELinux policy violation", "Investigate restricted operations"),
                (r"error.*crash", "Application crash", "Review app stability and logs"),
                (r"suspicious|malware|exploit|unauthorized", "Potential malicious activity", "Perform deeper malware scan"),
                (r"exception", "Runtime exception", "Check app behavior and stack traces"),
                (r"root|su", "Root access attempt", "Verify if root access is authorized"),
                (r"network.*error", "Network connectivity issue", "Check network configuration"),
                (r"authentication.*failed", "Authentication failure", "Investigate potential brute-force attempts")
            ]
            log_entries = []
            for line in self.extracted_data["logs"].split('\n'):
                if not line.strip():
                    continue
                match = re.match(r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+(\w+)/(\S+):\s+(.+)', line)
                if match:
                    timestamp, level, tag, message = match.groups()
                    log_entries.append({"timestamp": timestamp, "level": level, "tag": tag, "message": message})
                    for pattern, desc, action in log_patterns:
                        if re.search(pattern, message, re.IGNORECASE):
                            suspicious_findings.append({
                                "type": "Logs",
                                "description": f"{desc} at {timestamp} ({tag}): {message[:100]}...",
                                "action": action
                            })

            report.append(f"Total Log Entries: {len(log_entries)}")
            report.append("Log Levels:")
            levels = {}
            for entry in log_entries:
                levels[entry['level']] = levels.get(entry['level'], 0) + 1
            for level, count in levels.items():
                report.append(f"  - {level}: {count}")
            report.append("Top 5 Tags:")
            tags = {}
            for entry in log_entries:
                tags[entry['tag']] = tags.get(entry['tag'], 0) + 1
            for tag, count in sorted(tags.items(), key=lambda x: x[1], reverse=True)[:5]:
                report.append(f"  - {tag}: {count}")
            report.append("Sample Log Entries:")
            for entry in log_entries[:5]:
                report.append(f"  - {entry['timestamp']} {entry['level']}/{entry['tag']}: {entry['message'][:100]}...")
        else:
            report.append("No logs available for analysis. Possible permission issue.")
        report.append("")

        # Messages Analysis
        report.append("Messages Analysis:")
        report.append("-" * 20)
        if self.extracted_data["messages"] and "Error" not in self.extracted_data["messages"]:
            report.append("Detailed Message Analysis:")
            messages = []
            url_count = 0
            sensitive_count = 0
            for line in self.extracted_data["messages"].split('\n'):
                if not line.strip():
                    continue
                message = {}
                for item in line.split(','):
                    if '=' in item:
                        key, value = item.split('=', 1)
                        message[key.strip()] = value.strip()
                if 'address' in message and 'body' in message:
                    messages.append(message)
                    if re.search(r"http[s]?://[^\s]+", message['body'], re.IGNORECASE):
                        url_count += 1
                        suspicious_findings.append({
                            "type": "Messages",
                            "description": f"Potential phishing link in message from {message['address']}: {message['body'][:100]}...",
                            "action": "Verify URL legitimacy"
                        })
                    if re.search(r"password|login|credit|bank|ssn", message['body'], re.IGNORECASE):
                        sensitive_count += 1
                        suspicious_findings.append({
                            "type": "Messages",
                            "description": f"Sensitive data in message from {message['address']}: {message['body'][:100]}...",
                            "action": "Secure sensitive information and alert user"
                        })

            for idx, message in enumerate(messages, 1):
                date = datetime.fromtimestamp(int(message.get('date', 0)) / 1000).strftime('%Y-%m-%d %H:%M:%S') if message.get('date') else "Unknown"
                report.append(f"Message {idx}:")
                report.append(f"  From/To: {message['address']}")
                report.append(f"  Date: {date}")
                report.append(f"  Type: {'Sent' if message.get('type') == '2' else 'Received'}")
                report.append(f"  Body: {message['body'][:100]}...")
                report.append("")

            report.append(f"Total Messages: {len(messages)}")
            report.append(f"Messages with URLs: {url_count}")
            report.append(f"Messages with Sensitive Keywords: {sensitive_count}")
        else:
            report.append("No messages available for analysis. Possible permission issue.")
        report.append("")

        # Network Analysis
        report.append("Network Analysis:")
        report.append("-" * 20)
        if self.extracted_data["network"] and "Error" not in self.extracted_data["network"]:
            try:
                packets = rdpcap(self.extracted_data["network"])
                ip_counts = {}
                dns_queries = []
                malicious_ips = ["192.168.1.100", "10.0.0.1"]
                for pkt in packets:
                    if IP in pkt:
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                        ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1
                        if src_ip in malicious_ips or dst_ip in malicious_ips:
                            suspicious_findings.append({
                                "type": "Network",
                                "description": f"Connection to malicious IP: {src_ip} -> {dst_ip}",
                                "action": "Block suspicious IP and investigate further"
                            })
                    if DNS in pkt and pkt[DNS].qr == 0:
                        query = pkt[DNS].qname.decode() if pkt[DNS].qname else "Unknown"
                        dns_queries.append(query)
                        if re.search(r"suspicious|malware|phishing", query, re.IGNORECASE):
                            suspicious_findings.append({
                                "type": "Network",
                                "description": f"Suspicious DNS query: {query}",
                                "action": "Investigate domain for potential malicious activity"
                            })

                report.append(f"Total Packets: {len(packets)}")
                report.append(f"Unique IPs: {len(ip_counts)}")
                report.append("Top 5 IPs by Packet Count:")
                for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                    report.append(f"  - {ip}: {count} packets")
                report.append(f"DNS Queries: {len(dns_queries)}")
                if dns_queries:
                    report.append("Sample DNS Queries:")
                    for query in dns_queries[:5]:
                        report.append(f"  - {query}")
            except Exception as e:
                report.append(f"Error analyzing network data: {str(e)}")
                suspicious_findings.append({
                    "type": "Network",
                    "description": f"Failed to parse network data: {str(e)}",
                    "action": "Verify pcap file integrity"
                })
        else:
            report.append("No network data available for analysis. Possible capture failure.")
        report.append("")

        # Packages Analysis
        report.append("Packages Analysis:")
        report.append("-" * 20)
        if self.extracted_data["packages"]:
            suspicious_apps = ["com.example.malware", "org.unknown.app"]
            non_system_apps = [pkg for pkg in self.extracted_data["packages"] if not pkg.startswith("com.android.")]
            for pkg in self.extracted_data["packages"]:
                if any(sus_pkg in pkg for sus_pkg in suspicious_apps):
                    suspicious_findings.append({
                        "type": "Packages",
                        "description": f"Suspicious app detected: {pkg}",
                        "action": "Uninstall or scan with antivirus"
                    })
            report.append(f"Total Packages: {package_count}")
            report.append(f"Non-System Packages: {len(non_system_apps)}")
            if non_system_apps:
                report.append("Sample Non-System Packages:")
                for pkg in non_system_apps[:5]:
                    report.append(f"  - {pkg}")
        else:
            report.append("No packages available for analysis.")
        report.append("")

        # Files Analysis
        report.append("Files Analysis:")
        report.append("-" * 20)
        if self.extracted_data["files"]:
            suspicious_extensions = [".apk", ".exe", ".sh"]
            hidden_files = [f for f in self.extracted_data["files"] if f["name"].startswith(".")]
            for file_info in self.extracted_data["files"]:
                if not file_info["is_dir"]:
                    if any(file_info["name"].endswith(ext) for ext in suspicious_extensions):
                        suspicious_findings.append({
                            "type": "Files",
                            "description": f"Suspicious file extension: {file_info['name']} (Permissions: {file_info['perms']})",
                            "action": "Scan file for malware"
                        })
                    if "rwxr-xr-x" in file_info["perms"]:
                        suspicious_findings.append({
                            "type": "Files",
                            "description": f"Executable permissions on file: {file_info['name']}",
                            "action": "Verify file purpose"
                        })
            report.append(f"Total Files/Directories: {file_count}")
            report.append(f"Hidden Files: {len(hidden_files)}")
            report.append(f"Suspicious Extensions Detected: {len([f for f in self.extracted_data['files'] if any(f['name'].endswith(ext) for ext in suspicious_extensions)])}")
            if hidden_files:
                report.append("Sample Hidden Files:")
                for file in hidden_files[:5]:
                    report.append(f"  - {file['name']} (Size: {file['size']})")
        else:
            report.append("No files available for analysis.")
        report.append("")

        # Suspicious Findings
        report.append("Suspicious Activities:")
        report.append("-" * 20)
        if suspicious_findings:
            report.append(f"WARNING: {len(suspicious_findings)} suspicious activities detected:")
            for idx, finding in enumerate(suspicious_findings, 1):
                report.append(f"Finding {idx} [{finding['type']}]:")
                report.append(f"  Description: {finding['description']}")
                report.append(f"  Recommended Action: {finding['action']}")
                report.append("")
        else:
            report.append("No suspicious activities detected. Data appears safe.")
        report.append("")

        # Display report
        self.analysis_text.insert("1.0", "\n".join(report))
        self.status_text.configure(text="Analysis complete")
        filepath = self.save_to_file("\n".join(report), "analysis_report")
        self.analysis_text.insert("end", f"\nSaved to: {filepath}")

if __name__ == "__main__":
    root = ctk.CTk()
    app = AdvancedAndroidForensicsTool(root)
    root.mainloop()