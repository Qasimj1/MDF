import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
import re
from datetime import datetime
import os

# Set appearance mode and default color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class LogAnalyzerTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Android Log Analyzer Tool")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)

        # Fonts
        self.header_font = ("Roboto", 16, "bold")
        self.body_font = ("Roboto", 12)
        self.mono_font = ("Roboto Mono", 11)

        # Parsed logs storage
        self.logs = []
        self.analysis_results = []

        # Create GUI elements
        self.create_widgets()

    def create_widgets(self):
        # Main container
        self.main_frame = ctk.CTkFrame(self.root, fg_color="#1e1e1e")
        self.main_frame.pack(fill="both", expand=True)
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Top bar
        top_bar = ctk.CTkFrame(self.main_frame, fg_color="#2a2a2a", height=50, corner_radius=0)
        top_bar.grid(row=0, column=0, sticky="ew")
        top_bar.grid_columnconfigure(1, weight=1)

        title_label = ctk.CTkLabel(top_bar, text="Android Log Analyzer", font=self.header_font, text_color="#00b7eb")
        title_label.grid(row=0, column=0, padx=20, pady=10, sticky="w")

        # Action buttons
        action_frame = ctk.CTkFrame(self.main_frame, fg_color="#252525")
        action_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        action_buttons = [
            ("Load Log File", self.load_log_file, None),
            ("Analyze Logs", self.analyze_logs, None),
            ("Export Report", self.export_report, None),
        ]
        for idx, (text, cmd, icon) in enumerate(action_buttons):
            btn = ctk.CTkButton(action_frame, text=text, command=cmd, compound="left",
                               fg_color="#3c3c3c", hover_color="#00b7eb", font=self.body_font, width=120)
            btn.grid(row=0, column=idx, padx=5)

        # Tabbed output
        self.tab_view = ctk.CTkTabview(self.main_frame, fg_color="#1e1e1e", segmented_button_selected_color="#00b7eb")
        self.tab_view.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.tab_view.add("Raw Logs")
        self.tab_view.add("Analysis")
        self.tab_view.add("Summary")

        self.raw_logs_text = ctk.CTkTextbox(self.tab_view.tab("Raw Logs"), font=self.mono_font, text_color="#ffffff",
                                           fg_color="#1e1e1e", wrap="none")
        self.raw_logs_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.analysis_text = ctk.CTkTextbox(self.tab_view.tab("Analysis"), font=self.mono_font, text_color="#ffffff",
                                           fg_color="#1e1e1e", wrap="word")
        self.analysis_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.summary_text = ctk.CTkTextbox(self.tab_view.tab("Summary"), font=self.mono_font, text_color="#ffffff",
                                          fg_color="#1e1e1e", wrap="word")
        self.summary_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Status bar
        status_bar = ctk.CTkFrame(self.main_frame, fg_color="#2a2a2a", height=30, corner_radius=0)
        status_bar.grid(row=2, column=0, sticky="ew")
        status_bar.grid_columnconfigure(1, weight=1)

        self.status_text = ctk.CTkLabel(status_bar, text="Ready", font=self.body_font, text_color="#888888")
        self.status_text.grid(row=0, column=0, padx=10, sticky="w")

        # Exit button
        exit_btn = ctk.CTkButton(self.main_frame, text="Exit", command=self.root.quit, fg_color="#d32f2f",
                                 hover_color="#3c3c3c", font=self.body_font, width=100)
        exit_btn.grid(row=3, column=0, padx=10, pady=10, sticky="e")

    def load_log_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("Log files", "*.log"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    log_content = f.read()
                self.raw_logs_text.delete("1.0", "end")
                self.raw_logs_text.insert("1.0", log_content)
                self.logs = []
                self.parse_logs(log_content)
                self.status_text.configure(text=f"Loaded logs from: {os.path.basename(file_path)}")
                self.analysis_text.delete("1.0", "end")
                self.summary_text.delete("1.0", "end")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load log file: {str(e)}")
                self.status_text.configure(text="Error loading log file")

    def parse_logs(self, log_content):
        log_pattern = r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([A-Z])\s+([^:]+):\s+(.+)'
        for line in log_content.splitlines():
            if not line.strip():
                continue
            match = re.match(log_pattern, line)
            if match:
                timestamp, pid, tid, level, tag, message = match.groups()
                self.logs.append({
                    "timestamp": timestamp,
                    "pid": int(pid),
                    "tid": int(tid),
                    "level": level,
                    "tag": tag.strip(),
                    "message": message.strip(),
                    "raw": line
                })
            else:
                self.logs.append({"raw": line, "message": line})

    def analyze_logs(self):
        if not self.logs:
            messagebox.showwarning("Warning", "No logs loaded. Please load a log file first.")
            self.status_text.configure(text="No logs to analyze")
            return

        self.status_text.configure(text="Analyzing logs...")
        self.analysis_text.delete("1.0", "end")
        self.summary_text.delete("1.0", "end")
        self.analysis_results = []

        # Analysis patterns for suspicious/malicious activity
        analysis_patterns = [
            (r"Permission denied|Failed to open.*No such file or directory", "Potential unauthorized access or missing critical file", "Investigate file access permissions or missing system components"),
            (r"error|exception", "System or application error", "Review error context for stability or exploitation risks"),
            (r"suspicious|malware|exploit|unauthorized", "Explicit malicious activity", "Perform immediate malware scan"),
            (r"com\.android\.server\..*Required app.*uid 1000", "System app permission issue", "Verify if system app behavior is expected"),
            (r"ThermalControlUtils.*mForegroundPkg", "Thermal control changes", "Check for apps causing abnormal thermal activity"),
            (r"moveToBack|onForegroundActivitiesChanged.*hasForegroundActivities:0", "App moved to background", "Ensure app transitions are user-initiated"),
            (r"sensor.*period=\d+", "High-frequency sensor usage", "Verify if sensor usage is legitimate for the app"),
            (r"authentication.*failed", "Authentication failure", "Investigate potential brute-force attempts"),
            (r"SELinux.*denied", "SELinux policy violation", "Check for unauthorized operations or policy misconfiguration"),
        ]

        error_count = 0
        warning_count = 0
        suspicious_count = 0

        for log in self.logs:
            analysis = {"log": log, "findings": [], "suspicious": False}
            message = log.get("message", log["raw"])
            log_level = log.get("level", "I")

            # Count errors and warnings
            if log_level == "E":
                error_count += 1
                analysis["findings"].append({
                    "description": "Error log detected",
                    "action": "Investigate error cause and impact"
                })
            elif log_level == "W":
                warning_count += 1
                analysis["findings"].append({
                    "description": "Warning log detected",
                    "action": "Review warning for potential issues"
                })

            # Check for suspicious patterns
            for pattern, desc, action in analysis_patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    analysis["findings"].append({
                        "description": desc,
                        "action": action
                    })
                    analysis["suspicious"] = True
                    suspicious_count += 1

            # Additional heuristic checks
            if "pid" in log:
                if log["pid"] < 1000 and "com.android" not in message:
                    analysis["findings"].append({
                        "description": f"Low PID ({log['pid']}) for non-system process",
                        "action": "Verify if process is legitimate"
                    })
                    analysis["suspicious"] = True
                    suspicious_count += 1
                if "uid 1000" in message and "com.android.server" not in message:
                    analysis["findings"].append({
                        "description": "System UID (1000) used by non-system component",
                        "action": "Check for privilege escalation"
                    })
                    analysis["suspicious"] = True
                    suspicious_count += 1

            self.analysis_results.append(analysis)

        # Generate detailed analysis output
        analysis_output = ["Log Analysis Report", "="*40, ""]
        for idx, result in enumerate(self.analysis_results, 1):
            log = result["log"]
            raw_log = log["raw"]
            analysis_output.append(f"Log {idx}: {raw_log}")
            if result["findings"]:
                analysis_output.append("Findings:")
                for finding in result["findings"]:
                    analysis_output.append(f"  - {finding['description']}")
                    analysis_output.append(f"    Action: {finding['action']}")
                if result["suspicious"]:
                    analysis_output.append("  [SUSPICIOUS] This log indicates potential malicious activity.")
            else:
                analysis_output.append("  No issues detected.")
            analysis_output.append("")

        self.analysis_text.insert("1.0", "\n".join(analysis_output))

        # Generate summary
        summary_output = ["Analysis Summary", "="*40, ""]
        summary_output.append(f"Total Logs: {len(self.logs)}")
        summary_output.append(f"Error Logs: {error_count}")
        summary_output.append(f"Warning Logs: {warning_count}")
        summary_output.append(f"Suspicious Logs: {suspicious_count}")
        summary_output.append("")
        summary_output.append("Key Observations:")
        if suspicious_count > 0:
            summary_output.append(f"- {suspicious_count} logs flagged as suspicious. Immediate investigation recommended.")
        if error_count > 0:
            summary_output.append(f"- {error_count} error logs detected. Check system stability and error causes.")
        if warning_count > 0:
            summary_output.append(f"- {warning_count} warning logs detected. Review for potential issues.")
        if suspicious_count == 0 and error_count == 0:
            summary_output.append("- No critical issues detected. Logs appear normal.")
        summary_output.append("")
        summary_output.append("Recommendations:")
        summary_output.append("- Review suspicious logs in the 'Analysis' tab for detailed actions.")
        summary_output.append("- Scan device with antivirus if malicious activity is suspected.")
        summary_output.append("- Verify app permissions and system integrity.")
        summary_output.append("- Monitor device for unusual behavior.")

        self.summary_text.insert("1.0", "\n".join(summary_output))
        self.status_text.configure(text="Analysis complete")

    def export_report(self):
        if not self.analysis_results:
            messagebox.showwarning("Warning", "No analysis results to export. Please analyze logs first.")
            self.status_text.configure(text="No results to export")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                                                initialfile=f"log_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        if file_path:
            try:
                report = []
                report.append("Android Log Analysis Report")
                report.append("="*40)
                report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                report.append("")

                # Summary
                report.append(self.summary_text.get("1.0", "end").strip())
                report.append("")

                # Detailed Analysis
                report.append("Detailed Log Analysis")
                report.append("-"*40)
                report.append(self.analysis_text.get("1.0", "end").strip())

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(report))
                messagebox.showinfo("Success", f"Report saved to: {file_path}")
                self.status_text.configure(text=f"Report saved to: {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {str(e)}")
                self.status_text.configure(text="Error saving report")

if __name__ == "__main__":
    root = ctk.CTk()
    app = LogAnalyzerTool(root)
    root.mainloop()