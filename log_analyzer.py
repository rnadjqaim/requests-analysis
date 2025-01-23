import tkinter as tk
from tkinter import filedialog, messagebox
import csv
import re
from datetime import datetime
from collections import defaultdict
import paramiko

class LogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Access Log Analyzer")
        
        # Variables for Logstash and SSH
        self.logstash_host = tk.StringVar()
        self.logstash_port = tk.StringVar()
        self.ssh_ip = tk.StringVar()
        self.ssh_path = tk.StringVar()
        self.ssh_user = tk.StringVar()
        self.ssh_password = tk.StringVar()
        self.file_path = None
        self.analysis_results = {}

        # UI Components
        self.create_ui()
    
    def create_ui(self):
        # File Selection
        self.file_label = tk.Label(self.root, text="Select Access Log File:")
        self.file_label.grid(row=0, column=0, pady=5, sticky="w")
        
        self.file_button = tk.Button(self.root, text="Browse", command=self.select_file)
        self.file_button.grid(row=0, column=1, pady=5)

        # Logstash Input
        tk.Label(self.root, text="Logstash Host:").grid(row=1, column=0, sticky="w")
        tk.Entry(self.root, textvariable=self.logstash_host).grid(row=1, column=1, pady=5)
        
        tk.Label(self.root, text="Logstash Port:").grid(row=2, column=0, sticky="w")
        tk.Entry(self.root, textvariable=self.logstash_port).grid(row=2, column=1, pady=5)
        
        # SSH Details
        tk.Label(self.root, text="SSH IP:").grid(row=3, column=0, sticky="w")
        tk.Entry(self.root, textvariable=self.ssh_ip).grid(row=3, column=1, pady=5)
        
        tk.Label(self.root, text="SSH User:").grid(row=4, column=0, sticky="w")
        tk.Entry(self.root, textvariable=self.ssh_user).grid(row=4, column=1, pady=5)
        
        tk.Label(self.root, text="SSH Password:").grid(row=5, column=0, sticky="w")
        tk.Entry(self.root, textvariable=self.ssh_password, show="*").grid(row=5, column=1, pady=5)
        
        tk.Label(self.root, text="Log Path on SSH:").grid(row=6, column=0, sticky="w")
        tk.Entry(self.root, textvariable=self.ssh_path).grid(row=6, column=1, pady=5)
        
        # Analyze Button
        self.analyze_button = tk.Button(self.root, text="Analyze", command=self.analyze_log, state="disabled")
        self.analyze_button.grid(row=7, column=0, columnspan=2, pady=10)
        
        # Result Display
        self.result_text = tk.Text(self.root, wrap="word", height=20, width=80)
        self.result_text.grid(row=8, column=0, columnspan=2, pady=10)
        
        # Save Button
        self.save_button = tk.Button(self.root, text="Save Report", command=self.save_report, state="disabled")
        self.save_button.grid(row=9, column=0, columnspan=2, pady=5)
    
    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Log Files", "*.log"), ("All Files", "*.*")])
        if self.file_path:
            self.analyze_button.config(state="normal")
            messagebox.showinfo("File Selected", f"File Selected: {self.file_path}")
    
    def fetch_logs_from_ssh(self):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.ssh_ip.get(), username=self.ssh_user.get(), password=self.ssh_password.get())
            sftp = ssh.open_sftp()
            with sftp.open(self.ssh_path.get(), 'r') as file:
                logs = file.readlines()
            ssh.close()
            return logs
        except Exception as e:
            messagebox.showerror("SSH Error", f"Error fetching logs from SSH: {e}")
            return []
    
    def analyze_log(self):
        try:
            if self.file_path:
                with open(self.file_path, 'r') as file:
                    logs = file.readlines()
            else:
                logs = self.fetch_logs_from_ssh()
            
            bots = []
            four_xx_requests = defaultdict(list)
            five_xx_requests = defaultdict(list)
            hourly_requests = defaultdict(int)
            static_content = defaultdict(list)
            
            for log in logs:
                match = re.match(r'(.*) - - \[(.*?)\] "(.*?)" (\d{3}) .*', log)
                if match:
                    ip, date_str, request, status = match.groups()
                    status = int(status)
                    path = request.split()[1] if len(request.split()) > 1 else "-"
                    
                    log_date = datetime.strptime(date_str.split()[0], "%d/%b/%Y:%H:%M:%S")
                    hour = log_date.strftime("%Y-%m-%d %H:00")
                    
                    if "bot" in log.lower():
                        bots.append(log.strip())
                    
                    if 400 <= status < 500:
                        four_xx_requests[hour].append((path, log_date.strftime("%Y-%m-%d %H:%M:%S")))
                    elif 500 <= status < 600:
                        five_xx_requests[hour].append((path, log_date.strftime("%Y-%m-%d %H:%M:%S")))
                    
                    hourly_requests[hour] += 1
                    
                    if re.search(r'\.(css|js|png|jpg|jpeg|gif|ico|svg)$', path):
                        static_content[ip].append(path)
            
            self.analysis_results = {
                "bots": bots,
                "4xx": four_xx_requests,
                "5xx": five_xx_requests,
                "hourly": hourly_requests,
                "static": static_content
            }
            
            self.display_results()
            self.save_button.config(state="normal")
        
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
    
    def display_results(self):
        self.result_text.delete(1.0, tk.END)
        
        self.result_text.insert(tk.END, "Bots Detected:\n")
        self.result_text.insert(tk.END, "\n".join(self.analysis_results["bots"]) + "\n\n")
        
        self.result_text.insert(tk.END, "4xx Requests:\n")
        for hour, requests in self.analysis_results["4xx"].items():
            self.result_text.insert(tk.END, f"{hour}:\n")
            for path, date in requests:
                self.result_text.insert(tk.END, f"  - {date} {path}\n")
        
        self.result_text.insert(tk.END, "5xx Requests:\n")
        for hour, requests in self.analysis_results["5xx"].items():
            self.result_text.insert(tk.END, f"{hour}:\n")
            for path, date in requests:
                self.result_text.insert(tk.END, f"  - {date} {path}\n")
        
        self.result_text.insert(tk.END, "Hourly Requests:\n")
        for hour, count in self.analysis_results["hourly"].items():
            self.result_text.insert(tk.END, f"{hour}: {count} requests\n")
        
        self.result_text.insert(tk.END, "Static Content Accessed:\n")
        for ip, paths in self.analysis_results["static"].items():
            self.result_text.insert(tk.END, f"{ip}:\n")
            for path in paths:
                self.result_text.insert(tk.END, f"  - {path}\n")
    
    def save_report(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Type", "Details"])
                
                writer.writerow(["Bots"])
                for bot in self.analysis_results["bots"]:
                    writer.writerow(["", bot])
                
                writer.writerow(["4xx Requests"])
                for hour, requests in self.analysis_results["4xx"].items():
                    for path, date in requests:
                        writer.writerow(["", hour, date, path])
                
                writer.writerow(["5xx Requests"])
                for hour, requests in self.analysis_results["5xx"].items():
                    for path, date in requests:
                        writer.writerow(["", hour, date, path])
                
                writer.writerow(["Hourly Requests"])
                for hour, count in self.analysis_results["hourly"].items():
                    writer.writerow(["", hour, count])
                
                writer.writerow(["Static Content Access"])
                for ip, paths in self.analysis_results["static"].items():
                    for path in paths:
                        writer.writerow(["", ip, path])
            
            messagebox.showinfo("Saved", f"Report saved to {file_path} successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzerApp(root)
    root.mainloop()
