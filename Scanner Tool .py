
import socket
import threading
import csv
import os
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QTextEdit, 
    QVBoxLayout, QFileDialog, QCheckBox
)

# Function to check if an IP is alive using ping
def is_ip_alive(ip):
    try:
        if os.name == "nt":
            response = subprocess.run(["ping", "-n", "1", ip], capture_output=True, text=True)
        else:
            response = subprocess.run(["ping", "-c", "1", ip], capture_output=True, text=True)
        return "TTL=" in response.stdout or "ttl=" in response.stdout
    except:
        return False

# Function to scan a single port
def scan_port(ip, port, output_box, results, show_closed):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        start_time = time.time()
        result = s.connect_ex((ip, port))
        end_time = time.time()
        response_time = round((end_time - start_time) * 1000, 2)  # Convert to ms

        service = "Unknown"
        try:
            service = socket.getservbyport(port)
        except:
            pass

        if result == 0:
            result_text = f"[+] {ip}:{port} ({service}) is OPEN (Response: {response_time} ms)\n"
            results.append((ip, port, "Open", service, response_time))
        elif show_closed:
            result_text = f"[-] {ip}:{port} ({service}) is CLOSED\n"
            results.append((ip, port, "Closed", service, "-"))
        else:
            return

        output_box.append(result_text)
        s.close()
    except:
        pass

# Function to scan multiple ports efficiently
def scan_target(ip, ports, output_box, results, show_closed):
    output_box.append(f"[*] Scanning {ip}...\n")
    if not is_ip_alive(ip):
        output_box.append(f"[!] {ip} is not reachable (Ping Failed)\n")
        return

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port, output_box, results, show_closed) for port in ports]
        for future in futures:
            future.result()
    
    output_box.append(f"[\u2713] Scan Completed for {ip}!\n")

# GUI Class
class PortScannerGUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Advanced PyQt Port Scanner")
        self.setGeometry(200, 200, 600, 500)

        layout = QVBoxLayout()
        self.setStyleSheet("background-color: #2e2e2e; color: #ffffff;")

        self.ip_label = QLabel("Enter Target IP(s) (comma separated):")
        self.ip_label.setStyleSheet("color: #ffcc00;")
        self.ip_input = QLineEdit("192.168.1.1, 192.168.1.2")

        self.port_label = QLabel("Enter Ports (comma separated or range like 20-1000):")
        self.port_label.setStyleSheet("color: #ffcc00;")
        self.port_input = QLineEdit("21,22,23,25,53,80,443,445,3306,3389,8080,84,64,6,986,46,6349,6137,3,43,4634,36,49,64,943,94")

        self.show_closed_checkbox = QCheckBox("Show Closed Ports")
        self.show_closed_checkbox.setChecked(False)

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        self.scan_button.setStyleSheet("background-color: #ffcc00; color: black; font-weight: bold;")

        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)

        self.save_button = QPushButton("Save Results (CSV)")
        self.save_button.clicked.connect(self.save_results)
        self.save_button.setStyleSheet("background-color: #ff3300; color: white; font-weight: bold;")

        layout.addWidget(self.ip_label)
        layout.addWidget(self.ip_input)
        layout.addWidget(self.port_label)
        layout.addWidget(self.port_input)
        layout.addWidget(self.show_closed_checkbox)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.output_box)
        layout.addWidget(self.save_button)

        self.setLayout(layout)
        self.results = []

    def start_scan(self):
        self.output_box.clear()
        self.results = []
        ips = self.ip_input.text().split(",")
        show_closed = self.show_closed_checkbox.isChecked()
        ports = self.parse_ports(self.port_input.text())

        for ip in ips:
            scan_target(ip.strip(), ports, self.output_box, self.results, show_closed)

    def parse_ports(self, port_text):
        ports = []
        for part in port_text.split(","):
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports

    def save_results(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save File", "", "CSV Files (*.csv)")
        if file_path:
            with open(file_path, mode="w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["IP Address", "Port", "Status", "Service", "Response Time (ms)"])
                writer.writerows(self.results)
            self.output_box.append(f"[\u2713] Results saved to {file_path}\n")

if __name__ == "__main__":
    app = QApplication([])
    window = PortScannerGUI()
    window.show()
    app.exec()

