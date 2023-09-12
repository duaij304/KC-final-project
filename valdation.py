import subprocess
import pyshark
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import psutil
import customtkinter
import sys
from tkinter import scrolledtext
import matplotlib.pyplot as plt
import io
import base64
import subprocess 
from customtkinter import CTkProgressBar

class PacketAnalyzer:
    def __init__(self):
        self.capture_process = None
        self.capture_thread = None
        self.stop_capture_flag = False
        self.captured_packets = []
        self.tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
        self.result_text_widget = None
        self.dns_queries_by_domain = {} 
        self.network_topology = {}  


    def get_available_interfaces(self):
        interfaces = [iface for iface, addrs in psutil.net_if_addrs().items()]
        return interfaces



    def start_capture(self, interface, capture_filter=None):
        if self.capture_thread and self.capture_thread.is_alive():
            messagebox.showwarning("Warning", "Capture is already running. Please stop the existing capture first.")
            return

        self.stop_capture_flag = False
        self.capture_thread = threading.Thread(target=self.capture_packets, args=(interface, capture_filter))
        self.capture_thread.start()



    def capture_packets(self, interface, capture_filter):
        if not self.tshark_path:
            messagebox.showerror("Error", "Wireshark (tshark) not found in your PATH. Please install Wireshark.")
            return

        args = [self.tshark_path, "-i", interface, "-w", "capture.pcap"]
        if capture_filter:
            args += ["-f", capture_filter]

        try:
            self.capture_process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            messagebox.showinfo("Info", f"Capture started on interface {interface}! Press 'Stop Capture' to stop.")
            self.capture_process.communicate() 
            if not self.stop_capture_flag:
                messagebox.showerror("Error", "Capture process terminated unexpectedly. Please check your settings and try again.")
        except Exception as e:
            messagebox.showerror("Error", f"Error starting capture: {str(e)}")

    def stop_capture(self):
        if self.capture_process and self.capture_process.poll() is None:
            self.capture_process.terminate()
            self.capture_process.wait()
            messagebox.showinfo("Info", "Capture stopped.")
            self.stop_capture_flag = True
        else:
            messagebox.showwarning("Warning", "Capture process is not running.")






    def analyze_packets(self, analysis_type):
        self.captured_packets = []
        packet_count = 0
        source_devices = {}
        destination_devices = {}
        source_ports = {}

        try:
            capture = pyshark.FileCapture("capture.pcap")

            for packet in capture:
                packet_count += 1

                src_ip = packet.ip.src if hasattr(packet, "ip") else "Unknown"
                dst_ip = packet.ip.dst if hasattr(packet, "ip") else "Unknown"

                src_port = None
                dst_port = None

                if hasattr(packet, "transport_layer"):
                    src_port = packet[packet.transport_layer].srcport
                    dst_port = packet[packet.transport_layer].dstport

                if src_ip != "Unknown":
                    source_devices[src_ip] = source_devices.get(src_ip, 0) + 1

                if dst_ip != "Unknown":
                    destination_devices[dst_ip] = destination_devices.get(dst_ip, 0) + 1

                if src_port:
                    source_ports[src_port] = source_ports.get(src_port, 0) + 1

                if dst_port:
                    source_ports[dst_port] = source_ports.get(dst_port, 0) + 1

        except Exception as e:
            messagebox.showerror("Error", f"Error analyzing packets: {str(e)}")

        result_text = f"Total packets captured: {packet_count}\n\n"
        result_text += "Source Devices Information:\n"
        for device, count in source_devices.items():
            result_text += f"Source Device: {device}, Packets: {count}\n"

        result_text += "\nDestination Devices Information:\n"
        for device, count in destination_devices.items():
            result_text += f"Destination Device: {device}, Packets: {count}\n"

        result_text += "\nSource Ports Information:\n"
        for port, count in source_ports.items():
            result_text += f"Source Port: {port}, Packets: {count}\n"

        if analysis_type == "HTTP":
            self.analyze_http_packets(source_devices, destination_devices, source_ports, result_text)
        elif analysis_type == "DNS":
            self.analyze_dns_packets(source_devices, destination_devices, source_ports, result_text)

    def create_and_save_pie_chart(self, data, title):
        plt.figure(figsize=(6, 6))
        labels = data.keys()
        sizes = data.values()
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title(title)
        chart_image_buffer = io.BytesIO()
        plt.savefig(chart_image_buffer, format='png')
        chart_image_buffer.seek(0)
        plt.show()

    def analyze_http_packets(self, source_devices, destination_devices, source_ports, result_text):
        http_requests = 0
        http_responses = 0
        unique_hosts = set()

        for device, count in source_devices.items():
            if "HTTP" in device:
                unique_hosts.add(device)

        for device, count in destination_devices.items():
            if "HTTP" in device:
                unique_hosts.add(device)

        for port, count in source_ports.items():
            if port == "80" or port == "443":
                http_requests += count

        for port, count in source_ports.items():
            if port == "80" or port == "443":
                http_responses += count

        source_devices_chart = self.create_and_save_pie_chart(source_devices, "Source Devices")
        source_ports_chart = self.create_and_save_pie_chart(source_ports, "Source Ports")

        source_devices_image = base64.b64encode(source_devices_chart.read()).decode()
        source_ports_image = base64.b64encode(source_ports_chart.read()).decode()

        result_text += f"\n\nHTTP Packet Analysis:\n"
        result_text += f"Total HTTP Requests: {http_requests}\n"
        result_text += f"Total HTTP Responses: {http_responses}\n"
        result_text += f"Unique Hosts: {', '.join(unique_hosts)}\n"

        result_text += "\nSource Devices Pie Chart:\n"
        result_text += f'<img src="data:image/png;base64,{source_devices_image}" />\n'

        result_text += "\nSource Ports Pie Chart:\n"
        result_text += f'<img src="data:image/png;base64,{source_ports_image}" />\n'

        self.display_analysis_result(result_text)
        








    def analyze_dns_packets(self, source_devices, destination_devices, source_ports, result_text):
        dns_requests = 0
        dns_responses = 0
        domains = set() 

        for device, count in source_devices.items():
            if "DNS" in device:
                dns_requests += count

        for device, count in destination_devices.items():
            if "DNS" in device:
                dns_responses += count

        capture = pyshark.FileCapture("capture.pcap")

        for packet in capture:
            if "dns" in packet:
                dns_packet = packet.dns
                if hasattr(dns_packet, "qry_name"):
                    domain = dns_packet.qry_name
                    if domain:
                        domains.add(domain.lower())

        result_text += f"\n\nDNS Packet Analysis:\n"
        result_text += f"Total DNS Requests: {dns_requests}\n"
        result_text += f"Total DNS Responses: {dns_responses}\n"

        result_text += "\nUnique Domains and Subdomains Accessed:\n"
        for domain in sorted(domains):
            result_text += f"Domain/Subdomain: {domain}\n"

        self.display_analysis_result(result_text)
        





    def display_analysis_result(self, result_text):
        result_window = tk.Toplevel()
        result_window.title("Packet Analysis Results")

        self.result_text_widget = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
        self.result_text_widget.pack(expand=True, fill='both')

        self.result_text_widget.config(state=tk.NORMAL) 

        self.result_text_widget.insert(tk.END, result_text, 'html_content')

        self.result_text_widget.tag_configure('html_content', justify='left', spacing1=5, spacing2=5)

        self.result_text_widget.config(state=tk.DISABLED)

        scrollbar = tk.Scrollbar(self.result_text_widget, command=self.result_text_widget.yview)
        scrollbar.pack(side=tk.RIGHT, fill='y')

        self.result_text_widget.config(yscrollcommand=scrollbar.set)


def main():
    analyzer = PacketAnalyzer()  
    root = customtkinter.CTk()
    root.title("MyShark Wireshark Companion")
    root.geometry("1000x900")

    frame = customtkinter.CTkFrame(root)
    frame.pack()

    def get_selected_interface():
        return interface_combobox.get()

              
    interface_label = customtkinter.CTkLabel(frame, text="Select Interface:")
    interface_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")



    
    available_interfaces = analyzer.get_available_interfaces() 
    interface_combobox = customtkinter.CTkComboBox(frame, values=available_interfaces, state="readonly")
    interface_combobox.grid(row=0, column=1, padx=5, pady=5)
    interface_combobox.set(available_interfaces[0])
    
    capture_filter_label = customtkinter.CTkLabel(frame, text="Capture Filter (optional):")
    capture_filter_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

    capture_filter_entry = customtkinter.CTkEntry(frame)
    capture_filter_entry.grid(row=1, column=1, padx=5, pady=5)

    start_capture_button = customtkinter.CTkButton(frame, text="Start Capture", command=lambda: analyzer.start_capture(get_selected_interface(), capture_filter_entry.get()))
    start_capture_button.grid(row=2, column=0, columnspan=2, padx=5, pady=10, sticky="we")

    stop_capture_button = customtkinter.CTkButton(frame, text="Stop Capture", command=analyzer.stop_capture)
    stop_capture_button.grid(row=3, column=0, columnspan=2, padx=5, pady=10, sticky="we")
      
    analyze_dns_button = customtkinter.CTkButton(frame, text="Analyze DNS", command=lambda: analyzer.analyze_packets("DNS"))
    analyze_dns_button.grid(row=5, column=0, columnspan=2, padx=5, pady=10, sticky="we")


    analyze_packets_button = customtkinter.CTkButton(
    frame,
    text="Analyze Captured Packets",
    command=lambda: analyzer.analyze_packets("HTTP")  
    )
    analyze_packets_button.grid(row=4, column=0, columnspan=2, padx=5, pady=10, sticky="we")



    quit_button = customtkinter.CTkButton(frame, text="Quit", command=root.quit)
    quit_button.grid(row=8, column=0, columnspan=2, padx=5, pady=10, sticky="we")

  

    root.mainloop()

if __name__ == "__main__":
    main()
