import subprocess
import pyshark
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import psutil
import customtkinter

capture_process = None
capture_thread = None
stop_capture_flag = False
captured_packets = []

tshark_path = r"C:\Program Files\Wireshark\tshark.exe"

def get_available_interfaces():
    interfaces = [iface for iface, addrs in psutil.net_if_addrs().items()]
    return interfaces

def start_capture(interface, capture_filter=None):
    global capture_thread
    global stop_capture_flag

    if capture_thread and capture_thread.is_alive():
        messagebox.showwarning("Warning", "Capture is already running. Please stop the existing capture first.")
        return

    stop_capture_flag = False
    capture_thread = threading.Thread(target=capture_packets, args=(interface, capture_filter))
    capture_thread.start()

def capture_packets(interface, capture_filter):
    global capture_process

    if not tshark_path:
        messagebox.showerror("Error", "Wireshark (tshark) not found in your PATH. Please install Wireshark.")
        return

    args = [tshark_path, "-i", interface, "-w", "capture.pcap"]
    if capture_filter:
        args += ["-f", capture_filter]

    try:
        capture_process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        messagebox.showinfo("Info", f"Capture started on interface {interface}! Press 'Stop Capture' to stop.")
        capture_process.communicate() 
        if not stop_capture_flag:
            messagebox.showerror("Error", "Capture process terminated unexpectedly. Please check your settings and try again.")
    except Exception as e:
        messagebox.showerror("Error", f"Error starting capture: {str(e)}")

def stop_capture():
    global capture_process
    global stop_capture_flag

    if capture_process and capture_process.poll() is None:
        capture_process.terminate()
        capture_process.wait()
        messagebox.showinfo("Info", "Capture stopped.")
        stop_capture_flag = True
    else:
        messagebox.showwarning("Warning", "Capture process is not running.")

def analyze_packets():
    global captured_packets
    captured_packets = []  
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

    result_window = tk.Toplevel()
    result_window.title("Packet Analysis Results")

    result_text_widget = tk.Text(result_window, wrap=tk.WORD)
    result_text_widget.pack(expand=True, fill='both')

    result_text_widget.insert(tk.END, result_text)

    scrollbar = tk.Scrollbar(result_text_widget, command=result_text_widget.yview)
    scrollbar.pack(side=tk.RIGHT, fill='y')

    result_text_widget.config(yscrollcommand=scrollbar.set)

    result_text_widget.config(state=tk.DISABLED)

def export_results():
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    export_filename = f"packet_analysis_{timestamp}.txt"

    with open(export_filename, "w") as file:
        sys.stdout = file
        analyze_packets()
        sys.stdout = sys.__stdout__

    messagebox.showinfo("Info", f"Results exported to {export_filename}")

def main():
    root = customtkinter.CTk()
    root.title("MyShark Wireshark Companion")

    frame = customtkinter.CTkFrame(root)
    frame.pack()

    def get_selected_interface():
        return interface_combobox.get()

    interface_label = customtkinter.CTkLabel(frame, text="Select Interface:")
    interface_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

    available_interfaces = get_available_interfaces()
    interface_combobox = customtkinter.CTkComboBox(frame, values=available_interfaces, state="readonly")
    interface_combobox.grid(row=0, column=1, padx=5, pady=5)
    interface_combobox.set(available_interfaces[0])

    capture_filter_label = customtkinter.CTkLabel(frame, text="Capture Filter (optional):")
    capture_filter_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

    capture_filter_entry = customtkinter.CTkEntry(frame)
    capture_filter_entry.grid(row=1, column=1, padx=5, pady=5)

    start_capture_button = customtkinter.CTkButton(frame, text="Start Capture", command=lambda: start_capture(get_selected_interface(), capture_filter_entry.get()))
    start_capture_button.grid(row=2, column=0, columnspan=2, padx=5, pady=10, sticky="we")

    stop_capture_button = customtkinter.CTkButton(frame, text="Stop Capture", command=stop_capture)
    stop_capture_button.grid(row=3, column=0, columnspan=2, padx=5, pady=10, sticky="we")

    analyze_packets_button = customtkinter.CTkButton(frame, text="Analyze Captured Packets", command=analyze_packets)
    analyze_packets_button.grid(row=4, column=0, columnspan=2, padx=5, pady=10, sticky="we")

    export_results_button = customtkinter.CTkButton(frame, text="Export Results to File", command=export_results)
    export_results_button.grid(row=6, column=0, columnspan=2, padx=5, pady=10, sticky="we")

    quit_button = customtkinter.CTkButton(frame, text="Quit", command=root.quit)
    quit_button.grid(row=8, column=0, columnspan=2, padx=5, pady=10, sticky="we")

    root.mainloop()

if __name__ == "__main__":
    main()
