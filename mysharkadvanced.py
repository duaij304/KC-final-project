import tkinter as tk
from tkinter import ttk
import pyshark
import threading
import queue

capture_thread = None
stop_capture_event = threading.Event()
packet_queue = queue.Queue()

def start_capture(interface):
    global capture_thread, stop_capture_event
    stop_capture_event.clear()
    capture_thread = threading.Thread(target=capture_packets, args=(interface,))
    capture_thread.start()

def stop_capture():
    global stop_capture_event
    stop_capture_event.set()

def capture_packets(interface):
    # Set up asyncio event loop in this thread
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    capture = pyshark.LiveCapture(interface=interface)
    for packet in capture.sniff_continuously():
        if stop_capture_event.is_set():
            break
        packet_queue.put(packet)

def update_gui():
    while not stop_capture_event.is_set():
        try:
            packet = packet_queue.get(timeout=0.1)
            real_time_packet_analysis(packet)
        except queue.Empty:
            pass

def real_time_packet_analysis(packet):
    try:
        if hasattr(packet, "ip"):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            transport_layer = packet.transport_layer if hasattr(packet, "transport_layer") else None
            src_port = packet[transport_layer].srcport if transport_layer else None
            dst_port = packet[transport_layer].dstport if transport_layer else None
            protocol = transport_layer if transport_layer else "Unknown"

            output_text.insert(tk.END, f"Source IP: {src_ip}, Source Port: {src_port}\n")
            output_text.insert(tk.END, f"Destination IP: {dst_ip}, Destination Port: {dst_port}\n")
            output_text.insert(tk.END, f"Protocol: {protocol}\n")
            output_text.update()  # Update the GUI

    except Exception as e:
        output_text.insert(tk.END, f"An error occurred while analyzing the packet: {e}\n")

root = tk.Tk()
root.title("Real-Time Packet Analysis")

root = tk.Tk()
root.title("Real-Time Packet Analysis")

label = tk.Label(root, text="Enter the capture interface (e.g., eth0):")
label.pack()

interface_entry = tk.Entry(root)
interface_entry.pack()

def start_capture_button():
    interface = interface_entry.get()
    start_capture(interface)
start_button = ttk.Button(root, text="Start Capture", command=start_capture_button)
start_button.pack()

stop_button = ttk.Button(root, text="Stop Capture", command=stop_capture)
stop_button.pack()

output_text = tk.Text(root, height=20, width=50)
output_text.pack()

update_thread = threading.Thread(target=update_gui)
update_thread.daemon = True
update_thread.start()

root.mainloop()

root.mainloop()
