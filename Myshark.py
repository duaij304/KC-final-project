import pyshark
import subprocess
import shutil
import pyfiglet
import threading
def start_capture(interface):
    global capture_process
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    capture_process = subprocess.Popen([tshark_path, "-i", interface, "-w", "capture.pcap"])
    print(f"Capture started on interface {interface}! Use option 2 to stop and analyze.")

def stop_capture():
    global capture_process
    if capture_process:
        capture_process.terminate()
        print("Capture stopped.")
        capture_process = None
    else:
        print("Capture is not currently running.")

def analyze_packets():
    if not capture_process:
        print("Capture is not running. Please start it first.")
        return

    print("Analyzing captured packets:")
    capture = pyshark.FileCapture("capture.pcap")
    devices = {}
    ports = {}

    for packet in capture:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst

        src_port = packet[packet.transport_layer].srcport
        dst_port = packet[packet.transport_layer].dstport

        devices[src_ip] = devices.get(src_ip, 0) + 1
        devices[dst_ip] = devices.get(dst_ip, 0) + 1

        ports[src_port] = ports.get(src_port, 0) + 1
        ports[dst_port] = ports.get(dst_port, 0) + 1

    print("Device Information:")
    for device, count in devices.items():
        print(f"Device: {device}, Packets: {count}")

    print("Port Information:")
    for port, count in ports.items():
        print(f"Port: {port}, Packets: {count}")

def save_capture():
    if not capture_process:
        print("Capture is not running. Please start it first.")
        return

    shutil.copy("capture.pcap", "saved_capture.pcap")
    print("Capture saved to 'saved_capture.pcap'.")

def load_capture():
    global capture_process
    if capture_process:
        print("Please stop the capture before loading a saved capture.")
        return

    shutil.copy("saved_capture.pcap", "capture.pcap")
    print("Capture loaded from 'saved_capture.pcap'.")
shark_wifi_ascii = r"""
(..       \_    ,  |\  /|
 \       O  \  /|  \ \/ /
  \______    \/ |   \  / 
     vvvv\    \ |   /  |
     \^^^^  ==   \_/   |
      `\_   ===    \.  |
      / /\_   \ /      |
      |/   \_  \|      /
 snd         \________/
"""

codesnail_ascii = pyfiglet.figlet_format("MyShark")

print(codesnail_ascii)
print("Welcome to the MyShark Wireshark Companion!")

capture_process = None

# Define a function for packet capture in the background
def capture_thread(interface):
    start_capture(interface)
    capture_process.wait()  # Wait for the capture process to complete

# Start packet capture in a separate thread
capture_thread_instance = None

try:
    while True:
        print("\nMenu:")
        print("1. Start Capture")
        print("2. Stop Capture")
        print("3. Analyze Packets")
        print("4. Save Capture")
        print("5. Load Capture")
        print("6. Quit")

        choice = input("Enter your choice: ")

        if choice == "1":
            if capture_process:
                print("Capture is already running. Use option 2 to stop.")
            else:
                interface = input("Enter the capture interface (e.g., eth0): ")
                # Start packet capture in a separate thread
                capture_thread_instance = threading.Thread(target=capture_thread, args=(interface,))
                capture_thread_instance.start()
        elif choice == "2":
            stop_capture()
        elif choice == "3":
            analyze_packets()
        elif choice == "4":
            save_capture()
        elif choice == "5":
            load_capture()
        elif choice == "6":
            if capture_process:
                print("Please stop the capture before quitting.")
            else:
                break
        else:
            print("Invalid choice. Please enter a valid option.")

except KeyboardInterrupt:
    if capture_thread_instance and capture_thread_instance.is_alive():
        # Stop the packet capture thread if it's still running
        capture_thread_instance.join()
    print("\nKeyboard interrupt detected. Exiting...")

