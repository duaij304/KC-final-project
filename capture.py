import subprocess
import shutil
import pyshark

capture_process = None

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

def capture_thread(interface):
    start_capture(interface)
    capture_process.wait()  
