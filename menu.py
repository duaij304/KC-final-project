import threading
from capture import start_capture, stop_capture
from analysis import analyze_packets
from capture import capture_thread
from alerts import setup_alerts, trigger_alert
from reports import generate_report
from extensibility import load_extensions
from automation import configure_automation

capture_thread_instance = None

def main_menu():
    global capture_thread_instance
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
            if capture_thread_instance and capture_thread_instance.is_alive():
                print("Capture is already running. Use option 2 to stop.")
            else:
                interface = input("Enter the capture interface (e.g., eth0): ")
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
            if capture_thread_instance and capture_thread_instance.is_alive():
                capture_thread_instance.join()
            break
        else:
            print("Invalid choice. Please enter a valid option.")
