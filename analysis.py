import pyshark

def analyze_packets(capture_filename):
    capture = pyshark.FileCapture("capture.pcap")
    
    devices = {}
    ports = {}

    for packet in capture:
        if 'ip' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            if packet.transport_layer:
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

if __name__ == "__main__":
    capture_filename = "capture.pcap"
    analyze_packets(capture_filename)
