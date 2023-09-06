import time

class NetworkAlert:
    def __init__(self, alert_id, alert_type, source_ip, destination_ip, timestamp):
        self.alert_id = alert_id
        self.alert_type = alert_type
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.timestamp = timestamp

class AlertGenerator:
    def __init__(self):
        self.alert_id_counter = 0
        self.alerts = []

    def generate_alert(self, alert_type, source_ip, destination_ip):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        alert = NetworkAlert(self.alert_id_counter, alert_type, source_ip, destination_ip, timestamp)
        self.alerts.append(alert)
        self.alert_id_counter += 1

    def get_alerts(self):
        return self.alerts

def main():
    alert_generator = AlertGenerator()
    alert_generator.generate_alert("Suspicious Activity", "192.168.1.100", "10.0.0.1")
    alert_generator.generate_alert("DDoS Attack", "10.0.0.2", "192.168.1.200")

    alerts = alert_generator.get_alerts()

    print("Network Alerts:")
    for alert in alerts:
        print(f"Alert ID: {alert.alert_id}")
        print(f"Alert Type: {alert.alert_type}")
        print(f"Source IP: {alert.source_ip}")
        print(f"Destination IP: {alert.destination_ip}")
        print(f"Timestamp: {alert.timestamp}")
        print()

if __name__ == "__main__":
    main()
