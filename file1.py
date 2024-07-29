import numpy as np
import pandas as pd

# Define the DoSAnomalyDetector class
class DoSAnomalyDetector:
    def __init__(self, threshold):
        self.threshold = threshold
        self.traffic_data = []
        
    def update_traffic(self, packet_count):
        self.traffic_data.append(packet_count)
        
    def detect_anomaly(self):
        if len(self.traffic_data) == 0:
            return False
        
        mean_traffic = np.mean(self.traffic_data)
        std_dev_traffic = np.std(self.traffic_data)
        
        latest_traffic = self.traffic_data[-1]
        
        if (latest_traffic - mean_traffic) > self.threshold * std_dev_traffic:
            return True
        else:
            return False

# Initialize the anomaly detector
detector = DoSAnomalyDetector(threshold=3)

# Simulate normal traffic data (number of packets per second)
normal_traffic = [100, 102, 98, 97, 100, 101, 99, 102, 98, 97]

# Introduce a DoS attack (sudden spike in traffic)
dos_attack_traffic = [1000, 1200, 1500]

# Combine normal traffic and attack traffic
traffic_samples = normal_traffic + dos_attack_traffic

# Detect anomalies in the combined traffic data
anomaly_results = []
for packet_count in traffic_samples:
    detector.update_traffic(packet_count)
    if detector.detect_anomaly():
        anomaly_results.append(f"Anomaly detected with traffic: {packet_count}")
    else:
        anomaly_results.append(f"Traffic normal: {packet_count}")

# Display the results
for result in anomaly_results:
    print(result)
