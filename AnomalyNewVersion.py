import pandas as pd
import numpy as np
import sqlite3

# Load the data from the uploaded CSV file
file_path = 'C:\\Users\\yongj\\Desktop\\Code\\CICIDS2017.csv'
df = pd.read_csv(file_path)

# Strip any whitespace from the column names
df.columns = df.columns.str.strip()

# Print the first few rows to check if the data is loaded correctly
print("CSV Data Checking:\n", df.head())

# Calculate the total packet count using the corrected column names
try:
    df['Total Packet Count'] = df['Total Fwd Packets'] + df['Total Backward Packets']
    # Print to check if the calculation is correct
    print("\nCalculated Total Packet Count:\n", df[['Total Fwd Packets', 'Total Backward Packets', 'Total Packet Count']].head())
except KeyError as e:
    print(f"\nColumn not found: {e}")

class DoSAnomalyDetector:
    def __init__(self, threshold, db_name='traffic_data.db'):
        self.threshold = threshold
        self.traffic_data = []
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.create_tables()

    def create_tables(self):
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS Traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    packet_count INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS Anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    packet_count INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

    def update_traffic(self, packet_count):
        self.traffic_data.append(packet_count)
        with self.conn:
            self.conn.execute('INSERT INTO Traffic (packet_count) VALUES (?)', (int(packet_count),))

    def detect_anomaly(self):
        if len(self.traffic_data) == 0:
            return False

        mean_traffic = np.mean(self.traffic_data)
        std_dev_traffic = np.std(self.traffic_data)

        latest_traffic = self.traffic_data[-1]

        if (latest_traffic - mean_traffic) > self.threshold * std_dev_traffic:
            with self.conn:
                self.conn.execute('INSERT INTO Anomalies (packet_count) VALUES (?)', (int(latest_traffic),))
            return True
        else:
            return False

# Initialize the anomaly detector
detector = DoSAnomalyDetector(threshold=1)

# Generate normal traffic data (packets per second, assumed to follow a normal distribution)
normal_traffic = np.random.normal(loc=10, scale=5, size=100).astype(int)

# Generate DoS attack traffic (packets per second, assumed to be peak values)
dos_attack_traffic = np.random.normal(loc=150, scale=30, size=10).astype(int)

# Combine normal traffic and attack traffic
traffic_samples = np.concatenate((normal_traffic, dos_attack_traffic))

# Print to check the generated data
print("\nNormal Traffic:\n", normal_traffic[:10])
print("\nDoS Attack Traffic:\n", dos_attack_traffic[:10])

# Apply the detection algorithm on CSV file data
csv_anomaly_results = []
for packet_count in df['Total Packet Count']:
    detector.update_traffic(packet_count)
    if detector.detect_anomaly():
        csv_anomaly_results.append((packet_count, "Anomaly"))
    else:
        csv_anomaly_results.append((packet_count, "Normal"))

# Print to check the results
print("\nCSV Anomaly Results Sample:\n", csv_anomaly_results[:20])

# Reset the detector for simulated data
detector.traffic_data = []

# Apply the detection algorithm on simulated traffic data
sim_anomaly_results = []
for packet_count in traffic_samples:
    detector.update_traffic(packet_count)
    if detector.detect_anomaly():
        sim_anomaly_results.append((packet_count, "Anomaly"))
    else:
        sim_anomaly_results.append((packet_count, "Normal"))

# Simulate anomaly results (example data for demonstration)
sim_anomaly_results = [(int(x), 'Normal' if x < 15 else 'Anomaly') for x in np.concatenate((normal_traffic, dos_attack_traffic))]

# Print to check the results
print("\nSimulated Anomaly Results Sample:\n", sim_anomaly_results[:20])

# Store results in DataFrames for further analysis
csv_results_df = pd.DataFrame(csv_anomaly_results, columns=['Packet Count', 'Anomaly'])
sim_results_df = pd.DataFrame(sim_anomaly_results, columns=['Packet Count', 'Anomaly'])

# Display the first few rows of the DataFrames
print("\nCSV File Results:")
print(csv_results_df.head(20))  # Show more results if needed

print("\nSimulated Traffic Results:")
print(sim_results_df.head(20))  # Show more results if needed

# Extract data from the database for further analysis
with detector.conn:
    traffic_data_df = pd.read_sql_query('SELECT * FROM Traffic', detector.conn)
    anomalies_df = pd.read_sql_query('SELECT * FROM Anomalies', detector.conn)

print("\nTraffic Data from Database:")
print(traffic_data_df.head(20))  # Show more results if needed

print("\nAnomalies Data from Database:")
print(anomalies_df.head(20))  # Show more results if needed

# Compare CSV anomalies with simulated anomalies to find true anomalies
true_anomalies = []
for csv_result, sim_result in zip(csv_anomaly_results, sim_anomaly_results):
    if csv_result[1] == "Anomaly" and sim_result[1] == "Anomaly":
        true_anomalies.append(csv_result[0])

print("\nTrue Anomalies:\n", true_anomalies)

# Generate normal and DoS attack traffic data (for example purposes)
normal_traffic = np.random.normal(loc=10, scale=5, size=1000).astype(int)
dos_attack_traffic = np.random.normal(loc=150, scale=30, size=50).astype(int)

# Close the database connection
detector.conn.close()