import pandas as pd
import numpy as np
import sqlite3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load the data from the uploaded CSV file
file_path = 'C:\\Users\\yongj\\Desktop\\Code\\CICIDS2017.csv'
df = pd.read_csv(file_path)

# Strip any whitespace from the column names
df.columns = df.columns.str.strip()

# If 'Src IP' is not in the columns, add a placeholder column for testing
if 'Src IP' not in df.columns:
    df['Src IP'] = [f'192.168.0.{i%255}' for i in range(len(df))]  # Adding unique dummy IPs

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
        self.blocked_ips = set()

    def create_tables(self):
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS Traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    packet_count INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS Anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    packet_count INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

    def update_traffic(self, ip, packet_count):
        self.traffic_data.append((ip, packet_count))
        with self.conn:
            self.conn.execute('INSERT INTO Traffic (ip, packet_count) VALUES (?, ?)', (ip, int(packet_count)))

    def detect_anomaly(self, ip, packet_count):
        if len(self.traffic_data) == 0:
            return False

        mean_traffic = np.mean([p[1] for p in self.traffic_data])
        std_dev_traffic = np.std([p[1] for p in self.traffic_data])

        if (packet_count - mean_traffic) > self.threshold * std_dev_traffic:
            with self.conn:
                self.conn.execute('INSERT INTO Anomalies (ip, packet_count) VALUES (?, ?)', (ip, int(packet_count)))
            self.block_ip(ip)
            self.rate_limit(ip)
            logging.info(f"Anomaly detected: IP {ip}, Packet Count {packet_count}")
            return True
        else:
            return False

    def block_ip(self, ip):
        self.blocked_ips.add(ip)
        logging.info(f"IP {ip} blocked.")

    def rate_limit(self, ip):
        # Dummy implementation of rate limiting
        logging.info(f"Rate limiting applied to IP {ip}")

# Initialize the anomaly detector
detector = DoSAnomalyDetector(threshold=1)

# Apply the detection algorithm on CSV file data
csv_anomaly_results = []
for _, row in df.iterrows():
    ip = row['Src IP']
    packet_count = row['Total Packet Count']
    detector.update_traffic(ip, packet_count)
    if detector.detect_anomaly(ip, packet_count):
        csv_anomaly_results.append((ip, packet_count, "Anomaly"))
    else:
        csv_anomaly_results.append((ip, packet_count, "Normal"))

# Print to check the results
print("\nCSV Anomaly Results Sample:\n", csv_anomaly_results[:20])

# Store results in DataFrames for further analysis
csv_results_df = pd.DataFrame(csv_anomaly_results, columns=['IP', 'Packet Count', 'Anomaly'])

# Display the first few rows of the DataFrame
print("\nCSV File Results:")
print(csv_results_df.head(20))  # Show more results if needed

# Extract data from the database for further analysis
with detector.conn:
    traffic_data_df = pd.read_sql_query('SELECT * FROM Traffic', detector.conn)
    anomalies_df = pd.read_sql_query('SELECT * FROM Anomalies', detector.conn)

print("\nTraffic Data from Database:")
print(traffic_data_df.head(20))  # Show more results if needed

print("\nAnomalies Data from Database:")
print(anomalies_df.head(20))  # Show more results if needed

# Close the database connection
detector.conn.close()
