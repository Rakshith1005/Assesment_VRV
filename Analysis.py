import re
import csv
from collections import defaultdict, Counter
import pandas as pd

# Function to parse the log file
def parse_log_file(filename):
    with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
        log_data = file.readlines()
    return log_data

# Function to count requests per IP
def count_requests_per_ip(log_data):
    ip_count = defaultdict(int)
    for line in log_data:
        ip = line.split()[0]  # Extract the IP address
        ip_count[ip] += 1
    return sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

# Function to find the most accessed endpoint
def find_most_accessed_endpoint(log_data):
    endpoint_count = Counter()
    for line in log_data:
        match = re.search(r'"[A-Z]+\s(\/\S*)\sHTTP', line)
        if match:
            endpoint = match.group(1)
            endpoint_count[endpoint] += 1
    most_accessed = endpoint_count.most_common(1)
    return most_accessed[0] if most_accessed else (None, 0)

# Function to detect suspicious activity
def detect_suspicious_activity(log_data, threshold=10):
    failed_attempts = defaultdict(int)
    for line in log_data:
        if '401' in line or 'Invalid credentials' in line:
            ip = line.split()[0]
            failed_attempts[ip] += 1
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}
    return suspicious_ips

# Function to save results to CSV
def save_results_to_csv(ip_requests, most_accessed, suspicious_activity):
    # Requests per IP
    ip_df = pd.DataFrame(ip_requests, columns=["IP Address", "Request Count"])
    ip_df.to_csv("requests_per_ip.csv", index=False)

    # Most Accessed Endpoint
    endpoint_df = pd.DataFrame(
        [most_accessed], columns=["Endpoint", "Access Count"]
    )
    endpoint_df.to_csv("most_accessed_endpoint.csv", index=False)

    # Suspicious Activity
    suspicious_df = pd.DataFrame(
        list(suspicious_activity.items()), columns=["IP Address", "Failed Login Count"]
    )
    suspicious_df.to_csv("suspicious_activity.csv", index=False)

    print("\nResults saved as:")
    print("- requests_per_ip.csv")
    print("- most_accessed_endpoint.csv")
    print("- suspicious_activity.csv")

# Main function to execute the analysis
def main():
    log_file = "Log_File.log"  # Use the converted UTF-8 file
    log_data = parse_log_file(log_file)

    # Step 1: Count Requests per IP
    ip_requests = count_requests_per_ip(log_data)
    print("IP Address           Request Count")
    for ip, count in ip_requests:
        print(f"{ip:20} {count}")

    # Step 2: Find the Most Accessed Endpoint
    most_accessed = find_most_accessed_endpoint(log_data)
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    # Step 3: Detect Suspicious Activity
    suspicious_activity = detect_suspicious_activity(log_data)
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip:20} {count}")

    # Step 4: Save Results to CSV
    save_results_to_csv(ip_requests, most_accessed, suspicious_activity)

if __name__ == "__main__":
    main()