#!/bin/bash

# Script 1: High-volume port scan (creates many connections to different ports)
port_scan_anomaly() {
  echo "Starting port scan anomaly generation for 10 minutes..."
  for i in {1..600}; do  # 10 minutes of activity (600 seconds)
    nmap -T4 -p 20-1000 127.0.0.1 > /dev/null 2>&1
    sleep 1
  done
  echo "Port scan anomaly generation completed"
}

# Script 2: Connection flood (rapid connections to a specific service)
connection_flood() {
  echo "Starting connection flood anomaly for 10 minutes..."
  local TARGET_PORT=80
  local TARGET_HOST="localhost"
  
  for i in {1..1200}; do  # 10 minutes with higher frequency
    timeout 0.5s curl -s "http://$TARGET_HOST:$TARGET_PORT" > /dev/null 2>&1
    sleep 0.5
  done
  echo "Connection flood anomaly completed"
}

# Script 3: Unusual data transfer patterns (large file transfers)
unusual_data_transfer() {
  echo "Starting unusual data transfer patterns for 10 minutes..."
  mkdir -p ~/temp_anomaly
  
  for i in {1..10}; do
    # Create a large file
    dd if=/dev/urandom of=~/temp_anomaly/large_file_$i bs=1M count=100 > /dev/null 2>&1
    
    # Start a Python HTTP server in background
    python3 -m http.server 8000 --directory ~/temp_anomaly/ > /dev/null 2>&1 &
    HTTP_SERVER_PID=$!
    
    # Download the file multiple times
    for j in {1..5}; do
      curl -s http://localhost:8000/large_file_$i -o /dev/null
    done
    
    # Stop the HTTP server
    kill $HTTP_SERVER_PID
    wait $HTTP_SERVER_PID 2>/dev/null
  done
  
  # Clean up
  rm -rf ~/temp_anomaly
  echo "Unusual data transfer anomaly completed"
}

# Script 4: DNS query anomalies
dns_query_anomalies() {
  echo "Starting DNS query anomalies for 10 minutes..."
  
  # List of unusual domains
  DOMAINS=(
    "very-long-subdomain-that-probably-doesnt-exist-anywhere.example.com"
    "random-subdomain-123456789.example.org"
    "this-is-an-unusually-long-domain-name-for-testing-purposes-only.com"
    "completely-random-subdomain-for-testing-$(date +%s).example.net"
    "another-unusual-domain-name-with-random-characters-$(openssl rand -hex 8).com"
  )
  
  for i in {1..300}; do  # 10 minutes, less frequent
    # Query a random unusual domain
    RANDOM_DOMAIN=${DOMAINS[$RANDOM % ${#DOMAINS[@]}]}
    dig $RANDOM_DOMAIN > /dev/null
    
    # Create burst of queries occasionally
    if (( $i % 20 == 0 )); then
      for j in {1..20}; do
        dig ${DOMAINS[$RANDOM % ${#DOMAINS[@]}]} > /dev/null &
      done
    fi
    
    sleep 2
  done
  echo "DNS query anomalies completed"
}

# Script 5: Packet size anomalies
packet_size_anomalies() {
  echo "Starting packet size anomalies for 10 minutes..."
  
  # Start a Python HTTP server in background to receive the traffic
  python3 -m http.server 8899 > /dev/null 2>&1 &
  SERVER_PID=$!
  
  for i in {1..120}; do  # 10 minutes
    # Send very large payloads
    dd if=/dev/urandom bs=16k count=100 2>/dev/null | curl -s -X POST -d @- http://localhost:8899 > /dev/null
    
    # Send many tiny payloads
    for j in {1..100}; do
      echo "a" | curl -s -X POST -d @- http://localhost:8899 > /dev/null &
    done
    
    sleep 5
  done
  
  # Stop the server
  kill $SERVER_PID
  wait $SERVER_PID 2>/dev/null
  echo "Packet size anomalies completed"
}

# Script 6: Abnormal protocol behavior
abnormal_protocol_behavior() {
  echo "Starting abnormal protocol behavior for 10 minutes..."
  
  for i in {1..600}; do  # 10 minutes
    # Half-open connections
    timeout 0.1s curl -s http://localhost > /dev/null 2>&1
    
    # HTTP requests with unusual headers
    curl -s -H "X-Unusual-Header: $(openssl rand -hex 32)" -H "Content-Type: application/octet-stream" http://localhost > /dev/null 2>&1
    
    # If we're at specific intervals, create more intense anomalies
    if (( $i % 60 == 0 )); then
      for j in {1..30}; do
        curl -s -X OPTIONS http://localhost > /dev/null 2>&1 &
        sleep 0.1
      done
    fi
    
    sleep 1
  done
  echo "Abnormal protocol behavior completed"
}

# Main execution function to run all anomalies sequentially for a total of 1 hour
run_all_anomalies() {
  echo "Starting 1 hour of network anomaly generation..."
  port_scan_anomaly
  connection_flood
  unusual_data_transfer
  dns_query_anomalies
  packet_size_anomalies
  abnormal_protocol_behavior
  echo "All anomaly generation completed. You should now have 1 hour of anomaly data."
}

# Run a specific anomaly type or all of them
case "$1" in
  "portscan") port_scan_anomaly ;;
  "flood") connection_flood ;;
  "transfer") unusual_data_transfer ;;
  "dns") dns_query_anomalies ;;
  "packetsize") packet_size_anomalies ;;
  "protocol") abnormal_protocol_behavior ;;
  *) run_all_anomalies ;;
esac