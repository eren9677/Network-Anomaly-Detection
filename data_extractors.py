import subprocess
import csv
import os
import sys
import json
from collections import defaultdict

def extract_features_from_pcap(pcap_file, window_size=60):
    """
    Extract time-windowed network features from a PCAP file using tshark.
    Outputs data in 60-second windows by default.
    
    Args:
        pcap_file: Path to PCAP file
        window_size: Size of time window in seconds (default: 60)
    
    Returns:
        List of dictionaries containing features for each time window
    """
    print(f"Processing {pcap_file}...")
    
    # Run tshark to extract basic packet info in JSON format
    cmd = [
        "tshark", 
        "-r", pcap_file,
        "-T", "json",
        "-e", "frame.time_epoch", 
        "-e", "frame.len",
        "-e", "ip.src", 
        "-e", "ip.dst",
        "-e", "tcp.srcport", 
        "-e", "tcp.dstport",
        "-e", "udp.srcport", 
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing tshark: {e}")
        return []
    
    # Initialize data structures for each time window
    windows = defaultdict(lambda: {
        'packet_count': 0,
        'total_bytes': 0,
        'protocols': set(),
        'src_ips': set(),
        'dst_ips': set(),
        'src_ports': set(),
        'dst_ports': set()
    })
    
    # Parse JSON output
    try:
        packets = json.loads(result.stdout)
        
        # Process each packet
        for packet in packets:
            if '_source' in packet and 'layers' in packet['_source']:
                layers = packet['_source']['layers']
                
                # Get timestamp and determine window
                if 'frame.time_epoch' in layers:
                    timestamp = float(layers['frame.time_epoch'][0])
                    window_id = int(timestamp // window_size)
                    
                    # Update packet count
                    windows[window_id]['packet_count'] += 1
                    
                    # Update total bytes
                    if 'frame.len' in layers:
                        windows[window_id]['total_bytes'] += int(layers['frame.len'][0])
                    
                    # Update protocol information
                    if '_ws.col.Protocol' in layers:
                        windows[window_id]['protocols'].add(layers['_ws.col.Protocol'][0])
                    
                    # Update IP information
                    if 'ip.src' in layers:
                        windows[window_id]['src_ips'].add(layers['ip.src'][0])
                    if 'ip.dst' in layers:
                        windows[window_id]['dst_ips'].add(layers['ip.dst'][0])
                    
                    # Update port information
                    if 'tcp.srcport' in layers:
                        windows[window_id]['src_ports'].add(layers['tcp.srcport'][0])
                    if 'tcp.dstport' in layers:
                        windows[window_id]['dst_ports'].add(layers['tcp.dstport'][0])
                    if 'udp.srcport' in layers:
                        windows[window_id]['src_ports'].add(layers['udp.srcport'][0])
                    if 'udp.dstport' in layers:
                        windows[window_id]['dst_ports'].add(layers['udp.dstport'][0])
    
    except json.JSONDecodeError:
        print(f"Error: Could not parse tshark output as JSON")
        return []
    
    # Convert windows to feature rows
    feature_rows = []
    for window_id, data in windows.items():
        feature_row = {
            'window_start': window_id * window_size,
            'packet_count': data['packet_count'],
            'bytes_per_second': data['total_bytes'] / window_size,
            'unique_protocols': len(data['protocols']),
            'unique_src_ips': len(data['src_ips']),
            'unique_dst_ips': len(data['dst_ips']),
            'unique_src_ports': len(data['src_ports']),
            'unique_dst_ports': len(data['dst_ports']),
            'avg_packet_size': data['total_bytes'] / data['packet_count'] if data['packet_count'] > 0 else 0,
            'is_baseline': 'baseline' in pcap_file.lower() #assume the this baseline pcap file has normal traffic.
        }
        feature_rows.append(feature_row)
    
    return feature_rows

def basic_process(directory, output_csv):
    """
    Process all PCAP files in a directory and save features to CSV
    
    Args:
        directory: Directory containing PCAP files
        output_csv: Path to output CSV file
    """
    all_features = []
    
    # Process each PCAP file in the directory
    for filename in os.listdir(directory):
        if filename.endswith('.pcap'):
            file_path = os.path.join(directory, filename)
            features = extract_features_from_pcap(file_path)
            all_features.extend(features)
    
    # Write features to CSV
    if all_features:
        fieldnames = all_features[0].keys()
        with open(output_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_features)
        
        print(f"Successfully extracted features from {len(all_features)} time windows")
        print(f"Data saved to {output_csv}")

        return output_csv
    else:
        print("No features extracted")

def advanced_extraction(pcap_file, window_size=60):
    """
    Extract time-windowed network features from a PCAP file using tshark.
    Outputs data in 60-second windows by default with enhanced features.
    
    Args:
        pcap_file: Path to PCAP file
        window_size: Size of time window in seconds (default: 60)
    
    Returns:
        List of dictionaries containing features for each time window
    """
    print(f"Processing {pcap_file}...")
    
    # Run tshark to extract more detailed packet info in JSON format
    cmd = [
        "tshark", 
        "-r", pcap_file,
        "-T", "json",
        "-e", "frame.time_epoch", 
        "-e", "frame.len",
        "-e", "ip.src", 
        "-e", "ip.dst",
        "-e", "tcp.srcport", 
        "-e", "tcp.dstport",
        "-e", "udp.srcport", 
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "tcp.flags",
        "-e", "tcp.analysis.retransmission",
        "-e", "http.request.method",
        "-e", "dns.qry.name",
        "-e", "ip.ttl"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing tshark: {e}")
        return []
    
    # Initialize data structures for each time window
    windows = defaultdict(lambda: {
        'packet_count': 0,
        'total_bytes': 0,
        'protocols': set(),
        'src_ips': set(),
        'dst_ips': set(),
        'src_ports': set(),
        'dst_ports': set(),
        # New data structures for enhanced features
        'syn_count': 0,
        'fin_count': 0,
        'rst_count': 0,
        'retransmissions': 0,
        'http_methods': defaultdict(int),
        'dns_queries': set(),
        'ttl_values': [],
        'payload_sizes': [],
        'ip_pairs': set(),
        'port_pairs': set(),
        'new_connections': 0,
        'unique_ip_port_pairs': set(),
        'bytes_in': 0,
        'bytes_out': 0,
        'packet_count_in': 0,
        'packet_count_out': 0,
        'internal_ips': set()
    })
    
    # Get the local IP address prefix to distinguish internal/external traffic
    local_ip_prefix = '192.168.1.'  # Adjust based on your network
    
    # Parse JSON output
    try:
        packets = json.loads(result.stdout)
        
        # Process each packet
        for packet in packets:
            if '_source' in packet and 'layers' in packet['_source']:
                layers = packet['_source']['layers']
                
                # Get timestamp and determine window
                if 'frame.time_epoch' in layers:
                    timestamp = float(layers['frame.time_epoch'][0])
                    window_id = int(timestamp // window_size)
                    
                    # Basic packet information
                    windows[window_id]['packet_count'] += 1
                    
                    # Packet size
                    packet_size = 0
                    if 'frame.len' in layers:
                        packet_size = int(layers['frame.len'][0])
                        windows[window_id]['total_bytes'] += packet_size
                        windows[window_id]['payload_sizes'].append(packet_size)
                    
                    # Protocol information
                    if '_ws.col.Protocol' in layers:
                        windows[window_id]['protocols'].add(layers['_ws.col.Protocol'][0])
                    
                    # IP information
                    src_ip = None
                    dst_ip = None
                    
                    if 'ip.src' in layers:
                        src_ip = layers['ip.src'][0]
                        windows[window_id]['src_ips'].add(src_ip)
                        
                        # Track internal IPs
                        if src_ip.startswith(local_ip_prefix):
                            windows[window_id]['internal_ips'].add(src_ip)
                    
                    if 'ip.dst' in layers:
                        dst_ip = layers['ip.dst'][0]
                        windows[window_id]['dst_ips'].add(dst_ip)
                        
                        # Track internal IPs
                        if dst_ip.startswith(local_ip_prefix):
                            windows[window_id]['internal_ips'].add(dst_ip)
                    
                    # Track unique IP pairs
                    if src_ip and dst_ip:
                        ip_pair = f"{src_ip}-{dst_ip}"
                        windows[window_id]['ip_pairs'].add(ip_pair)
                        
                        # Distinguish inbound and outbound traffic
                        if src_ip.startswith(local_ip_prefix) and not dst_ip.startswith(local_ip_prefix):
                            # Outbound traffic
                            windows[window_id]['bytes_out'] += packet_size
                            windows[window_id]['packet_count_out'] += 1
                        elif dst_ip.startswith(local_ip_prefix) and not src_ip.startswith(local_ip_prefix):
                            # Inbound traffic
                            windows[window_id]['bytes_in'] += packet_size
                            windows[window_id]['packet_count_in'] += 1
                    
                    # Port information
                    src_port = None
                    dst_port = None
                    
                    if 'tcp.srcport' in layers:
                        src_port = layers['tcp.srcport'][0]
                        windows[window_id]['src_ports'].add(src_port)
                    elif 'udp.srcport' in layers:
                        src_port = layers['udp.srcport'][0]
                        windows[window_id]['src_ports'].add(src_port)
                    
                    if 'tcp.dstport' in layers:
                        dst_port = layers['tcp.dstport'][0]
                        windows[window_id]['dst_ports'].add(dst_port)
                    elif 'udp.dstport' in layers:
                        dst_port = layers['udp.dstport'][0]
                        windows[window_id]['dst_ports'].add(dst_port)
                    
                    # Track unique port pairs
                    if src_port and dst_port:
                        port_pair = f"{src_port}-{dst_port}"
                        windows[window_id]['port_pairs'].add(port_pair)
                        
                        # Track unique IP:port combinations
                        if src_ip and dst_ip:
                            ip_port_pair = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                            windows[window_id]['unique_ip_port_pairs'].add(ip_port_pair)
                    
                    # TCP flags for identifying connection patterns
                    if 'tcp.flags' in layers:
                        tcp_flags = int(layers['tcp.flags'][0], 16)
                        
                        # SYN flag (0x02) - Connection establishment
                        if tcp_flags & 0x02:
                            windows[window_id]['syn_count'] += 1
                            windows[window_id]['new_connections'] += 1
                        
                        # FIN flag (0x01) - Connection termination
                        if tcp_flags & 0x01:
                            windows[window_id]['fin_count'] += 1
                        
                        # RST flag (0x04) - Connection reset
                        if tcp_flags & 0x04:
                            windows[window_id]['rst_count'] += 1
                    
                    # Retransmissions - indicator of network problems or potential DoS
                    if 'tcp.analysis.retransmission' in layers:
                        windows[window_id]['retransmissions'] += 1
                    
                    # HTTP methods - useful for detecting unusual web traffic patterns
                    if 'http.request.method' in layers:
                        method = layers['http.request.method'][0]
                        windows[window_id]['http_methods'][method] += 1
                    
                    # DNS queries - useful for detecting DNS tunneling or unusual domains
                    if 'dns.qry.name' in layers:
                        dns_query = layers['dns.qry.name'][0]
                        windows[window_id]['dns_queries'].add(dns_query)
                    
                    # TTL values - unusual TTLs can indicate spoofed packets
                    if 'ip.ttl' in layers:
                        ttl = int(layers['ip.ttl'][0])
                        windows[window_id]['ttl_values'].append(ttl)
    
    except json.JSONDecodeError:
        print(f"Error: Could not parse tshark output as JSON")
        return []
    
    # Convert windows to feature rows
    feature_rows = []
    for window_id, data in windows.items():
        # Calculate statistics for numeric lists
        ttl_values = data['ttl_values']
        ttl_mean = sum(ttl_values) / len(ttl_values) if ttl_values else 0
        ttl_std = (sum((x - ttl_mean) ** 2 for x in ttl_values) / len(ttl_values)) ** 0.5 if ttl_values else 0
        
        payload_sizes = data['payload_sizes']
        payload_mean = sum(payload_sizes) / len(payload_sizes) if payload_sizes else 0
        payload_std = (sum((x - payload_mean) ** 2 for x in payload_sizes) / len(payload_sizes)) ** 0.5 if payload_sizes else 0
        
        # Compute traffic ratios
        io_bytes_ratio = data['bytes_in'] / data['bytes_out'] if data['bytes_out'] > 0 else 0
        io_packet_ratio = data['packet_count_in'] / data['packet_count_out'] if data['packet_count_out'] > 0 else 0
        
        # Compute connection termination ratio
        termination_ratio = (data['fin_count'] + data['rst_count']) / data['syn_count'] if data['syn_count'] > 0 else 0
        
        # Create feature dictionary
        feature_row = {
            'window_id': window_id,
            'window_start': window_id * window_size,
            
            # Basic traffic metrics
            'packet_count': data['packet_count'],
            'bytes_per_second': data['total_bytes'] / window_size,
            'avg_packet_size': data['total_bytes'] / data['packet_count'] if data['packet_count'] > 0 else 0,
            'packet_size_std': payload_std,
            
            # Network entities
            'unique_protocols': len(data['protocols']),
            'unique_src_ips': len(data['src_ips']),
            'unique_dst_ips': len(data['dst_ips']),
            'unique_src_ports': len(data['src_ports']),
            'unique_dst_ports': len(data['dst_ports']),
            'unique_ip_pairs': len(data['ip_pairs']),
            'unique_port_pairs': len(data['port_pairs']),
            'unique_connections': len(data['unique_ip_port_pairs']),
            'dns_query_count': len(data['dns_queries']),
            
            # Traffic direction metrics
            'bytes_in': data['bytes_in'],
            'bytes_out': data['bytes_out'],
            'packets_in': data['packet_count_in'],
            'packets_out': data['packet_count_out'],
            'io_bytes_ratio': io_bytes_ratio,
            'io_packet_ratio': io_packet_ratio,
            
            # Connection pattern metrics
            'new_connections': data['new_connections'],
            'syn_count': data['syn_count'],
            'fin_count': data['fin_count'],
            'rst_count': data['rst_count'],
            'syn_fin_ratio': data['syn_count'] / data['fin_count'] if data['fin_count'] > 0 else 0,
            'connection_termination_ratio': termination_ratio,
            
            # Error metrics
            'retransmission_count': data['retransmissions'],
            'retransmission_rate': data['retransmissions'] / data['packet_count'] if data['packet_count'] > 0 else 0,
            
            # Network behavior metrics
            'internal_external_ratio': len(data['internal_ips']) / (len(data['src_ips']) + len(data['dst_ips']) - len(data['internal_ips'])) if (len(data['src_ips']) + len(data['dst_ips']) - len(data['internal_ips'])) > 0 else 0,
            'ttl_mean': ttl_mean,
            'ttl_std': ttl_std,
            
            # HTTP metrics (if present)
            'http_get_count': data['http_methods'].get('GET', 0),
            'http_post_count': data['http_methods'].get('POST', 0),
            'http_other_count': sum(data['http_methods'].values()) - data['http_methods'].get('GET', 0) - data['http_methods'].get('POST', 0),
            
            # Labels
            'is_baseline': 'baseline' in pcap_file.lower(),
            'file_source': os.path.basename(pcap_file)
        }
        
        feature_rows.append(feature_row)
        
    
    return feature_rows


def advanced_process(directory, output_csv):
    """
    Process all PCAP files in a directory and save features to CSV
    
    Args:
        directory: Directory containing PCAP files
        output_csv: Path to output CSV file
    """
    all_features = []
    
    # Process each PCAP file in the directory
    for filename in os.listdir(directory):
        if filename.endswith('.pcap'):
            file_path = os.path.join(directory, filename)
            features = advanced_extraction(file_path)
            all_features.extend(features)
    
    # Write features to CSV
    if all_features:
        fieldnames = all_features[0].keys()
        with open(output_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_features)
        
        print(f"Successfully extracted features from {len(all_features)} time windows")
        print(f"Data saved to {output_csv}")

        ##return the name of the output csv file
        return output_csv
    else:
        print("No features extracted")
