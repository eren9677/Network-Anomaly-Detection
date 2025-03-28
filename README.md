# Network Anomaly Detection Project

## Project Overview
This project focuses on network anomaly detection using packet capture and machine learning techniques. The project uses Wireshark's command-line interface (tshark) for network traffic collection and analysis.

## Prerequisites
- Python 3.13
- Conda (recommended)
- Wireshark CLI (tshark)
- Bash shell

## Project Structure
```
network-anomaly-detection/
│
├── pcap-files/
│   ├── baseline_day1.pcap
│   ├── anomalies.pcap
│   └── ...
│
|──data_extractors.py
│── anomaly_detection.ipynb
│── anomaly_generator.sh
|── current_usage.md
├── python_reqs.txt
└── README.md
```

## Setup and Installation

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/network-anomaly-detection.git
cd network-anomaly-detection
```

### 2. Create Conda Environment
```bash
conda create -n PackageTracer python=3.13
conda activate PackageTracer
```

### 3. Install Dependencies
```bash
pip install -r python_reqs.txt
```

## Network Packet Capture

### Starting PCAP Capture
To capture network traffic, use the following command:
```bash
cd pcap-files
tshark -i en0 -a duration:3600 -w baseline_day1.pcap
```
- `-i en0`: Specifies the network interface (WiFi on Mac)
- `-a duration:3600`: Captures traffic for 1 hour
- Recommended: Run capture for 3-5 days to collect sufficient data

### Converting PCAP to CSV
Convert captured PCAP files to basic CSV for machine learning:
```bash
tshark -r test.pcap -T fields \
  -e frame.number -e frame.time \
  -e eth.src -e eth.dst \
  -e ip.src -e ip.dst -e ip.proto \
  -E header=y -E separator=, \
  -E quote=d -E occurrence=f > test.csv
```

## Anomaly Generation

### Prepare Anomaly Generator
```bash
cd pcap-files
chmod +x anomaly_generator.sh
```

### Run Packet Capture with Anomaly Generation
```bash
cd pcap-files
tshark -i en0 -a duration:3600 -w anomalies.pcap & ../anomaly_generator.sh
```

## Important Notes
- PCAP files are not included in the repository due to large file size (≈700MB)
- Ensure you have a `pcap-files` directory in the project folder
- The project uses a conda environment named `PackageTracer`

## Jupyter Notebook
Open the Jupyter Notebook:
```bash
jupyter notebook notebooks/anomaly_detection.ipynb
```

## Cleanup
Before uploading to GitHub, remove large PCAP files to keep the repository size manageable.

## Contact
Eren Kızılırmak
