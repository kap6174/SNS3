# Lab Assignment 3: Signature and Anomaly-based Intrusion Detection and Prevention System (NIDPS)

## Description

This is a simple Network Intrusion Detection System (NIDS) built with Python and Scapy. It monitors network traffic, detects potential intrusions such as port scanning and OS fingerprinting, logs alerts, and can block suspicious IP addresses using iptables.

## Features

- Real-time network traffic monitoring
- Detection of port scanning and OS fingerprinting attempts
- Logging of intrusion attempts and system events
- Automatic blocking of suspicious IP addresses
- Command-line interface for controlling the system and viewing logs

## Requirements

- **Operating System**: Linux (due to iptables usage)
- **Python**: Version 3.x
- **Scapy**: Python library for packet manipulation
- **Root Privileges**: Required for packet capturing and iptables manipulation

## Installation

Follow these steps to set up the NIDS on your system:

1. **Install Python**:  
   Ensure Python 3.x is installed. You can check this by running:
   ```bash
   python3 --version
   ```
   If not installed, install it using your package manager (e.g., `sudo apt install python3` on Debian/Ubuntu).

2. **Create a Virtual Environment** (optional but recommended):
   ```bash
   python3 -m venv scapy-env
   source scapy-env/bin/activate
   ```

3. **Install Scapy**:  
   With the virtual environment activated, install Scapy:
   ```bash
   pip install scapy
   ```

4. **Clone or Download the Project Files**:  
   Download all provided Python files (`main.py`, `network_monitor.py`, `detection_engine.py`, `prevention_system.py`, `alert_logger.py`, `cli_interface.py`) into a single directory.

## Usage

Run the Main Script: Execute the NIDS with `sudo` privileges due to the need for raw packet access and iptables modifications:
```bash
sudo ~/scapy-env/bin/python main.py
```
Replace `~/scapy-env/bin/python` with the path to your Python interpreter if using a different virtual environment or system Python.

### Interact with the Command-Line Interface (CLI)

Upon running, a menu will appear with the following options:

1. Start IDS: Begins monitoring and detection.  
2. Stop IDS: Stops monitoring and detection.  
3. View Live Traffic: Displays real-time packet information (Ctrl+C to exit).  
4. View Intrusion Logs: Shows the latest intrusion attempts.  
5. Display Blocked IPs: Lists currently blocked IP addresses.  
6. Clear Block List: Unblocks all IPs after confirmation.  
7. Unblock an IP: Unblocks a specific IP address.  
8. Generate Summary Report: Displays a summary of incidents and blocking statistics.  
9. Exit: Shuts down the NIDS.  

## Configuration

**Network Interface**:  
By default, the system monitors the loopback interface (`"lo"`). To monitor a different interface (e.g., `"eth0"` or `"wlan0"`), modify the `NetworkMonitor` instantiation in `main.py`:
```python
monitor = NetworkMonitor(packet_queue, interface="eth0")
```
Replace `"eth0"` with your desired interface. You can find available interfaces using `ifconfig` or `ip link`.

## Implementation Overview

The NIDS is composed of several modular components:

### NetworkMonitor (`network_monitor.py`)
- Captures TCP packets using Scapy on the specified interface.
- Places packet details (timestamp, source/destination IPs, ports, flags) into a queue.

### DetectionEngine (`detection_engine.py`)
- Analyzes packets from the queue for intrusion patterns:
  - **Port Scanning**: Triggers if an IP accesses more than 6 different ports within 15 seconds.
  - **OS Fingerprinting**: Triggers if an IP sends packets with 5 or more different SYN/ACK/FIN flag combinations within 20 seconds.
- Generates alerts and queues them for logging and prevention.

### AlertLogger (`alert_logger.py`)
- Logs intrusion alerts and system events to `ids.log` and the console.
- Formats logs with timestamps and details (e.g., attacker IP, targeted ports).

### PreventionSystem (`prevention_system.py`)
- Blocks suspicious IPs using iptables (`iptables -A INPUT -s <IP> -j DROP`).
- Maintains a list of blocked IPs with timestamps and reasons.
- Supports unblocking and syncing with system iptables rules.

### CommandLineInterface (`cli_interface.py`)
- Provides a menu-driven interface to start/stop the IDS, view traffic/logs, manage blocked IPs, and generate reports.

### Main (`main.py`)
- Initializes all components, sets up queues, and starts the CLI.
- Runs an alert-handling thread to process blocking actions.

## Execution Flow

1. **Packet Capture**: `NetworkMonitor` sniffs packets and queues them.  
2. **Detection**: `DetectionEngine` processes packets, detects intrusions, and queues alerts.  
3. **Logging & Prevention**: `AlertLogger` logs alerts, and `PreventionSystem` blocks IPs as needed.  
4. **User Interaction**: `CommandLineInterface` allows control and monitoring via the CLI.

## Inputs and Outputs

**Inputs**:  
- Network packets captured from the specified interface.

**Outputs**:  
- **Log File**: `ids.log` contains intrusion and system event logs (e.g., `"Intrusion Type: Port Scanning — Attacker IP: 192.168.1.1 — Targeted Ports: 22,80,..."`).  
- **Console Output**: Real-time alerts and traffic information.  
- **Summary Reports**: CLI-generated reports detailing incidents, unique IPs, intrusion types, and blocking stats.

## Examples

**Starting the IDS**: Select option 1 to begin monitoring:
```
IDS is now running and monitoring network traffic.
```

**Viewing Live Traffic**: Select option 3 to see packets in real-time:
```
14:35:22 192.168.1.1:12345 → 192.168.1.2:80 [SYN]
14:35:23 192.168.1.1:12346 → 192.168.1.2:22 [SYN|ACK]
```

**Viewing Intrusion Logs**: Select option 4 to view recent logs:
```
25-10-23 14:35:25 — Intrusion Type: Port Scanning — Attacker IP: 192.168.1.1 — Targeted Ports: 22,80,443,8080,21,23,25 — Time Span: 12.34s
```


## Customization

**Detection Rules**: Adjust detection thresholds in `detection_engine.py`:
- `_detect_port_scanning`: Change `len(window_data['ports']) > 6` or time window `<= 15`.
- `_detect_os_fingerprinting`: Change `len(window_data['flag_combos']) >= 5` or time window `<= 20`.

## Troubleshooting

- **Permission Errors**: Ensure `sudo` is used due to raw socket and iptables requirements.
- **Interface Not Found**: Verify the interface exists with `ifconfig` or `ip link`.
- **Scapy Issues**: Confirm Scapy is installed (`pip show scapy`) and the virtual environment is active.

> **Note**: This system modifies iptables rules, which may affect network connectivity. Monitor logs for false positives and have a rollback plan (e.g., `iptables -F` to flush rules).

## License

IIIT-Hyderabad SNS Course'25

## Contributors

Nikhil Saxena (2024201034)
Junaid Ahmed (2024201018)
Swarnadeep Saha (2024201049)