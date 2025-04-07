import os
import logging

class Logger:
    def __init__(self, log_file="ids.log"):
        self.log_file = log_file
        
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s — %(message)s',
            datefmt='%d-%m-%y %H:%M:%S'
        )
        self.logger = logging.getLogger('NIDS')
        
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s — %(message)s')
        console.setFormatter(formatter)
        self.logger.addHandler(console)
        
        if not os.path.exists(log_file):
            open(log_file, 'a').close()
    
    def log_intrusion(self, alert_info):
        intrusion_type = alert_info['intrusion_type']
        src_ip = alert_info['src_ip']
        if intrusion_type == 'Multiple Port Scanning' or intrusion_type == 'Sequential Port Scanning':
            targeted_ports = ','.join(map(str, alert_info['targeted_ports']))
            log_msg = f"Intrusion Type: {intrusion_type} — Attacker IP: {src_ip} — " \
                     f"Targeted Ports: {targeted_ports} — Time Span: {alert_info['time_span']}"
        
        elif intrusion_type == 'OS Fingerprinting':
            flags = ','.join(alert_info['flags'])
            log_msg = f"Intrusion Type: {intrusion_type} — Attacker IP: {src_ip} — " \
                     f"Flags: {flags} — Time Span: {alert_info['time_span']}"
        
        else:
            log_msg = f"Intrusion Type: {intrusion_type} — Attacker IP: {src_ip} — " \
                     f"Time Span: {alert_info['time_span']}"
        
        self.logger.warning(log_msg)
    
    def get_logs(self, n=None):
        try:
            with open(self.log_file, 'r') as f:
                logs = f.readlines()
            
            intrusion_logs = [log.strip() for log in logs if "Intrusion Type" in log]
            
            if n is None or n <= 0:
                return intrusion_logs
            else:
                return intrusion_logs[-n:]
                
        except FileNotFoundError:
            return []
        except Exception as e:
            print(f"Error reading log file: {e}")
            return []
    
    def log_system_event(self, event_type, message):
        log_msg = f"System Event: {event_type} — {message}"
        self.logger.info(log_msg)
    
    def _view_intrusion_logs(self):
        print("\n=== Intrusion Detection Logs ===\n")
        logs = self.get_logs()
        if not logs:
            print("No intrusion logs found.")
        else:
            recent_logs = logs[-10:] if len(logs) > 10 else logs
            for log in recent_logs:
                print(log)

    def generate_summary_report(self, log_file_path='ids.log'):
        try:
            total_incidents = 0
            unique_ips = set()
            intrusion_types = {}
            blocked_ips = set()
            unblocked_ips = set()
            earliest_timestamp = None
            latest_timestamp = None

            with open(log_file_path, 'r') as file:
                for line in file:
                    if not line.strip():
                        continue

                    try:
                        timestamp_str = line.split(' —')[0]
                    except IndexError:
                        continue  

                    if earliest_timestamp is None or timestamp_str < earliest_timestamp:
                        earliest_timestamp = timestamp_str
                    if latest_timestamp is None or timestamp_str > latest_timestamp:
                        latest_timestamp = timestamp_str

                    if "Intrusion Type:" in line:
                        total_incidents += 1

                        if "Intrusion Type: " in line:
                            try:
                                intrusion_type = line.split("Intrusion Type: ")[1].split(" —")[0]
                                intrusion_types[intrusion_type] = intrusion_types.get(intrusion_type, 0) + 1
                            except IndexError:
                                continue

                        if "Attacker IP: " in line:
                            try:
                                ip = line.split("Attacker IP: ")[1].split(" —")[0]
                                unique_ips.add(ip)
                            except IndexError:
                                continue

                    elif "BLOCK" in line and "Blocked IP " in line:
                        try:
                            ip = line.split("Blocked IP ")[1].split(" for")[0]
                            blocked_ips.add(ip)
                        except IndexError:
                            continue

                    elif "UNBLOCK" in line and "Unblocked IP " in line:
                        try:
                            ip = line.split("Unblocked IP ")[1].strip()
                            unblocked_ips.add(ip)
                        except IndexError:
                            continue

            print("\n" + "="*50)
            print("               IDS SUMMARY REPORT")
            print("="*50)
            print(f"Period: {earliest_timestamp} to {latest_timestamp}")
            print(f"Total Intrusion Incidents: {total_incidents}")
            print(f"Unique Attacker IPs: {len(unique_ips)}")

            print("\nIntrusion Types Breakdown:")
            for intrusion_type, count in intrusion_types.items():
                print(f"  - {intrusion_type}: {count} incidents")

            print("\nBlocking Statistics:")
            print(f"  - Total IPs Blocked: {len(blocked_ips)}")
            print(f"  - Total IPs Unblocked: {len(unblocked_ips)}")
            print(f"  - Currently Blocked IPs: {len(blocked_ips - unblocked_ips)}")

            if blocked_ips - unblocked_ips:
                print("\nCurrently Blocked IPs:")
                for ip in blocked_ips - unblocked_ips:
                    print(f"  - {ip}")

            print("="*50)

        except FileNotFoundError:
            print(f"Error: Log file '{log_file_path}' not found.")
        except Exception as e:
            print(f"Error generating summary report: {e}")

    