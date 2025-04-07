import os
import logging

class AlertLogger:
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
        
        if intrusion_type == 'Port Scanning':
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
        
        print(f"[ALERT] {log_msg}")
    
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