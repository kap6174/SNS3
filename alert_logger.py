#!/usr/bin/env python3
import os
import logging
from datetime import datetime

class AlertLogger:
    def __init__(self, log_file="ids.log"):
        """
        Initialize the Alert Logger
        
        Args:
            log_file: Path to the log file
        """
        self.log_file = log_file
        
        # Set up logging configuration
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s — %(message)s',
            datefmt='%d-%m-%y %H:%M:%S'
        )
        self.logger = logging.getLogger('NIDS')
        
        # Also log to console
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s — %(message)s')
        console.setFormatter(formatter)
        self.logger.addHandler(console)
        
        # Create log file if it doesn't exist
        if not os.path.exists(log_file):
            open(log_file, 'a').close()
    
    def log_intrusion(self, alert_info):
        """
        Log an intrusion detection
        
        Args:
            alert_info: Dictionary containing intrusion details
        """
        intrusion_type = alert_info['intrusion_type']
        src_ip = alert_info['src_ip']
        
        # Format log message based on intrusion type
        if intrusion_type == 'Port Scanning':
            targeted_ports = ','.join(map(str, alert_info['targeted_ports']))
            log_msg = f"Intrusion Type: {intrusion_type} — Attacker IP: {src_ip} — " \
                     f"Targeted Ports: {targeted_ports} — Time Span: {alert_info['time_span']}"
        
        elif intrusion_type == 'OS Fingerprinting':
            flags = ','.join(alert_info['flags'])
            log_msg = f"Intrusion Type: {intrusion_type} — Attacker IP: {src_ip} — " \
                     f"Flags: {flags} — Time Span: {alert_info['time_span']}"
        
        else:
            # Generic format for other intrusion types
            log_msg = f"Intrusion Type: {intrusion_type} — Attacker IP: {src_ip} — " \
                     f"Time Span: {alert_info['time_span']}"
        
        # Log the message
        self.logger.warning(log_msg)
        
        print(f"[ALERT] {log_msg}")
    
    def get_logs(self, n=None):
        """
        Get recent logs from the log file
        
        Args:
            n: Number of recent logs to retrieve (None for all)
            
        Returns:
            List of log entries
        """
        try:
            with open(self.log_file, 'r') as f:
                logs = f.readlines()
            
            # Filter for intrusion logs only (containing "Intrusion Type")
            intrusion_logs = [log.strip() for log in logs if "Intrusion Type" in log]
            
            # Return all logs or last n logs
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
        """
        Log a system event
        
        Args:
            event_type: Type of event (e.g., "START", "STOP", "ERROR")
            message: Event message
        """
        log_msg = f"System Event: {event_type} — {message}"
        self.logger.info(log_msg)