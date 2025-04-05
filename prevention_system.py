#!/usr/bin/env python3
import os
import platform
import subprocess
import re
from datetime import datetime

class PreventionSystem:
    def __init__(self, logger):
        """
        Initialize the Prevention System
        
        Args:
            logger: AlertLogger instance for logging actions
        """
        self.logger = logger
        self.blocked_ips = {}  # {ip: {'timestamp': str, 'reason': str}}
        self.os_type = platform.system()  # 'Windows', 'Linux', or 'Darwin' (macOS)
    
    def block_ip(self, ip_address, reason="Suspicious Activity"):
        """
        Block an IP address using the system's firewall
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Check if IP is already blocked
        if ip_address in self.blocked_ips:
            return True
            
        try:
            # Execute the appropriate command based on OS
            if self.os_type == "Linux":
                # Linux: Use iptables
                cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
                subprocess.run(cmd, shell=True, check=True)
            
            elif self.os_type == "Windows":
                # Windows: Use netsh advfirewall
                cmd = f'netsh advfirewall firewall add rule name="NIDS Block {ip_address}" ' \
                      f'dir=in interface=any action=block remoteip={ip_address}'
                subprocess.run(cmd, shell=True, check=True)
            
            elif self.os_type == "Darwin":  # macOS
                # macOS: Use pf (Packet Filter)
                # This is a simplified version; real implementation might need pf.conf modification
                # You would need to ensure pf is enabled with 'sudo pfctl -e'
                with open('/tmp/pf.rules', 'a') as f:
                    f.write(f"block in from {ip_address} to any\n")
                subprocess.run("sudo pfctl -f /tmp/pf.rules", shell=True, check=True)
            
            else:
                # Unsupported OS, just log the attempt
                self.logger.log_system_event("WARNING", f"Cannot block IP {ip_address}: unsupported OS")
                return False
            
            # Record the blocked IP
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.blocked_ips[ip_address] = {
                'timestamp': current_time,
                'reason': reason
            }
            
            # Log the action
            self.logger.log_system_event("BLOCK", f"Blocked IP {ip_address} for {reason}")
            return True
            
        except subprocess.SubprocessError as e:
            self.logger.log_system_event("ERROR", f"Failed to block IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address):
        """
        Unblock a previously blocked IP address
        
        Args:
            ip_address: IP address to unblock
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Check if IP is actually blocked
        if ip_address not in self.blocked_ips:
            return False
            
        try:
            # Execute the appropriate command based on OS
            if self.os_type == "Linux":
                # Linux: Use iptables
                cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
                subprocess.run(cmd, shell=True, check=True)
            
            elif self.os_type == "Windows":
                # Windows: Use netsh advfirewall
                cmd = f'netsh advfirewall firewall delete rule name="NIDS Block {ip_address}"'
                subprocess.run(cmd, shell=True, check=True)
            
            elif self.os_type == "Darwin":  # macOS
                # macOS: Use pf (Packet Filter)
                # For proper implementation, you'd need to modify pf.conf properly
                # This is a simplified example
                with open('/tmp/pf.rules', 'r') as f:
                    rules = f.readlines()
                
                with open('/tmp/pf.rules', 'w') as f:
                    for rule in rules:
                        if f"block in from {ip_address} to any" not in rule:
                            f.write(rule)
                
                subprocess.run("sudo pfctl -f /tmp/pf.rules", shell=True, check=True)
            
            else:
                # Unsupported OS, just log the attempt
                self.logger.log_system_event("WARNING", f"Cannot unblock IP {ip_address}: unsupported OS")
                return False
            
            # Remove the IP from our record
            del self.blocked_ips[ip_address]
            
            # Log the action
            self.logger.log_system_event("UNBLOCK", f"Unblocked IP {ip_address}")
            return True
            
        except subprocess.SubprocessError as e:
            self.logger.log_system_event("ERROR", f"Failed to unblock IP {ip_address}: {e}")
            return False
    
    def get_blocked_ips(self):
        """
        Get the list of blocked IP addresses
        
        Returns:
            dict: Dictionary of blocked IPs and their details
        """
        return self.blocked_ips
    
    def clear_block_list(self):
        """
        Clear the entire block list
        
        Returns:
            int: Number of IPs unblocked
        """
        count = 0
        for ip in list(self.blocked_ips.keys()):
            if self.unblock_ip(ip):
                count += 1
        
        return count
    
    def _get_system_blocked_ips(self):
        """
        Get the list of IPs blocked by the system firewall
        
        Returns:
            list: List of blocked IP addresses
        """
        blocked_ips = []
        
        try:
            if self.os_type == "Linux":
                # Linux: Use iptables
                cmd = "iptables -L INPUT -n"
                output = subprocess.check_output(cmd, shell=True, text=True)
                
                # Parse output to extract blocked IPs
                for line in output.splitlines():
                    if "DROP" in line:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            blocked_ips.append(match.group(1))
            
            elif self.os_type == "Windows":
                # Windows: Use netsh advfirewall
                cmd = 'netsh advfirewall firewall show rule name="NIDS Block*"'
                output = subprocess.check_output(cmd, shell=True, text=True)
                
                # Parse output to extract blocked IPs
                for line in output.splitlines():
                    if "RemoteIP:" in line:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            blocked_ips.append(match.group(1))
            
            elif self.os_type == "Darwin":  # macOS
                # macOS: Use pfctl
                cmd = "sudo pfctl -s rules"
                output = subprocess.check_output(cmd, shell=True, text=True)
                
                # Parse output to extract blocked IPs
                for line in output.splitlines():
                    if "block" in line and "from" in line:
                        match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            blocked_ips.append(match.group(1))
            
        except subprocess.SubprocessError as e:
            self.logger.log_system_event("ERROR", f"Failed to get system blocked IPs: {e}")
        
        return blocked_ips
    
    def sync_with_system(self):
        """
        Synchronize the blocked IP list with the system firewall
        
        This ensures the prevention system's internal state matches the actual system state
        """
        system_ips = self._get_system_blocked_ips()
        
        # Add IPs that are in the system but not in our record
        for ip in system_ips:
            if ip not in self.blocked_ips:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.blocked_ips[ip] = {
                    'timestamp': current_time,
                    'reason': "System blocked (synced)"
                }
        
        # Remove IPs that are in our record but not in the system
        for ip in list(self.blocked_ips.keys()):
            if ip not in system_ips:
                del self.blocked_ips[ip]