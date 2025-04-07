import platform
import subprocess
import re
from datetime import datetime

class PreventionSystem:
    def __init__(self, logger):
        self.logger = logger
        self.blocked_ips = {}  # {ip: {'timestamp': str, 'reason': str}}
        self.os_type = platform.system()  # 'Windows', 'Linux'
    
    def block_ip(self, ip_address, reason="Suspicious Activity"):
        if ip_address in self.blocked_ips:
            return True
            
        try:
            cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
            subprocess.run(cmd, shell=True, check=True)
            
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.blocked_ips[ip_address] = {
                'timestamp': current_time,
                'reason': reason
            }
            
            self.logger.log_system_event("BLOCK", f"Blocked IP {ip_address} for {reason}")
            return True
            
        except subprocess.SubprocessError as e:
            self.logger.log_system_event("ERROR", f"Failed to block IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address):
        if ip_address not in self.blocked_ips:
            return False
            
        try:
            cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
            subprocess.run(cmd, shell=True, check=True)
            del self.blocked_ips[ip_address]
            self.logger.log_system_event("UNBLOCK", f"Unblocked IP {ip_address}")
            return True
            
        except subprocess.SubprocessError as e:
            self.logger.log_system_event("ERROR", f"Failed to unblock IP {ip_address}: {e}")
            return False
    
    def get_blocked_ips(self):
        return self.blocked_ips
    
    def clear_block_list(self):
        count = 0
        for ip in list(self.blocked_ips.keys()):
            if self.unblock_ip(ip):
                count += 1
        
        return count
    
    def _get_system_blocked_ips(self):
        blocked_ips = []
    
        try:
            cmd = "iptables -L INPUT -n"
            output = subprocess.check_output(cmd, shell=True, text=True)
            
            for line in output.splitlines():
                if "DROP" in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        blocked_ips.append(match.group(1))
            
        except subprocess.SubprocessError as e:
            self.logger.log_system_event("ERROR", f"Failed to get system blocked IPs: {e}")
        
        return blocked_ips
    
    def sync_with_system(self):
        system_ips = self._get_system_blocked_ips()
        
        for ip in system_ips:
            if ip not in self.blocked_ips:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.blocked_ips[ip] = {
                    'timestamp': current_time,
                    'reason': "System blocked (synced)"
                }
        for ip in list(self.blocked_ips.keys()):
            if ip not in system_ips:
                del self.blocked_ips[ip]