#TODO : 
# cleanup thread and detection thread use same dicts. Add locks.

import time
import threading
from datetime import datetime

class DetectionEngine:
    def __init__(self, packet_queue, alert_queue, logger):
        self.packet_queue = packet_queue
        self.alert_queue = alert_queue
        self.logger = logger
        self.is_running = False
        self.stop_detection = threading.Event()
        self.detection_thread = None
        
        self.port_scan_tracker = {}  # {src_ip: {timestamp: [dst_ports]}}
        self.os_fingerprint_tracker = {}  # {src_ip: {timestamp: [flag_combinations]}}
        
        self.cleanup_thread = None
    
    def start_detection(self):
        if self.is_running:
            return
        
        self.stop_detection.clear()
        self.detection_thread = threading.Thread(target=self._detection_loop)
        self.detection_thread.daemon = True
        self.detection_thread.start()
        
        self.cleanup_thread = threading.Thread(target=self._cleanup_old_data)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        
        self.is_running = True
        print("Detection engine started")
    
    def stop_detection_system(self):
        if not self.is_running:
            return
        
        self.stop_detection.set()
        if self.detection_thread:
            self.detection_thread.join(timeout=2.0)
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=2.0)
        self.is_running = False
        print("Detection engine stopped")
    
    def _detection_loop(self):
        while not self.stop_detection.is_set():
            try:
                if not self.packet_queue.empty():
                    packet_info = self.packet_queue.get()
                    
                    self._detect_port_scanning(packet_info)
                    self._detect_os_fingerprinting(packet_info)
                    
                    self.packet_queue.task_done()
                else:
                    time.sleep(0.01)
            except Exception as e:
                print(f"Error in detection loop: {e}")
    
    def _detect_port_scanning(self, packet_info):

        #Rule: More than 6 different ports accessed within 15 seconds
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        dst_port = packet_info['dst_port']
        current_time = packet_info['timestamp']
        
        if src_ip not in self.port_scan_tracker:
            self.port_scan_tracker[src_ip] = {}
        

        scan_window_key = (dst_ip, current_time.strftime('%Y%m%d%H%M'))
        if scan_window_key not in self.port_scan_tracker[src_ip]:
            self.port_scan_tracker[src_ip][scan_window_key] = {
                'start_time': current_time,
                'ports': set(),
                'reported': False
            }
        
        self.port_scan_tracker[src_ip][scan_window_key]['ports'].add(dst_port)
        
        window_data = self.port_scan_tracker[src_ip][scan_window_key]
        if (len(window_data['ports']) > 6 and 
            not window_data['reported'] and
            (current_time - window_data['start_time']).total_seconds() <= 15):
            
            time_span = (current_time - window_data['start_time']).total_seconds()
            
            window_data['reported'] = True
            
            alert_info = {
                'timestamp': current_time,
                'intrusion_type': 'Port Scanning',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'targeted_ports': sorted(list(window_data['ports'])),
                'time_span': f"{time_span:.2f}s",
                'action': 'block'
            }
            
            self.logger.log_intrusion(alert_info)
            
            self.alert_queue.put(alert_info)
    
    def _detect_os_fingerprinting(self, packet_info):
        """
        Rule: 5 different SYN, ACK, and FIN flag combinations within 20 seconds
        """
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        flags = packet_info['flags']
        current_time = packet_info['timestamp']
        
        if 'S' not in str(flags) and 'A' not in str(flags) and 'F' not in str(flags):
            return
        
        if src_ip not in self.os_fingerprint_tracker:
            self.os_fingerprint_tracker[src_ip] = {}
        
        window_key = (dst_ip, current_time.strftime('%Y%m%d%H%M'))
        if window_key not in self.os_fingerprint_tracker[src_ip]:
            self.os_fingerprint_tracker[src_ip][window_key] = {
                'start_time': current_time,
                'flag_combos': set(),
                'reported': False
            }
        
        flag_combo = str(flags)
        self.os_fingerprint_tracker[src_ip][window_key]['flag_combos'].add(flag_combo)
        
        window_data = self.os_fingerprint_tracker[src_ip][window_key]
        if (len(window_data['flag_combos']) >= 5 and 
            not window_data['reported'] and
            (current_time - window_data['start_time']).total_seconds() <= 20):
            
            time_span = (current_time - window_data['start_time']).total_seconds()
            
            window_data['reported'] = True
            
            alert_info = {
                'timestamp': current_time,
                'intrusion_type': 'OS Fingerprinting',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'flags': list(window_data['flag_combos']),
                'time_span': f"{time_span:.2f}s",
                'action': 'block'
            }
            
            self.logger.log_intrusion(alert_info)
            
            self.alert_queue.put(alert_info)
    
    def _cleanup_old_data(self):
        while not self.stop_detection.is_set():
            try:
                current_time = datetime.now()
                
                for src_ip in list(self.port_scan_tracker.keys()):
                    for window_key in list(self.port_scan_tracker[src_ip].keys()):
                        window_time = self.port_scan_tracker[src_ip][window_key]['start_time']
                        if (current_time - window_time).total_seconds() > 60:
                            del self.port_scan_tracker[src_ip][window_key]
                    
                    if not self.port_scan_tracker[src_ip]:
                        del self.port_scan_tracker[src_ip]
                
                for src_ip in list(self.os_fingerprint_tracker.keys()):
                    for window_key in list(self.os_fingerprint_tracker[src_ip].keys()):
                        window_time = self.os_fingerprint_tracker[src_ip][window_key]['start_time']
                        if (current_time - window_time).total_seconds() > 60:
                            del self.os_fingerprint_tracker[src_ip][window_key]
                    
                    if not self.os_fingerprint_tracker[src_ip]:
                        del self.os_fingerprint_tracker[src_ip]
                
                time.sleep(30)
            except Exception as e:
                print(f"Error in cleanup thread: {e}")
                time.sleep(5)  # Sleep briefly before retrying