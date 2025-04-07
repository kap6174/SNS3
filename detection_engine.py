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
        
        self.tracker_lock = threading.Lock()
        
        self.port_scan_tracker = {}  # {src_ip: {timestamp: [dst_ports]}}
        self.seq_port_scan_tracker = {}  # {src_ip: {dst_ip: {timestamp: [ordered_ports]}}}
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
                    if packet_info.get('timestamp') is None:
                        print("Skip")
                        continue
                    self._detect_port_scanning(packet_info)
                    self._detect_sequential_port_scanning(packet_info)
                    self._detect_os_fingerprinting(packet_info)
                    self.packet_queue.task_done()
                else:
                    time.sleep(0.01)
            except Exception as e:
                print(f"Error in detection loop: {e}")
    
    def _detect_port_scanning(self, packet_info):
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        dst_port = packet_info['dst_port']
        current_time = packet_info['timestamp']
        current_time = packet_info.get('timestamp')
        if not isinstance(current_time, datetime):
            print(f"Invalid timestamp for packet: {packet_info}")
            return
        with self.tracker_lock:
            if src_ip not in self.port_scan_tracker:
                self.port_scan_tracker[src_ip] = {}
            
            #scan_window_key = (dst_ip, current_time.strftime('%Y%m%d%H%M'))
            scan_window_key = f"{dst_ip}-{int(current_time.timestamp() // 15)}"

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
                    'intrusion_type': 'Multiple Port Scanning',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'targeted_ports': sorted(list(window_data['ports'])),
                    'time_span': f"{time_span:.2f}s",
                    'action': 'block'
                }
                
                self.logger.log_intrusion(alert_info)
                self.alert_queue.put(alert_info)
    
    def _detect_sequential_port_scanning(self, packet_info):
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        dst_port = packet_info['dst_port']
        current_time = packet_info['timestamp']
        current_time = packet_info.get('timestamp')
        if not isinstance(current_time, datetime):
            print(f"Invalid timestamp for packet: {packet_info}")
            return

        with self.tracker_lock:
            if src_ip not in self.seq_port_scan_tracker:
                self.seq_port_scan_tracker[src_ip] = {}
            
            if dst_ip not in self.seq_port_scan_tracker[src_ip]:
                self.seq_port_scan_tracker[src_ip][dst_ip] = {}
            
            #scan_window_key = (dst_ip, current_time.strftime('%Y%m%d%H%M'))
            window_key = f"{dst_ip}-{int(current_time.timestamp() // 15)}"

            if window_key not in self.seq_port_scan_tracker[src_ip][dst_ip]:
                self.seq_port_scan_tracker[src_ip][dst_ip][window_key] = {
                    'start_time': current_time,
                    'ports': [],
                    'last_access': current_time,
                    'reported': False
                }
            
            window_data = self.seq_port_scan_tracker[src_ip][dst_ip][window_key]
            window_data['ports'].append(dst_port)
            window_data['last_access'] = current_time
            
        if len(window_data['ports']) >= 4 and not window_data['reported']:
            last_four = window_data['ports'][-4:]
            is_sequential = self._check_sequential_pattern(last_four)
            
            if is_sequential:
                time_span = (current_time - window_data['start_time']).total_seconds()
                window_data['reported'] = True
                
                alert_info = {
                    'timestamp': current_time,
                    'intrusion_type': 'Sequential Port Scanning',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'targeted_ports': last_four, 
                    'time_span': f"{time_span:.2f}s",
                    'action': 'block'
                }
                
                self.logger.log_intrusion(alert_info)
                self.alert_queue.put(alert_info)


    def _check_sequential_pattern(self, ports):
        sorted_ports = sorted(ports)
        
        if len(sorted_ports) >= 4:
            diffs = [sorted_ports[i] - sorted_ports[i-1] for i in range(1, len(sorted_ports))]
            
            unique_diffs = set(diffs)
            if len(unique_diffs) <= 1 and list(unique_diffs)[0] > 0:
                return True
                
        return False
    
    def _detect_os_fingerprinting(self, packet_info):
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        flags = packet_info['flags']
        current_time = packet_info['timestamp']
        current_time = packet_info.get('timestamp')
        if not isinstance(current_time, datetime):
            print(f"Invalid timestamp for packet: {packet_info}")
            return
        if 'S' not in str(flags) and 'A' not in str(flags) and 'F' not in str(flags):
            return
        
        with self.tracker_lock:
            if src_ip not in self.os_fingerprint_tracker:
                self.os_fingerprint_tracker[src_ip] = {}
            
            #window_key = (dst_ip, current_time.strftime('%Y%m%d%H%M'))
            window_key = f"{dst_ip}-{int(current_time.timestamp() // 15)}"
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
                
                with self.tracker_lock:
                    # Clean up port scan tracker
                    for src_ip in list(self.port_scan_tracker.keys()):
                        for window_key in list(self.port_scan_tracker[src_ip].keys()):
                            window_time = self.port_scan_tracker[src_ip][window_key]['start_time']
                            if (current_time - window_time).total_seconds() > 60:
                                del self.port_scan_tracker[src_ip][window_key]
                        
                        if not self.port_scan_tracker[src_ip]:
                            del self.port_scan_tracker[src_ip]
                    
                    # Clean up sequential port scan tracker
                    for src_ip in list(self.seq_port_scan_tracker.keys()):
                        for dst_ip in list(self.seq_port_scan_tracker[src_ip].keys()):
                            for window_key in list(self.seq_port_scan_tracker[src_ip][dst_ip].keys()):
                                window_data = self.seq_port_scan_tracker[src_ip][dst_ip][window_key]
                                if (current_time - window_data['last_access']).total_seconds() > 60:
                                    del self.seq_port_scan_tracker[src_ip][dst_ip][window_key]
                            
                            if not self.seq_port_scan_tracker[src_ip][dst_ip]:
                                del self.seq_port_scan_tracker[src_ip][dst_ip]
                        
                        if not self.seq_port_scan_tracker[src_ip]:
                            del self.seq_port_scan_tracker[src_ip]
                    
                    # Clean up OS fingerprint tracker
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