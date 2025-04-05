#!/usr/bin/env python3
import time
import threading
import collections
from datetime import datetime, timedelta

class DetectionEngine:
    def __init__(self, packet_queue, alert_queue, logger):
        """
        Initialize the Detection Engine
        
        Args:
            packet_queue: Queue containing captured network packets
            alert_queue: Queue for detected intrusions requiring action
            logger: Logger instance for recording detections
        """
        self.packet_queue = packet_queue
        self.alert_queue = alert_queue
        self.logger = logger
        self.is_running = False
        self.stop_detection = threading.Event()
        self.detection_thread = None
        
        # Detection state data structures
        self.port_scan_tracker = {}  # {src_ip: {timestamp: [dst_ports]}}
        self.os_fingerprint_tracker = {}  # {src_ip: {timestamp: [flag_combinations]}}
        
        # Clean-up older tracking data periodically
        self.cleanup_thread = None
    
    def start_detection(self):
        """Start the detection engine"""
        if self.is_running:
            print("Detection engine is already running.")
            return
        
        self.stop_detection.clear()
        self.detection_thread = threading.Thread(target=self._detection_loop)
        self.detection_thread.daemon = True
        self.detection_thread.start()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_old_data)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        
        self.is_running = True
        print("Detection engine started")
    
    def stop_detection(self):
        """Stop the detection engine"""
        if not self.is_running:
            print("Detection engine is not running.")
            return
        
        self.stop_detection.set()
        if self.detection_thread:
            self.detection_thread.join(timeout=2.0)
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=2.0)
        self.is_running = False
        print("Detection engine stopped")
    
    def _detection_loop(self):
        """Main detection loop that processes packets from the queue"""
        while not self.stop_detection.is_set():
            try:
                if not self.packet_queue.empty():
                    packet_info = self.packet_queue.get()
                    
                    # Apply detection rules
                    self._detect_port_scanning(packet_info)
                    self._detect_os_fingerprinting(packet_info)
                    
                    # Mark the task as done
                    self.packet_queue.task_done()
                else:
                    # No packets to process, sleep briefly
                    time.sleep(0.01)
            except Exception as e:
                print(f"Error in detection loop: {e}")
    
    def _detect_port_scanning(self, packet_info):
        """
        Detect port scanning activities
        Rule: More than 6 different ports accessed within 15 seconds
        """
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        dst_port = packet_info['dst_port']
        current_time = packet_info['timestamp']
        
        # Initialize data structure for this source IP if not exists
        if src_ip not in self.port_scan_tracker:
            self.port_scan_tracker[src_ip] = {}
        
        # Record this connection attempt
        scan_window_key = (dst_ip, current_time.strftime('%Y%m%d%H%M'))
        if scan_window_key not in self.port_scan_tracker[src_ip]:
            self.port_scan_tracker[src_ip][scan_window_key] = {
                'start_time': current_time,
                'ports': set(),
                'reported': False
            }
        
        # Add the destination port to the set of scanned ports
        self.port_scan_tracker[src_ip][scan_window_key]['ports'].add(dst_port)
        
        # Check if criteria for port scanning is met
        window_data = self.port_scan_tracker[src_ip][scan_window_key]
        if (len(window_data['ports']) > 6 and 
            not window_data['reported'] and
            (current_time - window_data['start_time']).total_seconds() <= 15):
            
            # Calculate time span of the attack
            time_span = (current_time - window_data['start_time']).total_seconds()
            
            # Mark as reported to prevent duplicate alerts
            window_data['reported'] = True
            
            # Generate alert
            alert_info = {
                'timestamp': current_time,
                'intrusion_type': 'Port Scanning',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'targeted_ports': sorted(list(window_data['ports'])),
                'time_span': f"{time_span:.2f}s",
                'action': 'block'
            }
            
            # Log the intrusion
            self.logger.log_intrusion(alert_info)
            
            # Add to alert queue for prevention system
            self.alert_queue.put(alert_info)
    
    def _detect_os_fingerprinting(self, packet_info):
        """
        Detect OS fingerprinting attempts
        Rule: 5 different SYN, ACK, and FIN flag combinations within 20 seconds
        """
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        flags = packet_info['flags']
        current_time = packet_info['timestamp']
        
        # Only track TCP packets with SYN, ACK, or FIN flags
        if 'S' not in str(flags) and 'A' not in str(flags) and 'F' not in str(flags):
            return
        
        # Initialize data structure for this source IP if not exists
        if src_ip not in self.os_fingerprint_tracker:
            self.os_fingerprint_tracker[src_ip] = {}
        
        # Create a key for the current 20-second window
        window_key = (dst_ip, current_time.strftime('%Y%m%d%H%M'))
        if window_key not in self.os_fingerprint_tracker[src_ip]:
            self.os_fingerprint_tracker[src_ip][window_key] = {
                'start_time': current_time,
                'flag_combos': set(),
                'reported': False
            }
        
        # Add the flag combination to the set
        flag_combo = str(flags)
        self.os_fingerprint_tracker[src_ip][window_key]['flag_combos'].add(flag_combo)
        
        # Check if criteria for OS fingerprinting is met
        window_data = self.os_fingerprint_tracker[src_ip][window_key]
        if (len(window_data['flag_combos']) >= 5 and 
            not window_data['reported'] and
            (current_time - window_data['start_time']).total_seconds() <= 20):
            
            # Calculate time span of the attack
            time_span = (current_time - window_data['start_time']).total_seconds()
            
            # Mark as reported to prevent duplicate alerts
            window_data['reported'] = True
            
            # Generate alert
            alert_info = {
                'timestamp': current_time,
                'intrusion_type': 'OS Fingerprinting',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'flags': list(window_data['flag_combos']),
                'time_span': f"{time_span:.2f}s",
                'action': 'block'
            }
            
            # Log the intrusion
            self.logger.log_intrusion(alert_info)
            
            # Add to alert queue for prevention system
            self.alert_queue.put(alert_info)
    
    def _cleanup_old_data(self):
        """Clean up old tracking data to prevent memory leaks"""
        while not self.stop_detection.is_set():
            try:
                current_time = datetime.now()
                
                # Clean up port scan tracker
                for src_ip in list(self.port_scan_tracker.keys()):
                    for window_key in list(self.port_scan_tracker[src_ip].keys()):
                        window_time = self.port_scan_tracker[src_ip][window_key]['start_time']
                        if (current_time - window_time).total_seconds() > 60:
                            del self.port_scan_tracker[src_ip][window_key]
                    
                    # Remove empty dictionaries
                    if not self.port_scan_tracker[src_ip]:
                        del self.port_scan_tracker[src_ip]
                
                # Clean up OS fingerprinting tracker
                for src_ip in list(self.os_fingerprint_tracker.keys()):
                    for window_key in list(self.os_fingerprint_tracker[src_ip].keys()):
                        window_time = self.os_fingerprint_tracker[src_ip][window_key]['start_time']
                        if (current_time - window_time).total_seconds() > 60:
                            del self.os_fingerprint_tracker[src_ip][window_key]
                    
                    # Remove empty dictionaries
                    if not self.os_fingerprint_tracker[src_ip]:
                        del self.os_fingerprint_tracker[src_ip]
                
                # Sleep for 30 seconds before next cleanup
                time.sleep(30)
            except Exception as e:
                print(f"Error in cleanup thread: {e}")
                time.sleep(5)  # Sleep briefly before retrying