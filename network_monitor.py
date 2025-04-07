from scapy.all import sniff, IP, TCP
import time
import threading
import queue
from datetime import datetime

class NetworkMonitor:
    def __init__(self, packet_queue, interface="lo"):
        self.packet_queue = packet_queue
        self.interface = interface
        self.stop_sniffing = threading.Event()
        self.sniffer_thread = None
        self.is_running = False
        
    def start_monitoring(self):
        if self.is_running:
            print("Network monitoring is already running.")
            return
            
        self.stop_sniffing.clear()
        self.sniffer_thread = threading.Thread(target=self._sniff_packets)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        self.is_running = True
        print(f"Network monitoring started on {self.interface or 'all interfaces'}")
    
    def stop_monitoring(self):
        if not self.is_running:
            print("Network monitoring is not running.")
            return
            
        self.stop_sniffing.set()
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2.0)
        self.is_running = False
        print("Network monitoring stopped")
    
    def _sniff_packets(self):
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda _: self.stop_sniffing.is_set()
            )
        except Exception as e:
            print(f"Error in packet sniffing: {e}")
    
    def _process_packet(self, packet):
        if IP in packet and TCP in packet:
            packet_info = {
                'timestamp': datetime.now(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': 'TCP',
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'flags': packet[TCP].flags,
                'raw_packet': packet
            }
            
            self.packet_queue.put(packet_info)
            
            # For viewing live traffic
            if hasattr(self, 'debug_mode') and self.debug_mode:
                flags_str = self._tcp_flags_to_str(packet[TCP].flags)
                print(f"{packet_info['timestamp'].strftime('%H:%M:%S')} "
                      f"{packet_info['src_ip']}:{packet_info['src_port']} → "
                      f"{packet_info['dst_ip']}:{packet_info['dst_port']} "
                      f"[{flags_str}]")
    
    def _tcp_flags_to_str(self, flags):
        flag_map = {
            'F': 'FIN',
            'S': 'SYN',
            'R': 'RST',
            'P': 'PSH',
            'A': 'ACK',
            'U': 'URG',
            'E': 'ECE',
            'C': 'CWR'
        }
        
        flag_str = []
        for flag_char, flag_name in flag_map.items():
            if flag_char in str(flags):
                flag_str.append(flag_name)
        
        return '|'.join(flag_str) if flag_str else 'None'
    
    def set_debug_mode(self, enabled=True):
        self.debug_mode = enabled


def start_packet_processing():
    packet_queue = queue.Queue()
    monitor = NetworkMonitor(packet_queue)
    monitor.set_debug_mode(True)
    monitor.start_monitoring()
    
    try:
        while True:
            if not packet_queue.empty():
                packet_info = packet_queue.get()
            time.sleep(0.01) 

    except KeyboardInterrupt:
        print("\nStopping network monitor...")
        monitor.stop_monitoring()
        print("Exiting...")

if __name__ == "__main__":
    start_packet_processing()