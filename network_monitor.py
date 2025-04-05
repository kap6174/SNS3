from scapy.all import sniff, IP, TCP
import time
import threading
import queue
import logging
from datetime import datetime

class NetworkMonitor:
    def __init__(self, packet_queue, interface=None):
        """
        Initialize the Network Monitor
        
        Args:
            packet_queue: Queue to store captured packets for processing
            interface: Network interface to monitor (None means all interfaces)
        """
        self.packet_queue = packet_queue
        self.interface = interface
        self.stop_sniffing = threading.Event()
        self.sniffer_thread = None
        self.is_running = False
        
        # Set up logging
        logging.basicConfig(
            filename='ids.log',
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
        
    def start_monitoring(self):
        """Start capturing network packets"""
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
        """Stop capturing network packets"""
        if not self.is_running:
            print("Network monitoring is not running.")
            return
            
        self.stop_sniffing.set()
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2.0)
        self.is_running = False
        print("Network monitoring stopped")
    
    def _sniff_packets(self):
        """Sniff packets and put them in the queue for processing"""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda _: self.stop_sniffing.is_set()
            )
        except Exception as e:
            self.logger.error(f"Error in packet sniffing: {e}")
            print(f"Error in packet sniffing: {e}")
    
    def _process_packet(self, packet):
        """Process a captured packet and extract relevant information"""
        if IP in packet and TCP in packet:
            # Extract relevant packet information
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
            
            # Put packet info in the queue for further processing by detection engine
            self.packet_queue.put(packet_info)
            
            # Debug output for viewing live traffic
            if hasattr(self, 'debug_mode') and self.debug_mode:
                flags_str = self._tcp_flags_to_str(packet[TCP].flags)
                print(f"{packet_info['timestamp'].strftime('%H:%M:%S')} "
                      f"{packet_info['src_ip']}:{packet_info['src_port']} → "
                      f"{packet_info['dst_ip']}:{packet_info['dst_port']} "
                      f"[{flags_str}]")
    
    def _tcp_flags_to_str(self, flags):
        """Convert TCP flags to string representation"""
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
        """Set debug mode to print live traffic"""
        self.debug_mode = enabled

def start_packet_processing():
    """Example function to demonstrate how to use NetworkMonitor"""
    # Create a queue for passing packets between threads
    packet_queue = queue.Queue()
    
    # Create and start the network monitor
    monitor = NetworkMonitor(packet_queue)
    monitor.set_debug_mode(True)
    monitor.start_monitoring()
    
    try:
        while True:
            # In a real implementation, a separate detection engine would
            # process packets from the queue
            if not packet_queue.empty():
                packet_info = packet_queue.get()
                # Process packet (this would be handled by the detection engine)
            time.sleep(0.01)  # Prevent CPU from maxing out
    except KeyboardInterrupt:
        print("\nStopping network monitor...")
        monitor.stop_monitoring()
        print("Exiting...")

if __name__ == "__main__":
    # This allows the module to be run independently for testing
    start_packet_processing()