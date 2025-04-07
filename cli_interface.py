import os
import time

class CommandLineInterface:
    def __init__(self, network_monitor, detection_engine, prevention_system, logger):
        self.network_monitor = network_monitor
        self.detection_engine = detection_engine
        self.prevention_system = prevention_system
        self.logger = logger
        self.running = True
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_menu(self):
        menu = """
Network Intrusion Detection and Prevention System
1. Start IDS
2. Stop IDS
3. View Live Traffic
4. View Intrusion Logs
5. Display Blocked IPs
6. Clear Block List
7. Unblock an IP
8. Generate Summary Report
9. Exit

Enter your choice: """
        
        return input(menu)
    
    def start(self):
        while self.running:
            choice = self.display_menu()
            
            if choice == '1':
                self._start_ids()
            elif choice == '2':
                self._stop_ids()
            elif choice == '3':
                self._view_live_traffic()
            elif choice == '4':
                self.logger._view_intrusion_logs()
            elif choice == '5':
                self._display_blocked_ips()
            elif choice == '6':
                self._clear_block_list()
            elif choice == '7':
                self._unblock_ip()
            elif choice == '8':
                self.logger.generate_summary_report()
            elif choice == '9':
                self._exit()
            else:
                print("\nInvalid choice. Press Enter to continue...")
                input()
    
    def _start_ids(self):
        if not self.network_monitor.is_running:
            self.network_monitor.start_monitoring()
        
        if not self.detection_engine.is_running:
            self.detection_engine.start_detection()
        
        print("\nIDS is now running and monitoring network traffic.")
    
    def _stop_ids(self):        
        if self.detection_engine.is_running:
            self.detection_engine.stop_detection_system()
        
        if self.network_monitor.is_running:
            self.network_monitor.stop_monitoring()
        
        print("\nIDS has been stopped.")
    
    def _view_live_traffic(self):
        self.clear_screen()
        print("\n=== Live Network Traffic ===")
        print("Press Ctrl+C to return to the menu\n")
        
        original_debug_mode = getattr(self.network_monitor, 'debug_mode', False)
        self.network_monitor.set_debug_mode(True)
        
        try:
            temp_started = False
            if not self.network_monitor.is_running:
                self.network_monitor.start_monitoring()
                temp_started = True
            
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            self.network_monitor.set_debug_mode(original_debug_mode)
            
            if temp_started and self.network_monitor.is_running:
                self.network_monitor.stop_monitoring()     
    
    def _display_blocked_ips(self):
        print("\n=== Blocked IP Addresses ===\n")
        
        blocked_ips = self.prevention_system.get_blocked_ips()
        if not blocked_ips:
            print("No IPs are currently blocked.")
        else:
            print(f"{'IP Address':<20} {'Reason':<20} {'Blocked Since':<20}")
            print("-" * 60)
            for ip, details in blocked_ips.items():
                print(f"{ip:<20} {details['reason']:<20} {details['timestamp']}")
        
    
    def _clear_block_list(self):
        print("\n=== Clear Block List ===\n")
        
        confirmation = input("Are you sure you want to unblock all IPs? (y/n): ")
        if confirmation.lower() == 'y':
            count = self.prevention_system.clear_block_list()
            print(f"\n{count} IP addresses have been unblocked.")
        else:
            print("\nOperation cancelled.")
        
    
    def _unblock_ip(self):
        print("\n=== Unblock IP Address ===\n")
        
        ip_address = input("Enter the IP address to unblock: ")
        if ip_address:
            if self.prevention_system.unblock_ip(ip_address):
                print(f"\nSuccessfully unblocked {ip_address}.")
            else:
                print(f"\n{ip_address} was not in the block list.")
        else:
            print("\nNo IP address entered.")
        
    
    def _exit(self):
        self.clear_screen()
        print("\nShutting down NIDS...")
        
        if self.detection_engine.is_running:
            self.detection_engine.stop_detection_system()
        
        if self.network_monitor.is_running:
            self.network_monitor.stop_monitoring()
        
        self.running = False

    

