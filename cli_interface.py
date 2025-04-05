#!/usr/bin/env python3
import os
import sys
import time
from datetime import datetime

class CommandLineInterface:
    def __init__(self, network_monitor, detection_engine, prevention_system, logger):
        """
        Initialize the Command Line Interface
        
        Args:
            network_monitor: NetworkMonitor instance
            detection_engine: DetectionEngine instance
            prevention_system: PreventionSystem instance
            logger: AlertLogger instance
        """
        self.network_monitor = network_monitor
        self.detection_engine = detection_engine
        self.prevention_system = prevention_system
        self.logger = logger
        self.running = True
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Display the NIDS banner"""
        banner = """
        #########################################################
        #                                                       #
        #             Network Intrusion Detection System        #
        #                                                       #
        #########################################################
        """
        print(banner)
    
    def display_menu(self):
        """Display the main menu options"""
        menu = """
        1. Start IDS
        2. Stop IDS
        3. View Live Traffic
        4. View Intrusion Logs
        5. Display Blocked IPs
        6. Clear Block List
        7. Unblock an IP
        8. Exit
        
        Enter your choice: """
        
        return input(menu)
    
    def start(self):
        """Start the CLI interface"""
        while self.running:
            self.clear_screen()
            self.display_banner()
            choice = self.display_menu()
            
            if choice == '1':
                self._start_ids()
            elif choice == '2':
                self._stop_ids()
            elif choice == '3':
                self._view_live_traffic()
            elif choice == '4':
                self._view_intrusion_logs()
            elif choice == '5':
                self._display_blocked_ips()
            elif choice == '6':
                self._clear_block_list()
            elif choice == '7':
                self._unblock_ip()
            elif choice == '8':
                self._exit()
            else:
                print("\nInvalid choice. Press Enter to continue...")
                input()
    
    def _start_ids(self):
        """Start the IDS components"""
        print("\nStarting Network-based Intrusion Detection System...")
        
        # Start network monitoring
        if not self.network_monitor.is_running:
            self.network_monitor.start_monitoring()
        
        # Start detection engine
        if not self.detection_engine.is_running:
            self.detection_engine.start_detection()
        
        print("\nIDS is now running and monitoring network traffic.")
        print("Press Enter to return to the menu...")
        input()
    
    def _stop_ids(self):
        """Stop the IDS components"""
        print("\nStopping Network-based Intrusion Detection System...")
        
        # Stop detection engine first
        if self.detection_engine.is_running:
            self.detection_engine.stop_detection()
        
        # Then stop network monitoring
        if self.network_monitor.is_running:
            self.network_monitor.stop_monitoring()
        
        print("\nIDS has been stopped.")
        print("Press Enter to return to the menu...")
        input()
    
    def _view_live_traffic(self):
        """View live network traffic"""
        self.clear_screen()
        print("\n=== Live Network Traffic ===")
        print("Press Ctrl+C to return to the menu\n")
        
        # Enable debug mode to see live traffic
        original_debug_mode = getattr(self.network_monitor, 'debug_mode', False)
        self.network_monitor.set_debug_mode(True)
        
        try:
            # If monitoring is not running, start it temporarily
            temp_started = False
            if not self.network_monitor.is_running:
                self.network_monitor.start_monitoring()
                temp_started = True
            
            # Wait and display traffic
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            # Restore original debug mode
            self.network_monitor.set_debug_mode(original_debug_mode)
            
            # If we temporarily started monitoring, stop it
            if temp_started and self.network_monitor.is_running:
                self.network_monitor.stop_monitoring()
    
    def _view_intrusion_logs(self):
        """View intrusion logs from the IDS log file"""
        self.clear_screen()
        print("\n=== Intrusion Detection Logs ===\n")
        
        logs = self.logger.get_logs()
        if not logs:
            print("No intrusion logs found.")
        else:
            # Display most recent 10 logs, or all if less than 10
            recent_logs = logs[-10:] if len(logs) > 10 else logs
            for log in recent_logs:
                print(log)
        
        print("\nPress Enter to return to the menu...")
        input()
    
    def _display_blocked_ips(self):
        """Display the list of blocked IPs"""
        self.clear_screen()
        print("\n=== Blocked IP Addresses ===\n")
        
        blocked_ips = self.prevention_system.get_blocked_ips()
        if not blocked_ips:
            print("No IPs are currently blocked.")
        else:
            print(f"{'IP Address':<20} {'Reason':<20} {'Blocked Since':<20}")
            print("-" * 60)
            for ip, details in blocked_ips.items():
                print(f"{ip:<20} {details['reason']:<20} {details['timestamp']}")
        
        print("\nPress Enter to return to the menu...")
        input()
    
    def _clear_block_list(self):
        """Clear the entire block list"""
        self.clear_screen()
        print("\n=== Clear Block List ===\n")
        
        confirmation = input("Are you sure you want to unblock all IPs? (y/n): ")
        if confirmation.lower() == 'y':
            count = self.prevention_system.clear_block_list()
            print(f"\n{count} IP addresses have been unblocked.")
        else:
            print("\nOperation cancelled.")
        
        print("\nPress Enter to return to the menu...")
        input()
    
    def _unblock_ip(self):
        """Unblock a specific IP address"""
        self.clear_screen()
        print("\n=== Unblock IP Address ===\n")
        
        ip_address = input("Enter the IP address to unblock: ")
        if ip_address:
            if self.prevention_system.unblock_ip(ip_address):
                print(f"\nSuccessfully unblocked {ip_address}.")
            else:
                print(f"\n{ip_address} was not in the block list.")
        else:
            print("\nNo IP address entered.")
        
        print("\nPress Enter to return to the menu...")
        input()
    
    def _exit(self):
        """Exit the CLI and IDS system"""
        self.clear_screen()
        print("\nShutting down NIDS...")
        
        # Stop components in proper order
        if self.detection_engine.is_running:
            self.detection_engine.stop_detection()
        
        if self.network_monitor.is_running:
            self.network_monitor.stop_monitoring()
        
        print("NIDS shutdown complete.")
        print("Goodbye!")
        self.running = False