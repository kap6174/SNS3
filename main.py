#!/usr/bin/env python3
import queue
import time
import threading
from network_monitor import NetworkMonitor
from detection_engine import DetectionEngine
from prevention_system import PreventionSystem
from alert_logger import AlertLogger
from cli_interface import CommandLineInterface

def main():
    """Main entry point for the Network Intrusion Detection System"""
    # Create shared resources
    packet_queue = queue.Queue()
    alert_queue = queue.Queue()
    
    # Initialize components
    logger = AlertLogger()
    prevention = PreventionSystem(logger)
    
    # Create and configure the network monitor
    monitor = NetworkMonitor(packet_queue)
    
    # Create the detection engine
    detection = DetectionEngine(packet_queue, alert_queue, logger)
    
    # Start the alert handler thread
    alert_thread = threading.Thread(
        target=handle_alerts, 
        args=(alert_queue, prevention),
        daemon=True
    )
    alert_thread.start()
    
    # Start the CLI interface
    cli = CommandLineInterface(monitor, detection, prevention, logger)
    cli.start()
    
    # Clean up when CLI exits
    if monitor.is_running:
        monitor.stop_monitoring()
    
    print("Shutting down NIDS...")

def handle_alerts(alert_queue, prevention_system):
    """Process alerts from the detection engine"""
    while True:
        try:
            alert = alert_queue.get(timeout=1.0)
            if alert['action'] == 'block':
                prevention_system.block_ip(alert['src_ip'], alert['intrusion_type'])
            
            # Alert is already logged by the detection engine
            
            # Mark the task as done
            alert_queue.task_done()
        except queue.Empty:
            # No alerts in queue, continue checking
            continue
        except Exception as e:
            print(f"Error processing alert: {e}")
        time.sleep(0.1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting NIDS...")
    except Exception as e:
        print(f"Error: {e}")
        print("NIDS crashed. Check logs for details.")