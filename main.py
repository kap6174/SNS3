# sudo ~/scapy-env/bin/python main.py

import queue
import time
import threading
from network_monitor import NetworkMonitor
from detection_engine import DetectionEngine
from prevention_system import PreventionSystem
from alert_logger import AlertLogger
from cli_interface import CommandLineInterface
import time

def main():
    packet_queue = queue.Queue()
    alert_queue = queue.Queue()
    
    logger = AlertLogger()
    prevention = PreventionSystem(logger)
    monitor = NetworkMonitor(packet_queue)
    detection = DetectionEngine(packet_queue, alert_queue, logger)
    
    alert_thread = threading.Thread(
        target=handle_alerts, 
        args=(alert_queue, prevention),
        daemon=True
    )
    alert_thread.start()
    
    cli = CommandLineInterface(monitor, detection, prevention, logger)
    cli.start()
    
    if monitor.is_running:
        monitor.stop_monitoring()
    
    print("Shutting down NIDS...")


def handle_alerts(alert_queue, prevention_system):
    while True:
        if alert_queue.empty():
            time.sleep(0.1)
            continue
        try:
            alert = alert_queue.get_nowait()

            if alert.get('action') == 'block':
                src_ip = alert.get('src_ip')
                intrusion_type = alert.get('intrusion_type')
                prevention_system.block_ip(src_ip, intrusion_type)

            alert_queue.task_done()

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