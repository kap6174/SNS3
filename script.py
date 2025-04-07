from scapy.all import IP, TCP, UDP, ICMP, send, conf
import random
import time
import argparse
import socket
import sys

conf.verb = 0

class IDSTester:
    def __init__(self, target_ip="127.0.0.1"):
        self.target_ip = target_ip
        self.verbose = True
        #self.source_ip = socket.gethostbyname("localhost")
        self.source_ip = "192.168.0.10"
        self.log(f"IDS Tester initialized. Target: {target_ip}, Source: {self.source_ip}")
    
    def log(self, message):
        if self.verbose:
            print(f"[*] {message}")
    
    def port_scan(self, num_ports=8, delay=0.1, sequential=True):
        scan_type = "sequential" if sequential else "random"
        self.log(f"Starting port scan simulation - {scan_type} ports")
        
        source_port = random.randint(49152, 65535)
        
        if sequential:
            start_port = random.randint(1, 65535 - num_ports)
            ports_to_scan = range(start_port, start_port + num_ports)
            self.log(f"Sequential port scan from port {start_port} to {start_port + num_ports - 1}")
        else:
            ports_to_scan = random.sample(range(1, 65536), num_ports)
            self.log(f"Random port scan: {sorted(ports_to_scan)}")
        
        for port in ports_to_scan:
            packet = IP(src=self.source_ip, dst=self.target_ip) / \
                     TCP(sport=source_port, dport=port, flags="S")
            send(packet)
            self.log(f"Sent TCP SYN packet to port {port}")
            time.sleep(delay)
        
        self.log(f"Port scan simulation completed. Scanned {num_ports} ports.")
        return True
    
    def os_fingerprint(self, num_attempts=6, delay=1.0, target_port=None):
        flag_combinations = [
            "S", "SA", "F", "FA", "SF", "PA", "RA", "FSPU", "FPU"
        ]
        
        if num_attempts > len(flag_combinations):
            selected_flags = flag_combinations
        else:
            selected_flags = random.sample(flag_combinations, num_attempts)
        
        self.log(f"Starting OS fingerprinting simulation with {len(selected_flags)} flag combinations")
        source_port = random.randint(49152, 65535)
        
        for flags in selected_flags:
            port = target_port if target_port else random.randint(1, 1024)
            packet = IP(src=self.source_ip, dst=self.target_ip) / \
                     TCP(sport=source_port, dport=port, flags=flags)
            send(packet)
            self.log(f"Sent TCP packet with flags '{flags or 'NULL'}' to port {port}")
            time.sleep(delay)
        
        self.log("OS fingerprinting simulation completed.")
        return True
    
    def send_mixed_traffic(self, num_packets=10, delay=0.5):
        self.log(f"Sending {num_packets} mixed TCP/UDP/ICMP packets")

        for i in range(num_packets):
            proto_choice = random.choice(["TCP", "UDP", "ICMP"])
            dst_port = random.randint(1, 1024)
            src_port = random.randint(49152, 65535)

            if proto_choice == "TCP":
                packet = IP(src=self.source_ip, dst=self.target_ip) / \
                         TCP(sport=src_port, dport=dst_port, flags="S")
                self.log(f"Sent TCP SYN to port {dst_port}")
            elif proto_choice == "UDP":
                packet = IP(src=self.source_ip, dst=self.target_ip) / \
                         UDP(sport=src_port, dport=dst_port)
                self.log(f"Sent UDP packet to port {dst_port}")
            elif proto_choice == "ICMP":
                packet = IP(src=self.source_ip, dst=self.target_ip) / \
                         ICMP()
                self.log("Sent ICMP Echo Request")

            send(packet)
            time.sleep(delay)

        self.log("Mixed traffic simulation completed.")
        return True


def main():
    parser = argparse.ArgumentParser(description="IDS Testing Framework")
    parser.add_argument("-t", "--target", default="127.0.0.1")
    parser.add_argument("--test", choices=["port-scan-random", "port-scan-sequential", "os-fingerprint", "mixed"], 
                        default="port-scan-random")
    parser.add_argument("-n", "--num", type=int, default=8)
    parser.add_argument("-d", "--delay", type=float, default=0.5)
    parser.add_argument("-p", "--port", type=int, default=0)
    args = parser.parse_args()

    try:
        tester = IDSTester(args.target)
        
        if args.test == "port-scan-random":
            tester.port_scan(args.num, args.delay, sequential=False)
        elif args.test == "port-scan-sequential":
            tester.port_scan(args.num, args.delay, sequential=True)
        elif args.test == "os-fingerprint":
            target_port = args.port if args.port > 0 else None
            tester.os_fingerprint(args.num, args.delay, target_port)
        elif args.test == "mixed":
            tester.send_mixed_traffic(args.num, args.delay)

    except KeyboardInterrupt:
        print("\n[!] Test terminated by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
