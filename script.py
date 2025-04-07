from scapy.all import IP, TCP, send, conf
import random
import time
import argparse
import socket
import sys

conf.verb = 0

class IDSTester:
    def __init__(self, target_ip="127.0.0.1", verbose=True):
        self.target_ip = target_ip
        self.verbose = verbose
        self.source_ip = socket.gethostbyname("localhost")
        self.log(f"IDS Tester initialized. Target: {target_ip}, Source: {self.source_ip}")
    
    def log(self, message):
        if self.verbose:
            print(f"[*] {message}")
    
    def port_scan(self, num_ports=8, delay=0.1, sequential=True):
        self.log(f"Starting port scan simulation - {'sequential' if sequential else 'random'} ports")
        
        source_port = random.randint(49152, 65535)
        
        if sequential:
            start_port = random.randint(1, 65535 - num_ports)
            ports_to_scan = range(start_port, start_port + num_ports)
        else:
            ports_to_scan = random.sample(range(1, 65536), num_ports)
        
        self.log(f"Scanning {num_ports} ports with {delay}s delay")
        
        for port in ports_to_scan:
            packet = IP(src=self.source_ip, dst=self.target_ip) / \
                    TCP(sport=source_port, dport=port, flags="S")
            
            send(packet)
            self.log(f"Sent SYN packet to port {port}")
            time.sleep(delay)
        
        self.log(f"Port scan simulation completed. Scanned {num_ports} ports.")
        return True
    
    def os_fingerprint(self, num_attempts=6, delay=1.0, target_port=None):
        flag_combinations = [
            "S",        # SYN
            "SA",       # SYN-ACK
            "F",        # FIN
            "FA",       # FIN-ACK
            "SF",       # SYN-FIN (unusual combination)
            #"PA",       # PSH-ACK
            #"R",        # RST
            #"RA",       # RST-ACK
            #"",         # NULL (no flags)
            #"FSPU",     # FIN-SYN-PSH-URG (XMAS scan)
            #"FPU",      # FIN-PSH-URG
        ]
        
        if num_attempts > len(flag_combinations):
            selected_flags = flag_combinations
        else:
            selected_flags = random.sample(flag_combinations, num_attempts)
        
        self.log(f"Starting OS fingerprinting simulation with {len(selected_flags)} flag combinations")
        
        source_port = random.randint(49152, 65535)
        
        for flags in selected_flags:
            if target_port is None:
                port = random.randint(1, 1024)
            else:
                port = target_port
            
            packet = IP(src=self.source_ip, dst=self.target_ip) / \
                    TCP(sport=source_port, dport=port, flags=flags)
            
            send(packet)
            
            flag_str = flags if flags else "NULL"
            self.log(f"Sent packet with flags '{flag_str}' to port {port}")
            
            time.sleep(delay)
        
        self.log("OS fingerprinting simulation completed.")
        return True
    

def main():
    parser = argparse.ArgumentParser(description="IDS Testing Framework")
    parser.add_argument("-t", "--target", default="127.0.0.1")
    parser.add_argument("--test", choices=["all", "port-scan", "os-fingerprint"], default="port-scan")
    parser.add_argument("-n", "--num", type=int, default=0)
    parser.add_argument("-d", "--delay", type=float, default=0)
    parser.add_argument("-p", "--port", type=int, default=0)
    parser.add_argument("-s", "--sequential", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_false", dest="verbose")
    args = parser.parse_args()

    try:
        tester = IDSTester(args.target, args.verbose)
        
        if args.test == "port-scan":
            num_ports = 8
            delay = 0.5
            tester.port_scan(num_ports, delay, True)
        elif args.test == "os-fingerprint":
            num_attempts = 6
            delay = args.delay if args.delay > 0 else 1.0
            target_port = args.port if args.port > 0 else None
            tester.os_fingerprint(num_attempts, delay, target_port)
            
    except KeyboardInterrupt:
        print("\n[!] Test terminated by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()