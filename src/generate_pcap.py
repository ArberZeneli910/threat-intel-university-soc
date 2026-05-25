from scapy.all import *
import random

def generate_nmap_portscan(packets=100):
    """Generate NMAP-style port scan - triggers ET SCAN rules"""
    traffic = []
    
    for port in range(1, packets+1):
        pkt = (
            IP(src="45.33.32.156",
               dst="192.168.1.1",
               ttl=64) /
            TCP(sport=36000,
                dport=port,
                flags="S",
                seq=random.randint(1000000, 9999999))
        )
        traffic.append(pkt)
    
    return traffic

def generate_null_scan(packets=50):
    """Generate NULL scan - triggers ET SCAN rules"""
    traffic = []
    
    for port in range(1, packets+1):
        pkt = (
            IP(src="45.33.32.156",
               dst="192.168.1.1") /
            TCP(sport=36000,
                dport=port,
                flags="")  # NULL scan - no flags
        )
        traffic.append(pkt)
    
    return traffic

def generate_xmas_scan(packets=50):
    """Generate XMAS scan - triggers ET SCAN rules"""
    traffic = []
    
    for port in range(1, packets+1):
        pkt = (
            IP(src="45.33.32.156",
               dst="192.168.1.1") /
            TCP(sport=36000,
                dport=port,
                flags="FPU")  # XMAS scan
        )
        traffic.append(pkt)
    
    return traffic

def generate_c2_beacon(packets=100):
    """Generate C2 beacon traffic"""
    traffic = []
    
    for i in range(packets):
        pkt = (
            IP(src="162.243.103.246",  # Known malicious IP as source
               dst="192.168.1.100") /
            TCP(sport=random.randint(1024,65535),
                dport=4444) /
            Raw(load=b"GET /beacon HTTP/1.1\r\nHost: c2server.com\r\n\r\n")
        )
        traffic.append(pkt)
    
    return traffic

def generate_normal_traffic(packets=100):
    """Generate normal HTTP traffic"""
    traffic = []
    
    for i in range(packets):
        pkt = (
            IP(src=f"192.168.1.{random.randint(2,254)}",
               dst="93.184.216.34") /
            TCP(sport=random.randint(1024,65535),
                dport=80) /
            Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )
        traffic.append(pkt)
    
    return traffic

def main():
    print("Generating university network traffic scenarios...")
    
    all_packets = []
    
    print("Generating normal traffic...")
    all_packets.extend(generate_normal_traffic(200))
    
    print("Generating NMAP port scan...")
    all_packets.extend(generate_nmap_portscan(200))
    
    print("Generating NULL scan...")
    all_packets.extend(generate_null_scan(100))
    
    print("Generating XMAS scan...")
    all_packets.extend(generate_xmas_scan(100))
    
    print("Generating C2 beacon traffic...")
    all_packets.extend(generate_c2_beacon(100))
    
    output_file = "/home/arber/thesis-project/data/pcaps/test.pcap"
    wrpcap(output_file, all_packets)
    print(f"Generated {len(all_packets)} packets")
    print(f"Saved to {output_file}")

if __name__ == "__main__":
    main()

