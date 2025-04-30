import socket
import struct

# Function to parse IP header
def parse_ip_header(data):
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    ttl = ip_header[5]
    protocol = ip_header[6]
    src_addr = socket.inet_ntoa(ip_header[8])
    dst_addr = socket.inet_ntoa(ip_header[9])

    return {
        'version': version,
        'header_length': ihl * 4,
        'ttl': ttl,
        'protocol': protocol,
        'src_addr': src_addr,
        'dst_addr': dst_addr
    }

def main():
    try:
        # Create raw socket for Windows
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind(("192.168.1.4", 0))  # <-- Replace with your local IP address

        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Enable promiscuous mode (Windows-specific)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        print("Sniffer started... Press Ctrl+C to stop.\n")
        while True:
            raw_data, addr = sniffer.recvfrom(65565)
            ip_info = parse_ip_header(raw_data)

            print(f"[+] Packet -> Src: {ip_info['src_addr']} | Dst: {ip_info['dst_addr']} | "
                  f"Protocol: {ip_info['protocol']} | TTL: {ip_info['ttl']}")
    except KeyboardInterrupt:
        print("\nSniffer stopped.")
        # Disable promiscuous mode
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()

