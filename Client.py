import socket
import struct
from checksum import calculate_checksum 


def create_ipv4_packet(data, fragment_offset, more_fragments_flag):
    version_ihl = 0x45  # IPv4, Header Length (5 words)
    type_of_service = 0
    total_length = len(data) + 20  # Data length + IPv4 header length
    identification = 12345
    flags_fragment_offset = (more_fragments_flag << 13) | fragment_offset
    time_to_live = 64
    protocol = socket.IPPROTO_TCP  # Assuming TCP protocol
    source_address = socket.inet_aton("127.0.0.1")
    destination_address = socket.inet_aton("127.0.0.1")

    # Construct IPv4 header (without checksum)
    ipv4_header = struct.pack("!BBHHHBBH4s4s",
                              version_ihl,
                              type_of_service,
                              total_length,
                              identification,
                              flags_fragment_offset,
                              time_to_live,
                              protocol,
                              0,  # Placeholder for checksum
                              source_address,
                              destination_address)

    # Calculate checksum (on header only)
    checksum = calculate_checksum(ipv4_header)

    # Update the header with the calculated checksum
    ipv4_header = ipv4_header[:10] + struct.pack("!H", checksum) + ipv4_header[12:]

    # Append data to the packet
    return ipv4_header + data.encode()

def client():
    # Take the input file
    filename=str(input("Enter the file name(kindly keep it in same directory)"))

    # Read data from file
    with open(filename, 'r') as file:
        data = file.read()

    # Get MTU size from user
    mtu_size = int(input("Enter MTU size: "))
    
    # Perform fragmentation and send packets to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 8889))
        offset = 0
        i=1
        while offset < len(data):
            fragment = data[offset:offset+mtu_size]
            more_fragments = 1 if (offset + mtu_size) < len(data) else 0
            packet= create_ipv4_packet(fragment, offset // 8, more_fragments)
            with open(f"ReassembledData_{filename}",'a') as file1:
                file1.writelines(str(packet) + '\n')
            print(f"Packet Number {i} - {fragment}") 
            i=i+1   
            s.send(packet)
            offset += mtu_size

if __name__ == "__main__":
    client()