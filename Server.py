import socket
import struct
from checksum import calculate_checksum 

def extract_data_from_packet(packet):
    """
    Extracts the data portion from a correctly formatted IPv4 packet.

    Args:
        packet: The received IPv4 packet data (bytes).

    Returns:
        The extracted data portion (bytes), or None if the packet format is invalid.

    Raises:
        ValueError: If the packet length is less than 20 bytes (minimum header size).
    """

    # Check if packet length is sufficient for a valid header
    if len(packet) < 20:
        raise ValueError("Packet length is too short for a valid IPv4 header")

    try:
        # Extract the IPv4 header
        ipv4_header = struct.unpack("!BBHHHBBH4s4s", packet[:20])
    except struct.error as e:
        # Handle potential errors during unpacking
        print(f"Error unpacking header: {e}")
        return None

    # Extract the data portion (assuming valid format)
    data = packet[20:]
    return data




def verify_checksum(packet):
    # Check if packet length is sufficient
    if len(packet) < 20:
        return False

    # Extract IPv4 header and received checksum
    ipv4_header = packet[:20]
    received_checksum = struct.unpack("!H", ipv4_header[10:12])[0]

    # Calculate checksum for the entire packet (excluding checksum field)
    checksum = calculate_checksum(packet[:10] + packet[12:])

    # Verify if calculated and received checksums match
    return received_checksum == checksum


def server():
    # Create socket and bind to address
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 8889))
        s.listen()
        i=1
        print("Server is listening for connections...")
        conn, addr = s.accept()

        # Reassemble fragments
        reassembled_data = b""
        while True:
            fragment = conn.recv(1500)
            if not fragment:
                break
            fragment = extract_data_from_packet(fragment)
            with open(f'fragment_{i}.dat', 'wb') as file:
                file.write(fragment)
            reassembled_data += fragment  
            print(f"Fragment Number {i} - {fragment}")
            i=i+1
        
            

        # Extract data from the reassembled data (excluding IPv4 header)
            
        # Example usage
        try:
            extracted_data = extract_data_from_packet(reassembled_data)
            if extracted_data is not None:
                if verify_checksum(reassembled_data):
                    print("Checksum verified! Processing data...")
            # Process the extracted data (extracted_data)
                else:
                    print("Checksum mismatch! Rejecting or requesting retransmission...")
        except:
            print("Error extracting data from packet!")
        print(reassembled_data.decode('utf-8', errors='ignore'))

if __name__ == "__main__":
    server()