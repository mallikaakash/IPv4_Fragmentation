def calculate_checksum(data):
    # Simple checksum calculation for demonstration purposes
    checksum = 0
    for i in range(0, len(data), 2):
        checksum += (data[i] << 8) + data[i + 1]
        if checksum > 0xFFFF:
            checksum = (checksum & 0xFFFF) + 1
    return ~checksum & 0xFFFF