import struct

HEADER_SIZE = 6  # URP header size in bytes
class URPSegment:
    def __init__(self, seq_num=0, flags=0, payload=b''):
        """
        Args:
            seq_num: 16-bit sequence number
            flags: 3-bit flags (ACK=1, SYN=2, FIN=4)
            payload: Data payload (bytes)
        """
        self.seq_num = seq_num & 0xFFFF  # Ensure 16-bit
        self.flags = flags & 0x07  # Ensure 3-bit
        self.payload = payload
        self.checksum = 0
        
    def set_flag(self, flag_name):
        if flag_name == 'ACK':
            self.flags = 1
        elif flag_name == 'SYN':
            self.flags = 2
        elif flag_name == 'FIN':
            self.flags = 4
        else:  # DATA
            self.flags = 0
            
    def is_ack(self):
        return self.flags == 1
        
    def is_syn(self):
        return self.flags == 2
        
    def is_fin(self):
        return self.flags == 4
        
    def is_data(self):
        return self.flags == 0
        
    def compute_checksum(self):
        """
        Compute 16-bit checksum for error detection.
        Uses ones' complement sum (similar to TCP/UDP checksum).
        """
        checksum = 0
        
        checksum += (self.seq_num >> 8) & 0xFF
        checksum += self.seq_num & 0xFF
        
        flags_reserved = (self.flags << 13) & 0xE000
        checksum += (flags_reserved >> 8) & 0xFF
        checksum += flags_reserved & 0xFF
        
        for byte in self.payload:
            checksum += byte
            
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
            
        # Ones' complement.
        self.checksum = (~checksum) & 0xFFFF
        return self.checksum
        
    def verify_checksum(self):
        checksum_sum = 0
        
        checksum_sum += (self.seq_num >> 8) & 0xFF
        checksum_sum += self.seq_num & 0xFF
        
        flags_reserved = (self.flags << 13) & 0xE000
        checksum_sum += (flags_reserved >> 8) & 0xFF
        checksum_sum += flags_reserved & 0xFF
        
        for byte in self.payload:
            checksum_sum += byte
        
        while checksum_sum >> 16:
            checksum_sum = (checksum_sum & 0xFFFF) + (checksum_sum >> 16)
        
        total = checksum_sum + self.checksum

        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
            
        # Should equal 0xFFFF if checksum is valid.
        return total == 0xFFFF
        
    def encode(self):
        self.compute_checksum()
        
        # Pack header: sequence number (2 bytes), reserved+flags (2 bytes), checksum (2 bytes).
        # Network byte order (big-endian).
        header = struct.pack('>H', self.seq_num)
        flags_reserved = struct.pack('>H', (self.flags << 13))
        checksum = struct.pack('>H', self.checksum)
        
        return header + flags_reserved + checksum + self.payload
        
    @staticmethod
    def decode(data):
        if len(data) < HEADER_SIZE:
            return None
            
        try:
            # Extract header fields.
            seq_num = struct.unpack('>H', data[0:2])[0]
            
            # Extract flags (bits 13-15 of the reserved+flags field).
            flags_reserved = struct.unpack('>H', data[2:4])[0]
            flags = (flags_reserved >> 13) & 0x07
            
            # Extract checksum.
            checksum = struct.unpack('>H', data[4:6])[0]
            
            # Extract payload.
            payload = data[6:] if len(data) > HEADER_SIZE else b''
            
            segment = URPSegment(seq_num, flags, payload)
            segment.checksum = checksum
            
            return segment
        except:
            return None