import struct

HEADER_SIZE = 6  # URP header size in bytes
class URPSegment:
    """
    Represents a URP segment with header and payload.
    Handles encoding/decoding of the 6-byte header format.
    """
    def __init__(self, seq_num=0, flags=0, payload=b''):
        """
        Initialize a URP segment.
        
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
        """Set a flag (ACK, SYN, or FIN)."""
        if flag_name == 'ACK':
            self.flags = 1
        elif flag_name == 'SYN':
            self.flags = 2
        elif flag_name == 'FIN':
            self.flags = 4
        else:  # DATA
            self.flags = 0
            
    def is_ack(self):
        """Check if segment is an ACK."""
        return self.flags == 1
        
    def is_syn(self):
        """Check if segment is a SYN."""
        return self.flags == 2
        
    def is_fin(self):
        """Check if segment is a FIN."""
        return self.flags == 4
        
    def is_data(self):
        """Check if segment is a DATA segment."""
        return self.flags == 0
        
    def compute_checksum(self):
        """
        Compute 16-bit checksum for error detection.
        Uses ones' complement sum (similar to TCP/UDP checksum).
        """
        checksum = 0
        
        # Add header fields (excluding checksum field itself)
        checksum += (self.seq_num >> 8) & 0xFF
        checksum += self.seq_num & 0xFF
        
        # Reserved + Flags (2 bytes) - flags in upper 3 bits
        flags_reserved = (self.flags << 13) & 0xE000
        checksum += (flags_reserved >> 8) & 0xFF
        checksum += flags_reserved & 0xFF
        
        # Add payload bytes
        for byte in self.payload:
            checksum += byte
            
        # Add carry bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
            
        # Ones' complement
        self.checksum = (~checksum) & 0xFFFF
        return self.checksum
        
    def verify_checksum(self):
        """
        Verify the checksum of a received segment.
        Returns True if checksum is valid, False otherwise.
        
        Verification: Sum all fields (including checksum as 16-bit value), add carries.
        Result should be 0xFFFF.
        """
        # Recompute what the sum should have been (without checksum)
        checksum_sum = 0
        
        # Add sequence number (2 bytes) - treat as individual bytes
        checksum_sum += (self.seq_num >> 8) & 0xFF
        checksum_sum += self.seq_num & 0xFF
        
        # Add flags + reserved (2 bytes) - treat as individual bytes
        flags_reserved = (self.flags << 13) & 0xE000
        checksum_sum += (flags_reserved >> 8) & 0xFF
        checksum_sum += flags_reserved & 0xFF
        
        # Add payload bytes
        for byte in self.payload:
            checksum_sum += byte
        
        # Add carry bits (before adding checksum)
        while checksum_sum >> 16:
            checksum_sum = (checksum_sum & 0xFFFF) + (checksum_sum >> 16)
        
        # Now add the checksum field (treat as 16-bit value)
        # The sum + checksum should equal 0xFFFF after ones' complement
        total = checksum_sum + self.checksum
        
        # Add carry bits
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
            
        # Should equal 0xFFFF if checksum is valid
        return total == 0xFFFF
        
    def encode(self):
        """
        Encode segment into bytes for transmission.
        Returns the complete segment as bytes.
        """
        self.compute_checksum()
        
        # Pack header: sequence number (2 bytes), reserved+flags (2 bytes), checksum (2 bytes)
        # Network byte order (big-endian)
        header = struct.pack('>H', self.seq_num)  # Bytes 0-1: Sequence number
        flags_reserved = struct.pack('>H', (self.flags << 13))  # Bytes 2-3: Flags in bits 13-15
        checksum = struct.pack('>H', self.checksum)  # Bytes 4-5: Checksum
        
        return header + flags_reserved + checksum + self.payload
        
    @staticmethod
    def decode(data):
        """
        Decode bytes into a URP segment.
        Returns a URPSegment object or None if invalid.
        """
        if len(data) < HEADER_SIZE:
            return None
            
        try:
            # Extract header fields
            seq_num = struct.unpack('>H', data[0:2])[0]  # Bytes 0-1: Sequence number
            
            # Extract flags (bits 13-15 of the reserved+flags field)
            flags_reserved = struct.unpack('>H', data[2:4])[0]  # Bytes 2-3
            flags = (flags_reserved >> 13) & 0x07  # Extract upper 3 bits
            
            # Extract checksum
            checksum = struct.unpack('>H', data[4:6])[0]  # Bytes 4-5: Checksum
            
            # Extract payload
            payload = data[6:] if len(data) > HEADER_SIZE else b''
            
            segment = URPSegment(seq_num, flags, payload)
            segment.checksum = checksum
            
            return segment
        except:
            return None