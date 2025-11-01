import random

class PLC:
    """
    Packet Loss and Corruption module.
    Emulates unreliable channel behavior by dropping and corrupting segments
    according to specified probabilities.
    """
    def __init__(self, flp, rlp, fcp, rcp, log_function):
        """
        Initialize PLC module.
        
        Args:
            flp: Forward loss probability (DATA, SYN, FIN)
            rlp: Reverse loss probability (ACK)
            fcp: Forward corruption probability
            rcp: Reverse corruption probability
            log_function: Function to call for logging
        """
        self.flp = flp
        self.rlp = rlp
        self.fcp = fcp
        self.rcp = rcp
        self.log_function = log_function
        self.stats = {
            'forward_dropped': 0,
            'forward_corrupted': 0,
            'reverse_dropped': 0,
            'reverse_corrupted': 0
        }
        random.seed()  # Use system time for seed
        
    def process_outgoing(self, segment_data, segment_type, seq_num, payload_len, time_ms):
        """
        Process outgoing segment (DATA, SYN, FIN).
        May drop or corrupt the segment based on probabilities.
        
        Returns: (segment_data or None, was_dropped, was_corrupted)
        """
        # Check for loss
        if random.random() < self.flp:
            self.stats['forward_dropped'] += 1
            self.log_function('snd', 'drp', time_ms, segment_type, seq_num, payload_len)
            return None, True, False
            
        # Check for corruption
        was_corrupted = False
        if random.random() < self.fcp:
            # Corrupt a random byte (excluding first 4 header bytes)
            if len(segment_data) > 4:
                corrupt_pos = random.randint(4, len(segment_data) - 1)
                byte_val = segment_data[corrupt_pos]
                bit_pos = random.randint(0, 7)
                byte_val ^= (1 << bit_pos)
                segment_data = segment_data[:corrupt_pos] + bytes([byte_val]) + segment_data[corrupt_pos+1:]
                was_corrupted = True
                self.stats['forward_corrupted'] += 1
                
        status = 'cor' if was_corrupted else 'ok'
        self.log_function('snd', status, time_ms, segment_type, seq_num, payload_len)
        
        return segment_data, False, was_corrupted
        
    def process_incoming(self, segment_data, segment_type, seq_num, payload_len, time_ms):
        """
        Process incoming segment (ACK).
        May drop or corrupt the segment based on probabilities.
        
        Returns: (segment_data or None, was_dropped, was_corrupted)
        """
        # Check for loss
        if random.random() < self.rlp:
            self.stats['reverse_dropped'] += 1
            self.log_function('rcv', 'drp', time_ms, segment_type, seq_num, payload_len)
            return None, True, False
            
        # Check for corruption
        was_corrupted = False
        if random.random() < self.rcp:
            # Corrupt a random byte (excluding first 4 header bytes)
            if len(segment_data) > 4:
                corrupt_pos = random.randint(4, len(segment_data) - 1)
                byte_val = segment_data[corrupt_pos]
                bit_pos = random.randint(0, 7)
                byte_val ^= (1 << bit_pos)
                segment_data = segment_data[:corrupt_pos] + bytes([byte_val]) + segment_data[corrupt_pos+1:]
                was_corrupted = True
                self.stats['reverse_corrupted'] += 1
                
        status = 'cor' if was_corrupted else 'ok'
        self.log_function('rcv', status, time_ms, segment_type, seq_num, payload_len)
        
        return segment_data, False, was_corrupted