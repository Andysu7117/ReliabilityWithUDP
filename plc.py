import random

class PLC:
    """Packet Loss and Corruption module."""
    def __init__(self, flp, rlp, fcp, rcp, log_function):
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
        random.seed()
        
    def proc_out(self, seg_data, segment_type, seq_num, payload_len, time_ms):
        # Check loss
        if random.random() < self.flp:
            self.stats['forward_dropped'] += 1
            self.log_function('snd', 'drp', time_ms, segment_type, seq_num, payload_len)
            return None, True, False
            
        # Check corruption
        was_corr = False
        if random.random() < self.fcp:
            if len(seg_data) > 4:
                corrupt_pos = random.randint(4, len(seg_data) - 1)
                byte_val = seg_data[corrupt_pos]
                bit_pos = random.randint(0, 7)
                byte_val ^= (1 << bit_pos)
                seg_data = seg_data[:corrupt_pos] + bytes([byte_val]) + seg_data[corrupt_pos+1:]
                was_corr = True
                self.stats['forward_corrupted'] += 1
                
        status = 'cor' if was_corr else 'ok'
        self.log_function('snd', status, time_ms, segment_type, seq_num, payload_len)
        
        return seg_data, False, was_corr
        
    def proc_inc(self, seg_data, segment_type, seq_num, payload_len, time_ms):
        # Check loss
        if random.random() < self.rlp:
            self.stats['reverse_dropped'] += 1
            self.log_function('rcv', 'drp', time_ms, segment_type, seq_num, payload_len)
            return None, True, False
            
        # Check corruption
        was_corr = False
        if random.random() < self.rcp:
            if len(seg_data) > 4:
                corrupt_pos = random.randint(4, len(seg_data) - 1)
                byte_val = seg_data[corrupt_pos]
                bit_pos = random.randint(0, 7)
                byte_val ^= (1 << bit_pos)
                seg_data = seg_data[:corrupt_pos] + bytes([byte_val]) + seg_data[corrupt_pos+1:]
                was_corr = True
                self.stats['reverse_corrupted'] += 1
                
        status = 'cor' if was_corr else 'ok'
        self.log_function('rcv', status, time_ms, segment_type, seq_num, payload_len)
        
        return seg_data, False, was_corr