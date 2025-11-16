from socket import *
from threading import Thread, Lock, RLock
import sys
import struct
import random
import time
import os
from urpsegment import URPSegment, HEADER_SIZE
from plc import PLC

# Constants
MSS = 1000  # Maximum segment size (payload)
MSL = 1.0  # Maximum segment lifetime in seconds

CLOSED = "CLOSED"
SYN_SENT = "SYN_SENT"
ESTABLISHED = "ESTABLISHED"
CLOSING = "CLOSING"
FIN_WAIT = "FIN_WAIT"

class URPSender:
    def __init__(self, sender_port, receiver_port, filename, max_win, rto, flp, rlp, fcp, rcp):
        """
        Args:
            sender_port: UDP port for sender
            receiver_port: UDP port for receiver
            filename: File to transfer
            max_win: Maximum window size in bytes
            rto: Retransmission timeout in milliseconds
            flp, rlp, fcp, rcp: PLC parameters
        """
        self.sender_port = sender_port
        self.receiver_port = receiver_port
        self.filename = filename
        self.max_win = max_win
        self.rto = rto / 1000.0
        
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', sender_port))
        self.socket.settimeout(0.1)
        
        self.plc = PLC(flp, rlp, fcp, rcp, self.log_segment)
        
        self.state = CLOSED
        self.isn = random.randint(0, 65535)  # Initial sequence number
        self.next_seq = self.isn + 1  # Next sequence number to send
        self.send_base = self.isn + 1  # Base of send window
        self.file_pointer = 0  # Position in file
        self.file_size = os.path.getsize(filename)
        
        # Sliding window.
        self.unacked_segments = []  # List of (seq_num, segment_data, payload_len, send_time)
        self.window_lock = RLock()
        
        self.timer_running = False
        self.timer_start_time = None
        self.timer_lock = Lock()
        
        # Fast retransmit.
        self.dup_ack_count = 0
        self.last_ack_num = None
        
        self.stats = {
            'original_data_sent': 0,
            'total_data_sent': 0,
            'original_segments_sent': 0,
            'total_segments_sent': 0,
            'timeout_retransmissions': 0,
            'fast_retransmissions': 0,
            'duplicate_acks_received': 0,
            'corrupted_acks_discarded': 0
        }
        
        self.log_file = open('sender_log.txt', 'w')
        self.start_time = None
        
    def log_segment(self, direction, status, time_ms, seg_type, seq_num, payload_len):
        self.log_file.write(f"{direction} {status} {time_ms:.2f} {seg_type} {seq_num} {payload_len}\n")
        self.log_file.flush()
        
    def get_elapsed_time(self):
        if self.start_time is None:
            return 0.0
        return (time.time() - self.start_time) * 1000.0
        
    def start_timer(self):
        with self.timer_lock:
            if not self.timer_running and len(self.unacked_segments) > 0:
                self.timer_running = True
                self.timer_start_time = time.time()
                
    def stop_timer(self):
        with self.timer_lock:
            self.timer_running = False
            self.timer_start_time = None
            
    def restart_timer(self):
        self.stop_timer()
        self.start_timer()
        
    def check_timer(self):
        with self.timer_lock:
            if not self.timer_running:
                return False
            if self.timer_start_time is None:
                return False
            elapsed = time.time() - self.timer_start_time
            return elapsed >= self.rto
            
    def get_available_window_space(self):
        sent_not_acked = sum(seg[2] for seg in self.unacked_segments)  # payload_len
        return self.max_win - sent_not_acked
        
    def send_segment(self, segment, is_retransmission=False):
        """
        Args:
            segment: URPSegment object
            is_retransmission: True if this is a retransmission
        """
        segment_data = segment.encode()
        seg_type = 'SYN' if segment.is_syn() else ('FIN' if segment.is_fin() else 'DATA')
        payload_len = len(segment.payload)
        
        # Track original statistics BEFORE processing through PLC.
        if not is_retransmission:
            self.stats['original_segments_sent'] += 1
            self.stats['original_data_sent'] += payload_len
        
        # Process through PLC.
        processed_data, was_dropped, was_corrupted = self.plc.process_outgoing(
            segment_data, seg_type, segment.seq_num, payload_len, self.get_elapsed_time()
        )
        
        if not was_dropped:
            self.socket.sendto(processed_data, ('127.0.0.1', self.receiver_port))

            self.stats['total_segments_sent'] += 1
            self.stats['total_data_sent'] += payload_len
            
                        
    def retransmit_oldest(self):
        with self.window_lock:
            if len(self.unacked_segments) == 0:
                return
            seq_num, segment_data, payload_len, _ = self.unacked_segments[0]
            self.unacked_segments[0] = (seq_num, segment_data, payload_len, time.time())

        segment = URPSegment.decode(segment_data)
        if segment is None:
            return

        seg_type = 'SYN' if segment.is_syn() else ('FIN' if segment.is_fin() else 'DATA')

        if self.check_timer():
            self.stats['timeout_retransmissions'] += 1
        else:
            self.stats['fast_retransmissions'] += 1

        processed_data, was_dropped, _ = self.plc.process_outgoing(
            segment_data, seg_type, seq_num, payload_len, self.get_elapsed_time()
        )

        if not was_dropped:
            self.socket.sendto(processed_data, ('127.0.0.1', self.receiver_port))
            self.stats['total_segments_sent'] += 1
            self.stats['total_data_sent'] += payload_len

        self.restart_timer()
        self.dup_ack_count = 0  

    @staticmethod
    def seq_gt(a, b):
        """Return True if a > b (mod 2^16)."""
        return ((a - b + 65536) % 65536) < 32768 and a != b

    @staticmethod
    def seq_ge(a, b):
        """Return True if a >= b (mod 2^16)."""
        return ((a - b + 65536) % 65536) < 32768
    
    @staticmethod
    def seq_lt(a, b):
        """Return True if a < b (mod 2^16)."""
        return ((b - a + 65536) % 65536) < 32768 and a != b
            
    def process_ack(self, segment):
        if not segment.is_ack():
            return False
            
        ack_num = segment.seq_num
        
        with self.window_lock:
            if len(self.unacked_segments) == 0:
                return True

            # Check if this ACK acknowledges new data.
            if len(self.unacked_segments) > 0:
                oldest_seq, _, oldest_payload_len, _ = self.unacked_segments[0]
                if ack_num == oldest_seq:
                    if self.last_ack_num != ack_num:
                        self.last_ack_num = ack_num
                        self.dup_ack_count = 1
                        self.stats['duplicate_acks_received'] += 1
                    else:
                        # Same duplicate ACK number.
                        self.dup_ack_count += 1
                        self.stats['duplicate_acks_received'] += 1
                    
                    # Fast retransmit on >=3 duplicate ACKs.
                    if self.dup_ack_count >= 3 and self.max_win > MSS:
                        try:
                            self.retransmit_oldest()
                        except Exception as e:
                            import traceback
                            traceback.print_exc()
                    return True
            
            # Check if ACK acknowledges any segments (ack_num >= send_base).
            if self.seq_ge(ack_num, self.send_base):
                removed_bytes = 0
                segments_removed = 0
                while len(self.unacked_segments) > 0:
                    seq_num, _, payload_len, _ = self.unacked_segments[0]
                    if self.seq_ge(ack_num, (seq_num + payload_len) % 65536):
                        self.unacked_segments.pop(0)
                        removed_bytes += payload_len
                        segments_removed += 1
                    else:
                        break

                if segments_removed > 0:
                    self.send_base = ack_num

                    if len(self.unacked_segments) > 0:
                        self.restart_timer()
                    else:
                        self.stop_timer()

                    self.dup_ack_count = 0
                    self.last_ack_num = ack_num
                    return True
                else:
                    # ACK doesn't acknowledge any segments (e.g., segment was corrupted).
                    if len(self.unacked_segments) > 0:
                        oldest_seq, _, oldest_payload_len, _ = self.unacked_segments[0]
                        if ack_num == oldest_seq:
                            if self.last_ack_num != ack_num:
                                self.last_ack_num = ack_num
                                self.dup_ack_count = 1
                                self.stats['duplicate_acks_received'] += 1
                            else:
                                self.dup_ack_count += 1
                                self.stats['duplicate_acks_received'] += 1
                            
                            # Fast retransmit on >=3 duplicate ACKs.
                            if self.dup_ack_count >= 3 and self.max_win > MSS:
                                self.retransmit_oldest()
                            return True

            # Check if ACK is for an unacked segment (duplicate ACK pattern).
            if len(self.unacked_segments) > 0:
                oldest_seq, _, oldest_payload_len, _ = self.unacked_segments[0]
                if ack_num == oldest_seq:
                    if self.last_ack_num != ack_num:
                        self.last_ack_num = ack_num
                        self.dup_ack_count = 1
                        self.stats['duplicate_acks_received'] += 1
                    else:
                        self.dup_ack_count += 1
                        self.stats['duplicate_acks_received'] += 1
                    
                    # Fast retransmit on >=3 duplicate ACKs.
                    if self.dup_ack_count >= 3 and self.max_win > MSS:
                        self.retransmit_oldest()
                    return True
                    
            if self.seq_lt(ack_num, self.send_base):
                return True
            
            #duplicate ACK.
            if ack_num == self.send_base and len(self.unacked_segments) > 0:
                oldest_seq, _, _, _ = self.unacked_segments[0]
                if oldest_seq != ack_num:
                    return True

            if self.last_ack_num is None:
                self.last_ack_num = ack_num
            return True
        
    def connection_setup(self):
        self.state = SYN_SENT
        self.start_time = time.time()
        
        syn_segment = URPSegment(self.isn, 0, b'')
        syn_segment.set_flag('SYN')
        
        segment_data = syn_segment.encode()
        with self.window_lock:
            self.unacked_segments.append((
                self.isn,
                segment_data,
                0,
                time.time()
            ))
            self.start_timer()
        
        self.send_segment(syn_segment, is_retransmission=False)
        
        while self.state == SYN_SENT:
            try:
                self.socket.settimeout(0.01)
                data, addr = self.socket.recvfrom(1024)
                
                temp_segment = URPSegment.decode(data)
                ack_seq_num = temp_segment.seq_num if temp_segment else 0
                
                ack_segment_raw, was_dropped, was_corrupted = self.plc.process_incoming(
                    data, 'ACK', ack_seq_num, 0, self.get_elapsed_time()
                )
                
                if was_dropped:
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                ack_segment = URPSegment.decode(ack_segment_raw)
                if ack_segment is None:
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                if not ack_segment.verify_checksum():
                    self.stats['corrupted_acks_discarded'] += 1
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                if ack_segment.is_ack() and ack_segment.seq_num == self.isn + 1:
                    self.state = ESTABLISHED
                    self.send_base = self.isn + 1
                    self.stop_timer()
                    with self.window_lock:
                        if len(self.unacked_segments) > 0:
                            self.unacked_segments.pop(0)
                    break
                    
            except timeout:
                if self.check_timer():
                    self.retransmit_oldest()
                continue
                
    def transfer_data(self):
        file = open(self.filename, 'rb')
        
        while self.file_pointer < self.file_size or len(self.unacked_segments) > 0:
            segments_sent_this_iteration = 0
            
            # Send as many segments as window allows (for sliding window).
            while self.file_pointer < self.file_size:
                available = self.get_available_window_space()
                
                # break if window is full to check for ACKs.
                if self.max_win > MSS and available < MSS:
                    break
                
                if available >= MSS and self.file_pointer < self.file_size:
                    read_size = min(MSS, self.file_size - self.file_pointer)
                    data = file.read(read_size)
                
                if len(data) > 0:
                    # Create DATA segment.
                    current_seq = self.next_seq
                    current_payload_len = len(data)
                    data_segment = URPSegment(current_seq, 0, data)
                    segment_data = data_segment.encode()
                    
                    # Track segment BEFORE sending so we can retransmit even if dropped.
                    with self.window_lock:
                        already_tracked = False
                        for seq_num, _, _, _ in self.unacked_segments:
                            if seq_num == current_seq:
                                already_tracked = True
                                break
                        
                        if not already_tracked:
                            self.unacked_segments.append((
                                current_seq,
                                segment_data,
                                current_payload_len,
                                time.time()
                            ))
                            if len(self.unacked_segments) == 1:
                                self.start_timer()
                    
                    self.send_segment(data_segment)
                    
                    if self.max_win > MSS:
                        self.next_seq = (self.next_seq + current_payload_len) % 65536
                        self.file_pointer += current_payload_len
                    
                    # stop-and-wait mode wait for ACK before continuing.
                    if self.max_win == MSS:
                        # Wait for ACK of this segment.
                        while len(self.unacked_segments) > 0:
                            try:
                                self.socket.settimeout(0.01)
                                data, addr = self.socket.recvfrom(1024)
                                
                                temp_segment = URPSegment.decode(data)
                                ack_seq_num = temp_segment.seq_num if temp_segment else 0
                                
                                ack_segment_raw, was_dropped, was_corrupted = self.plc.process_incoming(
                                    data, 'ACK', ack_seq_num, 0, self.get_elapsed_time()
                                )
                                
                                if was_dropped:
                                    if self.check_timer():
                                        self.retransmit_oldest()
                                    continue
                                    
                                # Decode and verify
                                ack_segment = URPSegment.decode(ack_segment_raw)
                                if ack_segment is None:
                                    if self.check_timer():
                                        self.retransmit_oldest()
                                    continue
                                    
                                if not ack_segment.verify_checksum():
                                    self.stats['corrupted_acks_discarded'] += 1
                                    if self.check_timer():
                                        self.retransmit_oldest()
                                    continue
                                    
                                # Process ACK
                                ack_processed = self.process_ack(ack_segment)

                                # Check unacked_segments with lock for thread safety
                                with self.window_lock:
                                    if len(self.unacked_segments) == 0:
                                        self.next_seq = (self.next_seq + current_payload_len) % 65536
                                        self.file_pointer += current_payload_len
                                        break
                                    
                                if self.check_timer():
                                    self.retransmit_oldest()
                                    
                            except timeout:
                                if self.check_timer():
                                    self.retransmit_oldest()
                                continue
                        continue
                    
            
            # Check for incoming ACKs (for sliding window mode)
            if self.max_win > MSS:
                consecutive_timeouts = 0
                max_consecutive_timeouts = 1000  # Prevent infinite loop
                while True:
                    available = self.get_available_window_space()

                    if available >= MSS and self.file_pointer < self.file_size:
                        break
                    
                    with self.window_lock:
                        if len(self.unacked_segments) == 0:
                            break
                    
                    if self.check_timer():
                        self.retransmit_oldest()
                        consecutive_timeouts = 0 
                    
                    try:
                        self.socket.settimeout(0.01)
                        data, addr = self.socket.recvfrom(1024)
                        
                        temp_segment = URPSegment.decode(data)
                        ack_seq_num = temp_segment.seq_num if temp_segment else 0
                        
                        ack_segment_raw, was_dropped, was_corrupted = self.plc.process_incoming(
                            data, 'ACK', ack_seq_num, 0, self.get_elapsed_time()
                        )
                        
                        if was_dropped:
                            if self.check_timer():
                                self.retransmit_oldest()
                            continue
                            
                        ack_segment = URPSegment.decode(ack_segment_raw)
                        if ack_segment is None:
                            if self.check_timer():
                                self.retransmit_oldest()
                            continue
                            
                        if not ack_segment.verify_checksum():
                            self.stats['corrupted_acks_discarded'] += 1
                            if self.check_timer():
                                self.retransmit_oldest()
                            continue
                            
                        self.process_ack(ack_segment)
                        consecutive_timeouts = 0
                        
                        # After processing ACK, check if we should continue or break
                        available = self.get_available_window_space()
                        if available >= MSS and self.file_pointer < self.file_size:
                            break
                            
                    except timeout:
                        # No ACK received
                        consecutive_timeouts += 1
                        if consecutive_timeouts >= max_consecutive_timeouts:
                            break
                        continue
                    except Exception as e:
                        break
                
        file.close()
        
        while len(self.unacked_segments) > 0:
            try:
                self.socket.settimeout(0.01)
                data, addr = self.socket.recvfrom(1024)
                
                temp_segment = URPSegment.decode(data)
                ack_seq_num = temp_segment.seq_num if temp_segment else 0
                
                ack_segment_raw, was_dropped, was_corrupted = self.plc.process_incoming(
                    data, 'ACK', ack_seq_num, 0, self.get_elapsed_time()
                )
                
                if was_dropped:
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                ack_segment = URPSegment.decode(ack_segment_raw)
                if ack_segment is None:
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                if not ack_segment.verify_checksum():
                    self.stats['corrupted_acks_discarded'] += 1
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                self.process_ack(ack_segment)
                
            except timeout:
                if self.check_timer():
                    self.retransmit_oldest()
                continue
                
        self.state = CLOSING
        
    def connection_teardown(self):
        """
        Perform connection teardown: send FIN, wait for ACK.
        Implements state transition through CLOSING and FIN_WAIT.
        """
        self.state = FIN_WAIT
        
        fin_seq = self.next_seq
        fin_segment = URPSegment(fin_seq, 0, b'')
        fin_segment.set_flag('FIN')
        
        segment_data = fin_segment.encode()
        with self.window_lock:
            self.unacked_segments.append((
                fin_seq,
                segment_data,
                0,
                time.time()
            ))
            if len(self.unacked_segments) == 1:
                self.start_timer()
        
        self.send_segment(fin_segment, is_retransmission=False)
        
        while self.state == FIN_WAIT:
            try:
                self.socket.settimeout(0.01)
                data, addr = self.socket.recvfrom(1024)
                
                temp_segment = URPSegment.decode(data)
                ack_seq_num = temp_segment.seq_num if temp_segment else 0
                
                ack_segment_raw, was_dropped, was_corrupted = self.plc.process_incoming(
                    data, 'ACK', ack_seq_num, 0, self.get_elapsed_time()
                )
                
                if was_dropped:
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                ack_segment = URPSegment.decode(ack_segment_raw)
                if ack_segment is None:
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                if not ack_segment.verify_checksum():
                    self.stats['corrupted_acks_discarded'] += 1
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                expected_ack = (fin_seq + 1) % 65536
                if ack_segment.is_ack() and ack_segment.seq_num == expected_ack:
                    self.state = CLOSED
                    with self.window_lock:
                        if len(self.unacked_segments) > 0:
                            self.unacked_segments.pop(0)
                    break
                    
            except timeout:
                if self.check_timer():
                    self.retransmit_oldest()
                continue
                
    def run(self):
        try:
            self.connection_setup()
            self.transfer_data()
            self.connection_teardown()
        except Exception as e:
            print(f"Connection reset: {e}")
            return
            
        self.write_statistics()
        self.log_file.close()
        self.socket.close()
        
    def write_statistics(self):
        """Write statistics to log file."""
        self.log_file.write(f"\nOriginal data sent: {self.stats['original_data_sent']}\n")
        self.log_file.write(f"Total data sent: {self.stats['total_data_sent']}\n")
        self.log_file.write(f"Original segments sent: {self.stats['original_segments_sent']}\n")
        self.log_file.write(f"Total segments sent: {self.stats['total_segments_sent']}\n")
        self.log_file.write(f"Timeout retransmissions: {self.stats['timeout_retransmissions']}\n")
        self.log_file.write(f"Fast retransmissions: {self.stats['fast_retransmissions']}\n")
        self.log_file.write(f"Duplicate acks received: {self.stats['duplicate_acks_received']}\n")
        self.log_file.write(f"Corrupted acks discarded: {self.stats['corrupted_acks_discarded']}\n")
        self.log_file.write(f"PLC forward segments dropped: {self.plc.stats['forward_dropped']}\n")
        self.log_file.write(f"PLC forward segments corrupted: {self.plc.stats['forward_corrupted']}\n")
        self.log_file.write(f"PLC reverse segments dropped: {self.plc.stats['reverse_dropped']}\n")
        self.log_file.write(f"PLC reverse segments corrupted: {self.plc.stats['reverse_corrupted']}\n")

def main():
    if len(sys.argv) != 10:
        print("\n===== Error usage, python3 sender.py sender_port receiver_port txt_file_to_send max_win rto flp rlp fcp rcp ======\n")
        sys.exit(1)
        
    sender_port = int(sys.argv[1])
    receiver_port = int(sys.argv[2])
    filename = sys.argv[3]
    max_win = int(sys.argv[4])
    rto = int(sys.argv[5])
    flp = float(sys.argv[6])
    rlp = float(sys.argv[7])
    fcp = float(sys.argv[8])
    rcp = float(sys.argv[9])
    
    sender = URPSender(sender_port, receiver_port, filename, max_win, rto, flp, rlp, fcp, rcp)
    sender.run()

if __name__ == "__main__":
    main()
