"""
URP Sender Implementation
Usage: python3 sender.py sender_port receiver_port txt_file_to_send max_win rto flp rlp fcp rcp
"""
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
        self.sender_port = sender_port
        self.receiver_port = receiver_port
        self.filename = filename
        self.max_win = max_win
        self.rto = rto / 1000.0
        
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', sender_port))
        self.socket.settimeout(0.1)
        
        self.plc = PLC(flp, rlp, fcp, rcp, self.log_seg)
        
        self.state = CLOSED
        self.isn = random.randint(0, 65535)  # Initial sequence number
        self.next_seq = self.isn + 1  # Next sequence number to send
        self.send_base = self.isn + 1
        self.file_ptr = 0  # Position in file
        self.file_size = os.path.getsize(filename)
        
        # Sliding window.
        self.unackd_segs = []  # List of (seq_num, seg_data, payload_len, send_time)
        self.win_lock = RLock()
        
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
        
    def log_seg(self, direction, status, time_ms, seg_type, seq_num, payload_len):
        """Log a segment event to the log file."""
        self.log_file.write(f"{direction} {status} {time_ms:.2f} {seg_type} {seq_num} {payload_len}\n")
        self.log_file.flush()
        
    def get_time_elapsed(self):
        if self.start_time is None:
            return 0.0
        return (time.time() - self.start_time) * 1000.0
        
    def start_timer(self):
        with self.timer_lock:
            if not self.timer_running and len(self.unackd_segs) > 0:
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
        """Check if timer expired."""
        with self.timer_lock:
            if not self.timer_running:
                return False
            if self.timer_start_time is None:
                return False
            elapsed = time.time() - self.timer_start_time
            return elapsed >= self.rto
    
    def handle_dropped_seg(self):
        """Handle dropped segment retransmit if timer expired."""
        if self.check_timer():
            self.retransmit_oldest()
    
    def handle_invalid_seg(self):
        """Handle invalid segment retransmit if timer expired."""
        if self.check_timer():
            self.retransmit_oldest()
    
    def handle_corrupt_ack(self):
        """Handle corrupted ACK, update stats and retransmit if timer expired."""
        self.stats['corrupted_acks_discarded'] += 1
        if self.check_timer():
            self.retransmit_oldest()
            
    def get_avail_win_space(self):
        """Check how much space available in send window."""
        sent_not_acked = sum(seg[2] for seg in self.unackd_segs)  # payload_len
        return self.max_win - sent_not_acked
        
    def send_seg(self, segment, is_retrans=False):
        """Send a segment through the PLC and socket."""
        seg_data = segment.encode()
        seg_type = 'SYN' if segment.is_syn() else ('FIN' if segment.is_fin() else 'DATA')
        payload_len = len(segment.payload)

        if not is_retrans:
            self.stats['original_segments_sent'] += 1
            self.stats['original_data_sent'] += payload_len
        
        proc_data, was_drop, was_corr = self.plc.proc_out(
            seg_data, seg_type, segment.seq_num, payload_len, self.get_time_elapsed()
        )
        
        if not was_drop:
            self.socket.sendto(proc_data, ('127.0.0.1', self.receiver_port))

            self.stats['total_segments_sent'] += 1
            self.stats['total_data_sent'] += payload_len
            
                        
    def retransmit_oldest(self):
        """Retransmit oldest unacked segment."""
        with self.win_lock:
            if len(self.unackd_segs) == 0:
                return
            seq_num, seg_data, payload_len, _ = self.unackd_segs[0]
            self.unackd_segs[0] = (seq_num, seg_data, payload_len, time.time())

        seg = URPSegment.decode(seg_data)
        if seg is None:
            return

        seg_type = 'SYN' if seg.is_syn() else ('FIN' if seg.is_fin() else 'DATA')

        if self.check_timer():
            self.stats['timeout_retransmissions'] += 1
        else:
            self.stats['fast_retransmissions'] += 1

        proc_data, was_drop, _ = self.plc.proc_out(
            seg_data, seg_type, seq_num, payload_len, self.get_time_elapsed()
        )

        if not was_drop:
            self.socket.sendto(proc_data, ('127.0.0.1', self.receiver_port))
            self.stats['total_segments_sent'] += 1
            self.stats['total_data_sent'] += payload_len

        self.restart_timer()
        self.dup_ack_count = 0  

    @staticmethod
    def seq_gt(a, b):
        return ((a - b + 65536) % 65536) < 32768 and a != b

    @staticmethod
    def seq_ge(a, b):
        return ((a - b + 65536) % 65536) < 32768
    
    @staticmethod
    def seq_lt(a, b):
        return ((b - a + 65536) % 65536) < 32768 and a != b
            
    def process_ack(self, seg):
        """
        Process received ACK segment.
        """
        if not seg.is_ack():
            return False
            
        ack_num = seg.seq_num
        
        with self.win_lock:
            if len(self.unackd_segs) == 0:
                return True

            if len(self.unackd_segs) > 0:
                oldest_seq, _, oldest_payload_len, _ = self.unackd_segs[0]
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
                        try:
                            self.retransmit_oldest()
                        except Exception as e:
                            import traceback
                            traceback.print_exc()
                    return True

            if self.seq_ge(ack_num, self.send_base):
                rem_bytes = 0
                segs_remvd = 0
                while len(self.unackd_segs) > 0:
                    seq_num, _, payload_len, _ = self.unackd_segs[0]
                    if self.seq_ge(ack_num, (seq_num + payload_len) % 65536):
                        self.unackd_segs.pop(0)
                        rem_bytes += payload_len
                        segs_remvd += 1
                    else:
                        break

                if segs_remvd > 0:
                    self.send_base = ack_num

                    if len(self.unackd_segs) > 0:
                        self.restart_timer()
                    else:
                        self.stop_timer()

                    self.dup_ack_count = 0
                    self.last_ack_num = ack_num
                    return True
                else:
                    # ACK doesn't acknowledge any segments
                    if len(self.unackd_segs) > 0:
                        oldest_seq, _, oldest_payload_len, _ = self.unackd_segs[0]
                        if ack_num == oldest_seq:
                            if self.last_ack_num != ack_num:
                                self.last_ack_num = ack_num
                                self.dup_ack_count = 1
                                self.stats['duplicate_acks_received'] += 1
                            else:
                                self.dup_ack_count += 1
                                self.stats['duplicate_acks_received'] += 1
                            
                            # Fast retransmit.
                            if self.dup_ack_count >= 3 and self.max_win > MSS:
                                self.retransmit_oldest()
                            return True

            # Check if ACK is for an unacked segment.
            if len(self.unackd_segs) > 0:
                oldest_seq, _, oldest_payload_len, _ = self.unackd_segs[0]
                if ack_num == oldest_seq:
                    if self.last_ack_num != ack_num:
                        self.last_ack_num = ack_num
                        self.dup_ack_count = 1
                        self.stats['duplicate_acks_received'] += 1
                    else:
                        self.dup_ack_count += 1
                        self.stats['duplicate_acks_received'] += 1
                    
                    if self.dup_ack_count >= 3 and self.max_win > MSS:
                        self.retransmit_oldest()
                    return True
                    
            if self.seq_lt(ack_num, self.send_base):
                return True
            
            if ack_num == self.send_base and len(self.unackd_segs) > 0:
                oldest_seq, _, _, _ = self.unackd_segs[0]
                if oldest_seq != ack_num:
                    return True

            if self.last_ack_num is None:
                self.last_ack_num = ack_num
            return True
        
    def conn_setup(self):
        self.state = SYN_SENT
        self.start_time = time.time()
        
        syn_seg = URPSegment(self.isn, 0, b'')
        syn_seg.set_flag('SYN')
        
        seg_data = syn_seg.encode()
        with self.win_lock:
            self.unackd_segs.append((
                self.isn,
                seg_data,
                0,
                time.time()
            ))
            self.start_timer()
        
        self.send_seg(syn_seg, is_retrans=False)
        
        while self.state == SYN_SENT:
            try:
                self.socket.settimeout(0.01)
                data, addr = self.socket.recvfrom(1024)
                
                temp_seg = URPSegment.decode(data)
                ack_seq_num = temp_seg.seq_num if temp_seg else 0
                
                ack_seg_raw, was_drop, was_corr = self.plc.proc_inc(
                    data, 'ACK', ack_seq_num, 0, self.get_time_elapsed()
                )
                
                if was_drop:
                    self.handle_dropped_seg()
                    continue
                    
                ack_seg = URPSegment.decode(ack_seg_raw)
                if ack_seg is None:
                    self.handle_invalid_seg()
                    continue
                    
                if not ack_seg.check_checksum():
                    self.handle_corrupt_ack()
                    continue
                    
                if ack_seg.is_ack() and ack_seg.seq_num == self.isn + 1:
                    self.state = ESTABLISHED
                    self.send_base = self.isn + 1
                    self.stop_timer()
                    with self.win_lock:
                        if len(self.unackd_segs) > 0:
                            self.unackd_segs.pop(0)
                    break
                    
            except timeout:
                self.handle_dropped_seg()
                continue
                
    def trans_data(self):
        """Transfer file data using stop-and wait or sliding window."""
        file = open(self.filename, 'rb')
        
        while self.file_ptr < self.file_size or len(self.unackd_segs) > 0:
            segs_sent_in_iter = 0
            
            # Send as many segments as window  allows.
            while self.file_ptr < self.file_size:
                available = self.get_avail_win_space()
                
                if self.max_win > MSS and available < MSS:
                    break
                
                if available >= MSS and self.file_ptr < self.file_size:
                    read_size = min(MSS, self.file_size - self.file_ptr)
                    data = file.read(read_size)
                
                if len(data) > 0:
                    current_seq = self.next_seq
                    current_payload_len = len(data)
                    data_seg = URPSegment(current_seq, 0, data)
                    seg_data = data_seg.encode()
                    
                    with self.win_lock:
                        alr_tracked = False
                        for seq_num, _, _, _ in self.unackd_segs:
                            if seq_num == current_seq:
                                alr_tracked = True
                                break
                        
                        if not alr_tracked:
                            self.unackd_segs.append((
                                current_seq,
                                seg_data,
                                current_payload_len,
                                time.time()
                            ))
                            if len(self.unackd_segs) == 1:
                                self.start_timer()
                    
                    self.send_seg(data_seg)
                    
                    if self.max_win > MSS:
                        self.next_seq = (self.next_seq + current_payload_len) % 65536
                        self.file_ptr += current_payload_len
                    
                    # stop-and-wait mode.
                    if self.max_win == MSS:
                        while len(self.unackd_segs) > 0:
                            try:
                                self.socket.settimeout(0.01)
                                data, addr = self.socket.recvfrom(1024)
                                
                                temp_seg = URPSegment.decode(data)
                                ack_seq_num = temp_seg.seq_num if temp_seg else 0
                                
                                ack_seg_raw, was_drop, was_corr = self.plc.proc_inc(
                                    data, 'ACK', ack_seq_num, 0, self.get_time_elapsed()
                                )
                                
                                if was_drop:
                                    self.handle_dropped_seg()
                                    continue
                                    
                                ack_seg = URPSegment.decode(ack_seg_raw)
                                if ack_seg is None:
                                    self.handle_invalid_seg()
                                    continue
                                    
                                if not ack_seg.check_checksum():
                                    self.handle_corrupt_ack()
                                    continue
                                    
                                ack_processed = self.process_ack(ack_seg)

                                with self.win_lock:
                                    if len(self.unackd_segs) == 0:
                                        self.next_seq = (self.next_seq + current_payload_len) % 65536
                                        self.file_ptr += current_payload_len
                                        break
                                    
                                self.handle_dropped_seg()
                                    
                            except timeout:
                                self.handle_dropped_seg()
                                continue
                        continue
                    
            
            # sliding window mode.
            if self.max_win > MSS:
                consec_timeouts = 0
                max_consec_timeouts = 1000  # Prevent infinite loop
                while True:
                    available = self.get_avail_win_space()

                    if available >= MSS and self.file_ptr < self.file_size:
                        break
                    
                    with self.win_lock:
                        if len(self.unackd_segs) == 0:
                            break
                    
                    if self.check_timer():
                        self.retransmit_oldest()
                        consec_timeouts = 0 
                    
                    try:
                        self.socket.settimeout(0.01)
                        data, addr = self.socket.recvfrom(1024)
                        
                        temp_seg = URPSegment.decode(data)
                        ack_seq_num = temp_seg.seq_num if temp_seg else 0
                        
                        ack_seg_raw, was_drop, was_corr = self.plc.proc_inc(
                            data, 'ACK', ack_seq_num, 0, self.get_time_elapsed()
                        )
                        
                        if was_drop:
                            self.handle_dropped_seg()
                            continue
                            
                        ack_seg = URPSegment.decode(ack_seg_raw)
                        if ack_seg is None:
                            self.handle_invalid_seg()
                            continue
                            
                        if not ack_seg.check_checksum():
                            self.handle_corrupt_ack()
                            continue
                            
                        self.process_ack(ack_seg)
                        consec_timeouts = 0
                        
                        available = self.get_avail_win_space()
                        if available >= MSS and self.file_ptr < self.file_size:
                            break
                            
                    except timeout:
                        self.handle_dropped_seg()
                        consec_timeouts += 1
                        if consec_timeouts >= max_consec_timeouts:
                            break
                        continue
                    except Exception as e:
                        break
                
        file.close()
        
        while len(self.unackd_segs) > 0:
            try:
                self.socket.settimeout(0.01)
                data, addr = self.socket.recvfrom(1024)
                
                temp_seg = URPSegment.decode(data)
                ack_seq_num = temp_seg.seq_num if temp_seg else 0
                
                ack_seg_raw, was_drop, was_corr = self.plc.proc_inc(
                    data, 'ACK', ack_seq_num, 0, self.get_time_elapsed()
                )
                
                if was_drop:
                    self.handle_dropped_seg()
                    continue
                    
                ack_seg = URPSegment.decode(ack_seg_raw)
                if ack_seg is None:
                    self.handle_invalid_seg()
                    continue
                    
                if not ack_seg.check_checksum():
                    self.handle_corrupt_ack()
                    continue
                    
                self.process_ack(ack_seg)
                
            except timeout:
                self.handle_dropped_seg()
                continue
                
        self.state = CLOSING
        
    def connection_end(self):
        self.state = FIN_WAIT
        
        fin_seq = self.next_seq
        fin_seg = URPSegment(fin_seq, 0, b'')
        fin_seg.set_flag('FIN')
        
        seg_data = fin_seg.encode()
        with self.win_lock:
            self.unackd_segs.append((
                fin_seq,
                seg_data,
                0,
                time.time()
            ))
            if len(self.unackd_segs) == 1:
                self.start_timer()
        
        self.send_seg(fin_seg, is_retrans=False)
        
        while self.state == FIN_WAIT:
            try:
                self.socket.settimeout(0.01)
                data, addr = self.socket.recvfrom(1024)
                
                temp_seg = URPSegment.decode(data)
                ack_seq_num = temp_seg.seq_num if temp_seg else 0
                
                ack_seg_raw, was_drop, was_corr = self.plc.proc_inc(
                    data, 'ACK', ack_seq_num, 0, self.get_time_elapsed()
                )
                
                if was_drop:
                    self.handle_dropped_seg()
                    continue
                    
                ack_seg = URPSegment.decode(ack_seg_raw)
                if ack_seg is None:
                    self.handle_invalid_seg()
                    continue
                    
                if not ack_seg.check_checksum():
                    self.handle_corrupt_ack()
                    continue
                    
                expected_ack = (fin_seq + 1) % 65536
                if ack_seg.is_ack() and ack_seg.seq_num == expected_ack:
                    self.state = CLOSED
                    with self.win_lock:
                        if len(self.unackd_segs) > 0:
                            self.unackd_segs.pop(0)
                    break
                    
            except timeout:
                self.handle_dropped_seg()
                continue
                
    def run(self):
        try:
            self.conn_setup()
            self.trans_data()
            self.connection_end()
        except Exception as e:
            print(f"Connection reset: {e}")
            return
            
        self.write_stats()
        self.log_file.close()
        self.socket.close()
        
    def write_stats(self):
        """Write stats to log file."""
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
