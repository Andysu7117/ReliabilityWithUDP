"""
URP Sender Implementation
Implements a reliable UDP-based transport protocol (URP) with:
- Connection setup (SYN/ACK handshake)
- Sliding window data transfer
- Connection teardown (FIN/ACK)
- Packet Loss and Corruption (PLC) emulation
- Comprehensive logging

Usage: python3 sender.py sender_port receiver_port txt_file_to_send max_win rto flp rlp fcp rcp
"""
from socket import *
from threading import Thread, Lock
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

# State constants for Sender
CLOSED = "CLOSED"
SYN_SENT = "SYN_SENT"
ESTABLISHED = "ESTABLISHED"
CLOSING = "CLOSING"
FIN_WAIT = "FIN_WAIT"

class URPSender:
    """
    Main URP Sender implementation.
    Manages connection lifecycle, sliding window, timers, and file transfer.
    """
    def __init__(self, sender_port, receiver_port, filename, max_win, rto, flp, rlp, fcp, rcp):
        """
        Initialize URP Sender.
        
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
        self.rto = rto / 1000.0  # Convert to seconds
        
        # Initialize UDP socket
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', sender_port))
        self.socket.settimeout(0.1)  # Small timeout for checking
        
        # Initialize PLC
        self.plc = PLC(flp, rlp, fcp, rcp, self.log_segment)
        
        # Protocol state
        self.state = CLOSED
        self.isn = random.randint(0, 65535)  # Initial sequence number
        self.next_seq = self.isn + 1  # Next sequence number to send
        self.send_base = self.isn + 1  # Base of send window
        self.file_pointer = 0  # Position in file
        self.file_size = os.path.getsize(filename)
        
        # Sliding window
        self.unacked_segments = []  # List of (seq_num, segment_data, payload_len, send_time)
        self.window_lock = Lock()
        
        # Timer
        self.timer_running = False
        self.timer_start_time = None
        self.timer_lock = Lock()
        
        # Fast retransmit
        self.dup_ack_count = 0
        self.last_ack_num = None
        
        # Statistics
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
        
        # Logging
        self.log_file = open('sender_log.txt', 'w')
        self.start_time = None
        
    def log_segment(self, direction, status, time_ms, seg_type, seq_num, payload_len):
        """
        Log a segment event to the log file.
        Called by PLC module and protocol logic.
        """
        self.log_file.write(f"{direction} {status} {time_ms:.2f} {seg_type} {seq_num} {payload_len}\n")
        self.log_file.flush()  # Real-time logging
        
    def get_elapsed_time(self):
        """Get elapsed time in milliseconds since start."""
        if self.start_time is None:
            return 0.0
        return (time.time() - self.start_time) * 1000.0
        
    def start_timer(self):
        """Start the retransmission timer."""
        with self.timer_lock:
            if not self.timer_running and len(self.unacked_segments) > 0:
                self.timer_running = True
                self.timer_start_time = time.time()
                
    def stop_timer(self):
        """Stop the retransmission timer."""
        with self.timer_lock:
            self.timer_running = False
            self.timer_start_time = None
            
    def restart_timer(self):
        """Restart the retransmission timer."""
        self.stop_timer()
        self.start_timer()
        
    def check_timer(self):
        """
        Check if timer has expired.
        Returns True if expired, False otherwise.
        """
        with self.timer_lock:
            if not self.timer_running:
                return False
            if self.timer_start_time is None:
                return False
            elapsed = time.time() - self.timer_start_time
            return elapsed >= self.rto
            
    def get_available_window_space(self):
        """
        Calculate available space in send window.
        Returns number of bytes available for new data.
        """
        sent_not_acked = sum(seg[2] for seg in self.unacked_segments)  # payload_len
        return self.max_win - sent_not_acked
        
    def send_segment(self, segment, is_retransmission=False):
        """
        Send a segment through the PLC and socket.
        
        Args:
            segment: URPSegment object
            is_retransmission: True if this is a retransmission
        """
        segment_data = segment.encode()
        seg_type = 'SYN' if segment.is_syn() else ('FIN' if segment.is_fin() else 'DATA')
        payload_len = len(segment.payload)
        
        # Track original statistics BEFORE processing through PLC
        # Original data sent should count all original segments, even if dropped
        if not is_retransmission:
            self.stats['original_segments_sent'] += 1
            self.stats['original_data_sent'] += payload_len
        
        # Process through PLC
        processed_data, was_dropped, was_corrupted = self.plc.process_outgoing(
            segment_data, seg_type, segment.seq_num, payload_len, self.get_elapsed_time()
        )
        
        if not was_dropped:
            # Send through socket
            self.socket.sendto(processed_data, ('127.0.0.1', self.receiver_port))
            
            # Track total statistics (only for segments that weren't dropped)
            self.stats['total_segments_sent'] += 1
            self.stats['total_data_sent'] += payload_len
            
            # If not a retransmission, add to unacked list
            # (For stop-and-wait DATA, SYN, and FIN, we already added them before sending)
            # Only add here for sliding window DATA segments
            if not is_retransmission and self.max_win > MSS:
                # For sliding window, add to unacked list here
                # For stop-and-wait DATA, SYN, and FIN, segment was already added before sending
                with self.window_lock:
                    self.unacked_segments.append((
                        segment.seq_num,
                        segment_data,
                        payload_len,
                        time.time()
                    ))
                    # Start timer if this is the oldest unacked segment
                    if len(self.unacked_segments) == 1:
                        self.start_timer()
                        
    def retransmit_oldest(self):
        """
        Retransmit the oldest unacknowledged segment.
        Called on timeout or fast retransmit.
        """
        # Extract segment info while holding lock
        with self.window_lock:
            if len(self.unacked_segments) == 0:
                return
                
            seq_num, segment_data, payload_len, send_time = self.unacked_segments[0]
            
        # Determine segment type (outside lock)
        segment = URPSegment.decode(segment_data)
        if segment is None:
            return
            
        seg_type = 'SYN' if segment.is_syn() else ('FIN' if segment.is_fin() else 'DATA')
        
        # Check if timeout or fast retransmit
        if self.check_timer():
            self.stats['timeout_retransmissions'] += 1
        else:
            self.stats['fast_retransmissions'] += 1
            
        # Retransmit
        processed_data, was_dropped, was_corrupted = self.plc.process_outgoing(
            segment_data, seg_type, seq_num, payload_len, self.get_elapsed_time()
        )
        
        if not was_dropped:
            self.socket.sendto(processed_data, ('127.0.0.1', self.receiver_port))
            self.stats['total_segments_sent'] += 1
            self.stats['total_data_sent'] += payload_len
            
        # Restart timer
        self.restart_timer()
        self.dup_ack_count = 0  # Reset duplicate ACK count
            
    def process_ack(self, segment):
        """
        Process a received ACK segment.
        Updates window, removes acknowledged segments, handles duplicates.
        Returns True if ACK was processed, False otherwise.
        """
        if not segment.is_ack():
            return False
            
        ack_num = segment.seq_num
        
        # Check if this acknowledges new data
        with self.window_lock:
            # Check if ACK acknowledges new data (handle sequence number wraparound)
            # For 16-bit sequence numbers, we need to handle wraparound
            # ACK is ahead if: ack_num > send_base (normal) OR wraparound occurred
            ack_ahead = False
            
            if ack_num > self.send_base:
                # Normal case: ACK is ahead
                ack_ahead = True
            elif ack_num < self.send_base:
                # Wraparound case: ACK wrapped around while send_base didn't
                # This happens when send_base is near 65535
                if self.send_base > 63000:  # Close to wraparound
                    ack_ahead = True
            
            if ack_ahead:
                # New ACK - slide window
                # Remove all segments with seq_num < ack_num
                removed_bytes = 0
                while len(self.unacked_segments) > 0:
                    seq_num, _, payload_len, _ = self.unacked_segments[0]
                    # Compare sequence numbers (handle wraparound)
                    # seq_num < ack_num in normal case, or if wraparound occurred
                    if seq_num < ack_num or (ack_num < seq_num and seq_num > 60000 and ack_num < 1000):
                        self.unacked_segments.pop(0)
                        removed_bytes += payload_len
                    else:
                        break

                self.send_base = ack_num
                
                # Restart timer if there are unacked segments
                if len(self.unacked_segments) > 0:
                    self.restart_timer()
                else:
                    self.stop_timer()
                    
                # Reset duplicate ACK count
                self.dup_ack_count = 0
                self.last_ack_num = ack_num
                return True
                
            elif self.last_ack_num is not None and ack_num == self.last_ack_num:
                # Duplicate ACK
                self.dup_ack_count += 1
                self.stats['duplicate_acks_received'] += 1
                
                # Fast retransmit on 3 duplicate ACKs (only in sliding window mode)
                if self.dup_ack_count == 3 and self.max_win > MSS:
                    self.retransmit_oldest()
                return True
                
            else:
                # Ignore old ACK or first ACK (last_ack_num is None)
                return True
                
        return False
        
    def connection_setup(self):
        """
        Perform connection setup: send SYN, wait for ACK.
        Implements state transition from CLOSED to ESTABLISHED.
        """
        self.state = SYN_SENT
        self.start_time = time.time()
        
        # Create SYN segment
        syn_segment = URPSegment(self.isn, 0, b'')
        syn_segment.set_flag('SYN')
        
        # Track SYN segment before sending so we can retransmit if dropped
        segment_data = syn_segment.encode()
        with self.window_lock:
            self.unacked_segments.append((
                self.isn,
                segment_data,
                0,  # SYN has no payload
                time.time()
            ))
            # Start timer
            self.start_timer()
        
        self.send_segment(syn_segment, is_retransmission=False)
        
        # Wait for ACK
        while self.state == SYN_SENT:
            try:
                self.socket.settimeout(0.01)
                data, addr = self.socket.recvfrom(1024)
                
                # Try to decode first to get sequence number for logging
                temp_segment = URPSegment.decode(data)
                ack_seq_num = temp_segment.seq_num if temp_segment else 0
                
                # Process through PLC
                ack_segment_raw, was_dropped, was_corrupted = self.plc.process_incoming(
                    data, 'ACK', ack_seq_num, 0, self.get_elapsed_time()
                )
                
                if was_dropped:
                    # Check for timeout
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                # Decode segment
                ack_segment = URPSegment.decode(ack_segment_raw)
                if ack_segment is None:
                    # Check for timeout
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                # Verify checksum
                if not ack_segment.verify_checksum():
                    self.stats['corrupted_acks_discarded'] += 1
                    # Check for timeout
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                # Check if ACK acknowledges SYN (ACK num should be ISN + 1)
                if ack_segment.is_ack() and ack_segment.seq_num == self.isn + 1:
                    self.state = ESTABLISHED
                    self.send_base = self.isn + 1
                    self.stop_timer()
                    # Remove SYN from unacked list
                    with self.window_lock:
                        if len(self.unacked_segments) > 0:
                            self.unacked_segments.pop(0)
                    break
                    
            except timeout:
                # Check for timeout
                if self.check_timer():
                    self.retransmit_oldest()
                continue
                
    def transfer_data(self):
        """
        Transfer file data using sliding window protocol.
        Operates in ESTABLISHED state.
        Supports both stop-and-wait (max_win = MSS) and sliding window.
        """
        file = open(self.filename, 'rb')
        
        while self.file_pointer < self.file_size:
            # In sliding window mode, try to send multiple segments before checking ACKs
            # In stop-and-wait mode, send one segment and wait for ACK
            segments_sent_this_iteration = 0
            
            # Send as many segments as window allows (for sliding window)
            while self.file_pointer < self.file_size:
                # Check if we can send more data
                available = self.get_available_window_space()
                
                # In sliding window mode, break if window is full to check for ACKs
                if self.max_win > MSS and available < MSS:
                    break
                
                if available >= MSS and self.file_pointer < self.file_size:
                    # Read data from file
                    read_size = min(MSS, self.file_size - self.file_pointer)
                    data = file.read(read_size)
                
                if len(data) > 0:
                    # Create DATA segment
                    current_seq = self.next_seq
                    current_payload_len = len(data)
                    data_segment = URPSegment(current_seq, 0, data)
                    
                    # In stop-and-wait mode, track segment before sending
                    # so we can retransmit even if dropped
                    if self.max_win == MSS:
                        # For stop-and-wait, ensure segment is tracked for retransmission
                        # even if dropped by PLC
                        segment_data = data_segment.encode()
                        with self.window_lock:
                            # Check if this segment is already tracked
                            if len(self.unacked_segments) == 0 or self.unacked_segments[0][0] != current_seq:
                                self.unacked_segments.append((
                                    current_seq,
                                    segment_data,
                                    current_payload_len,
                                    time.time()
                                ))
                                # Start timer if this is the oldest unacked segment
                                if len(self.unacked_segments) == 1:
                                    self.start_timer()
                    
                    self.send_segment(data_segment)
                    
                    # In sliding window mode, increment immediately after sending
                    # In stop-and-wait mode, we'll increment after ACK
                    if self.max_win > MSS:
                        self.next_seq = (self.next_seq + current_payload_len) % 65536
                        self.file_pointer += current_payload_len
                    
                    # In stop-and-wait mode (max_win == MSS), wait for ACK before continuing
                    if self.max_win == MSS:
                        # Wait for ACK of this segment
                        while len(self.unacked_segments) > 0:
                            try:
                                self.socket.settimeout(0.01)
                                data, addr = self.socket.recvfrom(1024)
                                
                                # Try to decode first to get sequence number for logging
                                temp_segment = URPSegment.decode(data)
                                ack_seq_num = temp_segment.seq_num if temp_segment else 0
                                
                                # Process through PLC
                                ack_segment_raw, was_dropped, was_corrupted = self.plc.process_incoming(
                                    data, 'ACK', ack_seq_num, 0, self.get_elapsed_time()
                                )
                                
                                if was_dropped:
                                    # Check for timeout while waiting
                                    if self.check_timer():
                                        self.retransmit_oldest()
                                    continue
                                    
                                # Decode and verify
                                ack_segment = URPSegment.decode(ack_segment_raw)
                                if ack_segment is None:
                                    # Check for timeout
                                    if self.check_timer():
                                        self.retransmit_oldest()
                                    continue
                                    
                                if not ack_segment.verify_checksum():
                                    self.stats['corrupted_acks_discarded'] += 1
                                    # Check for timeout
                                    if self.check_timer():
                                        self.retransmit_oldest()
                                    continue
                                    
                                # Process ACK
                                ack_processed = self.process_ack(ack_segment)
                                
                                # Break out of wait loop if segment was ACKed
                                # Check unacked_segments with lock for thread safety
                                with self.window_lock:
                                    if len(self.unacked_segments) == 0:
                                        # Segment was ACKed - now safe to increment
                                        self.next_seq = (self.next_seq + current_payload_len) % 65536
                                        self.file_pointer += current_payload_len
                                        break
                                    
                                # Check for timeout after processing ACK (in case it didn't acknowledge)
                                if self.check_timer():
                                    self.retransmit_oldest()
                                    
                            except timeout:
                                # Check for timer expiration
                                if self.check_timer():
                                    self.retransmit_oldest()
                                continue
                        # Continue to next iteration to send next segment
                        continue
                    
                # In sliding window mode, continue the inner loop to send more segments
                # The loop will naturally exit when available < MSS or file_pointer >= file_size
                # In stop-and-wait mode, we already broke out above
                # No need for explicit break here - let the loop condition handle it
            
            # Check for incoming ACKs (for sliding window mode)
            # Only check if we're in sliding window mode
            if self.max_win > MSS:
                try:
                    self.socket.settimeout(0.01)
                    data, addr = self.socket.recvfrom(1024)
                    
                    # Try to decode first to get sequence number for logging
                    temp_segment = URPSegment.decode(data)
                    ack_seq_num = temp_segment.seq_num if temp_segment else 0
                    
                    # Process through PLC
                    ack_segment_raw, was_dropped, was_corrupted = self.plc.process_incoming(
                        data, 'ACK', ack_seq_num, 0, self.get_elapsed_time()
                    )
                    
                    if was_dropped:
                        # Check for timeout
                        if self.check_timer():
                            self.retransmit_oldest()
                        continue
                        
                    # Decode and verify
                    ack_segment = URPSegment.decode(ack_segment_raw)
                    if ack_segment is None:
                        # Check for timeout
                        if self.check_timer():
                            self.retransmit_oldest()
                        continue
                        
                    if not ack_segment.verify_checksum():
                        self.stats['corrupted_acks_discarded'] += 1
                        # Check for timeout
                        if self.check_timer():
                            self.retransmit_oldest()
                        continue
                        
                    # Process ACK
                    self.process_ack(ack_segment)
                        
                except timeout:
                    # No ACK received, continue to send more segments if window allows
                    pass
                except:
                    # Other error, continue
                    pass
                
        file.close()
        
        # Wait for all data to be acknowledged
        while len(self.unacked_segments) > 0:
            try:
                self.socket.settimeout(0.01)
                data, addr = self.socket.recvfrom(1024)
                
                # Try to decode first to get sequence number for logging
                temp_segment = URPSegment.decode(data)
                ack_seq_num = temp_segment.seq_num if temp_segment else 0
                
                ack_segment_raw, was_dropped, was_corrupted = self.plc.process_incoming(
                    data, 'ACK', ack_seq_num, 0, self.get_elapsed_time()
                )
                
                if was_dropped:
                    # Check for timeout
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                ack_segment = URPSegment.decode(ack_segment_raw)
                if ack_segment is None:
                    # Check for timeout
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                if not ack_segment.verify_checksum():
                    self.stats['corrupted_acks_discarded'] += 1
                    # Check for timeout
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
        
        # Create FIN segment
        fin_seq = self.next_seq
        fin_segment = URPSegment(fin_seq, 0, b'')
        fin_segment.set_flag('FIN')
        
        # Track FIN segment before sending so we can retransmit if dropped
        segment_data = fin_segment.encode()
        with self.window_lock:
            self.unacked_segments.append((
                fin_seq,
                segment_data,
                0,  # FIN has no payload
                time.time()
            ))
            # Start timer if there are no other unacked segments
            if len(self.unacked_segments) == 1:
                self.start_timer()
        
        self.send_segment(fin_segment, is_retransmission=False)
        
        # Wait for ACK
        while self.state == FIN_WAIT:
            try:
                self.socket.settimeout(0.01)
                data, addr = self.socket.recvfrom(1024)
                
                # Try to decode first to get sequence number for logging
                temp_segment = URPSegment.decode(data)
                ack_seq_num = temp_segment.seq_num if temp_segment else 0
                
                ack_segment_raw, was_dropped, was_corrupted = self.plc.process_incoming(
                    data, 'ACK', ack_seq_num, 0, self.get_elapsed_time()
                )
                
                if was_dropped:
                    # Check for timeout
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                ack_segment = URPSegment.decode(ack_segment_raw)
                if ack_segment is None:
                    # Check for timeout
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                if not ack_segment.verify_checksum():
                    self.stats['corrupted_acks_discarded'] += 1
                    # Check for timeout
                    if self.check_timer():
                        self.retransmit_oldest()
                    continue
                    
                # Check if ACK acknowledges FIN (ACK num should be FIN seq + 1)
                expected_ack = (fin_seq + 1) % 65536
                if ack_segment.is_ack() and ack_segment.seq_num == expected_ack:
                    self.state = CLOSED
                    # Remove FIN from unacked list
                    with self.window_lock:
                        if len(self.unacked_segments) > 0:
                            self.unacked_segments.pop(0)
                    break
                    
            except timeout:
                if self.check_timer():
                    self.retransmit_oldest()
                continue
                
    def run(self):
        """Main execution flow: setup, transfer, teardown."""
        try:
            self.connection_setup()
            self.transfer_data()
            self.connection_teardown()
        except Exception as e:
            print(f"Connection reset: {e}")
            return
            
        # Write final statistics
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
    """Main entry point for URP Sender."""
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
