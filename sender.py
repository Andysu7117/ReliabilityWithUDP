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
        self.window_lock = RLock()  # Use reentrant lock since retransmit_oldest may be called while lock is held
        
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
        print(f"[DEBUG] retransmit_oldest: Called")
        # Extract segment info while holding lock
        with self.window_lock:
            if len(self.unacked_segments) == 0:
                print(f"[DEBUG] retransmit_oldest: No unacked segments, returning")
                return
            seq_num, segment_data, payload_len, _ = self.unacked_segments[0]
            print(f"[DEBUG] retransmit_oldest: Retransmitting segment {seq_num}, payload_len={payload_len}")
            # Update send time for this retransmission
            self.unacked_segments[0] = (seq_num, segment_data, payload_len, time.time())

        segment = URPSegment.decode(segment_data)
        if segment is None:
            print(f"[DEBUG] retransmit_oldest: Failed to decode segment, returning")
            return

        seg_type = 'SYN' if segment.is_syn() else ('FIN' if segment.is_fin() else 'DATA')
        print(f"[DEBUG] retransmit_oldest: Segment type={seg_type}, checking timer")

        if self.check_timer():
            print(f"[DEBUG] retransmit_oldest: Timeout retransmission")
            self.stats['timeout_retransmissions'] += 1
        else:
            print(f"[DEBUG] retransmit_oldest: Fast retransmission")
            self.stats['fast_retransmissions'] += 1

        print(f"[DEBUG] retransmit_oldest: Processing through PLC")
        processed_data, was_dropped, _ = self.plc.process_outgoing(
            segment_data, seg_type, seq_num, payload_len, self.get_elapsed_time()
        )
        print(f"[DEBUG] retransmit_oldest: PLC processing done, was_dropped={was_dropped}")

        if not was_dropped:
            print(f"[DEBUG] retransmit_oldest: Sending retransmitted segment {seq_num}")
            self.socket.sendto(processed_data, ('127.0.0.1', self.receiver_port))
            self.stats['total_segments_sent'] += 1
            self.stats['total_data_sent'] += payload_len
        else:
            print(f"[DEBUG] retransmit_oldest: Retransmitted segment {seq_num} was dropped by PLC")

        print(f"[DEBUG] retransmit_oldest: Restarting timer and resetting dup_ack_count")
        self.restart_timer()
        self.dup_ack_count = 0
        print(f"[DEBUG] retransmit_oldest: Finished, returning")  

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
        """
        Process a received ACK segment.
        Updates window, removes acknowledged segments, handles duplicates.
        Returns True if ACK was processed, False otherwise.
        """
        if not segment.is_ack():
            return False
            
        ack_num = segment.seq_num
        
        # DEBUG: Print ACK processing info
        print(f"[DEBUG] process_ack: ACK {ack_num}, send_base={self.send_base}, last_ack_num={self.last_ack_num}, dup_count={self.dup_ack_count}, unacked_count={len(self.unacked_segments)}")
        
        # Check if this acknowledges new data
        with self.window_lock:
            if len(self.unacked_segments) == 0:
                print(f"[DEBUG] process_ack: No unacked segments, returning")
                return True

            # Check if this ACK acknowledges new data
            # An ACK acknowledges new data only if it acknowledges at least one segment
            # First, check if ACK equals the oldest unacked segment (duplicate ACK pattern)
            # This handles corrupted segments where receiver sends ACK = expected_seq
            if len(self.unacked_segments) > 0:
                oldest_seq, _, oldest_payload_len, _ = self.unacked_segments[0]
                if ack_num == oldest_seq:
                    print(f"[DEBUG] process_ack: Duplicate ACK detected! ack_num==oldest_seq={oldest_seq}, last_ack_num={self.last_ack_num}, dup_count={self.dup_ack_count}")
                    # This is a duplicate ACK for the oldest unacked segment
                    if self.last_ack_num != ack_num:
                        # First duplicate ACK for this segment
                        print(f"[DEBUG] process_ack: First duplicate ACK for this segment")
                        self.last_ack_num = ack_num
                        self.dup_ack_count = 1
                        self.stats['duplicate_acks_received'] += 1
                    else:
                        # Same duplicate ACK number
                        print(f"[DEBUG] process_ack: Incrementing duplicate ACK count to {self.dup_ack_count + 1}")
                        self.dup_ack_count += 1
                        self.stats['duplicate_acks_received'] += 1
                    
                    # Fast retransmit on >=3 duplicate ACKs
                    if self.dup_ack_count >= 3 and self.max_win > MSS:
                        print(f"[DEBUG] process_ack: Triggering fast retransmit! dup_count={self.dup_ack_count}, max_win={self.max_win}, MSS={MSS}")
                        try:
                            self.retransmit_oldest()
                            print(f"[DEBUG] process_ack: Fast retransmit completed successfully")
                        except Exception as e:
                            print(f"[DEBUG] process_ack: Exception during fast retransmit: {e}")
                            import traceback
                            traceback.print_exc()
                    else:
                        print(f"[DEBUG] process_ack: Not retransmitting yet: dup_count={self.dup_ack_count}, max_win={self.max_win}, MSS={MSS}")
                    return True
            
            # Check if ACK acknowledges any segments (ack_num >= send_base)
            # ACK N means "I've received all data up to (but not including) sequence number N"
            # So ACK N acknowledges segments with seq_num < N
            if self.seq_ge(ack_num, self.send_base):
                print(f"[DEBUG] process_ack: ACK {ack_num} >= send_base {self.send_base}, trying to remove segments")
                # Try to remove acknowledged segments
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
                
                # Only update send_base if we actually removed segments
                if segments_removed > 0:
                    print(f"[DEBUG] process_ack: Removed {segments_removed} segments, updating send_base to {ack_num}")
                    self.send_base = ack_num

                    # Restart or stop timer based on unacked segments
                    if len(self.unacked_segments) > 0:
                        self.restart_timer()
                    else:
                        self.stop_timer()

                    # Reset duplicate ACK count
                    self.dup_ack_count = 0
                    self.last_ack_num = ack_num
                    return True
                else:
                    # ACK doesn't acknowledge any segments (e.g., segment was corrupted)
                    # This means the ACK number is less than what we'd expect if the segment was received
                    # Check if this is a duplicate ACK for the oldest unacked segment
                    if len(self.unacked_segments) > 0:
                        oldest_seq, _, oldest_payload_len, _ = self.unacked_segments[0]
                        print(f"[DEBUG] process_ack: No segments removed, oldest_seq={oldest_seq}, ack_num={ack_num}")
                        # The receiver sends ACK = oldest_seq if it hasn't received the segment yet
                        # So if ack_num == oldest_seq, it's a duplicate ACK
                        if ack_num == oldest_seq:
                            print(f"[DEBUG] process_ack: Duplicate ACK detected! ack_num==oldest_seq={oldest_seq}, last_ack_num={self.last_ack_num}, dup_count={self.dup_ack_count}")
                            # This is a duplicate ACK for the oldest unacked segment
                            if self.last_ack_num != ack_num:
                                # First duplicate ACK for this segment
                                print(f"[DEBUG] process_ack: First duplicate ACK for this segment")
                                self.last_ack_num = ack_num
                                self.dup_ack_count = 1
                                self.stats['duplicate_acks_received'] += 1
                            else:
                                # Same duplicate ACK number
                                print(f"[DEBUG] process_ack: Incrementing duplicate ACK count to {self.dup_ack_count + 1}")
                                self.dup_ack_count += 1
                                self.stats['duplicate_acks_received'] += 1
                            
                            # Fast retransmit on >=3 duplicate ACKs
                            if self.dup_ack_count >= 3 and self.max_win > MSS:
                                print(f"[DEBUG] process_ack: Triggering fast retransmit! dup_count={self.dup_ack_count}, max_win={self.max_win}, MSS={MSS}")
                                self.retransmit_oldest()
                            else:
                                print(f"[DEBUG] process_ack: Not retransmitting yet: dup_count={self.dup_ack_count}, max_win={self.max_win}, MSS={MSS}")
                            return True
                        else:
                            print(f"[DEBUG] process_ack: ACK {ack_num} != oldest_seq {oldest_seq}, not a duplicate ACK")

            # Check for duplicate ACK (same ACK number as last one)
            if self.last_ack_num is not None and ack_num == self.last_ack_num:
                print(f"[DEBUG] process_ack: Duplicate ACK detected (same as last): ack_num={ack_num}, dup_count={self.dup_ack_count + 1}")
                # Duplicate ACK (same ACK number as last one)
                self.dup_ack_count += 1
                self.stats['duplicate_acks_received'] += 1

                # Fast retransmit on >=3 duplicate ACKs
                if self.dup_ack_count >= 3 and self.max_win > MSS:
                    print(f"[DEBUG] process_ack: Triggering fast retransmit! dup_count={self.dup_ack_count}, max_win={self.max_win}, MSS={MSS}")
                    self.retransmit_oldest()
                else:
                    print(f"[DEBUG] process_ack: Not retransmitting yet: dup_count={self.dup_ack_count}, max_win={self.max_win}, MSS={MSS}")
                return True

            # Check if ACK is for an unacked segment (duplicate ACK pattern)
            # If ACK number equals the oldest unacked segment's sequence number,
            # it means the receiver hasn't received that segment yet (duplicate ACK)
            if len(self.unacked_segments) > 0:
                oldest_seq, _, oldest_payload_len, _ = self.unacked_segments[0]
                print(f"[DEBUG] process_ack: Checking if ACK {ack_num} matches oldest_seq {oldest_seq}")
                # The receiver sends ACK = oldest_seq if it hasn't received the segment yet
                if ack_num == oldest_seq:
                    print(f"[DEBUG] process_ack: Duplicate ACK detected (matches oldest_seq)! ack_num={ack_num}, last_ack_num={self.last_ack_num}, dup_count={self.dup_ack_count}")
                    # This is a duplicate ACK for the oldest unacked segment
                    if self.last_ack_num != ack_num:
                        # First duplicate ACK for this segment
                        print(f"[DEBUG] process_ack: First duplicate ACK for this segment")
                        self.last_ack_num = ack_num
                        self.dup_ack_count = 1
                        self.stats['duplicate_acks_received'] += 1
                    else:
                        # Same duplicate ACK number
                        print(f"[DEBUG] process_ack: Incrementing duplicate ACK count to {self.dup_ack_count + 1}")
                        self.dup_ack_count += 1
                        self.stats['duplicate_acks_received'] += 1
                    
                    # Fast retransmit on >=3 duplicate ACKs
                    if self.dup_ack_count >= 3 and self.max_win > MSS:
                        print(f"[DEBUG] process_ack: Triggering fast retransmit! dup_count={self.dup_ack_count}, max_win={self.max_win}, MSS={MSS}")
                        self.retransmit_oldest()
                    else:
                        print(f"[DEBUG] process_ack: Not retransmitting yet: dup_count={self.dup_ack_count}, max_win={self.max_win}, MSS={MSS}")
                    return True
                else:
                    print(f"[DEBUG] process_ack: ACK {ack_num} != oldest_seq {oldest_seq}")

            # Old ACK or first ACK (last_ack_num is None)
            # Set last_ack_num so we can detect duplicates next time
            if self.last_ack_num is None:
                print(f"[DEBUG] process_ack: Setting last_ack_num to {ack_num} (first ACK)")
                self.last_ack_num = ack_num
            else:
                print(f"[DEBUG] process_ack: Old ACK or other case, last_ack_num={self.last_ack_num}, ack_num={ack_num}")
            # If ack_num < send_base, it's an old ACK - ignore it
            return True
        
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
        
        # Continue loop while we have data to send OR unacked segments
        while self.file_pointer < self.file_size or len(self.unacked_segments) > 0:
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
            # Keep checking until window space is available or we've processed enough ACKs
            if self.max_win > MSS:
                # Check for ACKs while window is full or we have unacked segments
                # This loop should continue as long as we have unacked segments or can send more data
                # Keep checking for ACKs until we can send more data or have no unacked segments
                print(f"[DEBUG] transfer_data: Entering ACK processing loop (sliding window mode)")
                consecutive_timeouts = 0
                max_consecutive_timeouts = 1000  # Prevent infinite loop
                while True:
                    available = self.get_available_window_space()
                    print(f"[DEBUG] transfer_data: ACK loop iteration - available={available}, file_pointer={self.file_pointer}, file_size={self.file_size}, unacked_count={len(self.unacked_segments)}")
                    
                    # If window has space and we have more data to send, break to send more
                    if available >= MSS and self.file_pointer < self.file_size:
                        print(f"[DEBUG] transfer_data: Breaking ACK loop - window has space and more data to send")
                        break
                    
                    # If no unacked segments, break
                    with self.window_lock:
                        if len(self.unacked_segments) == 0:
                            print(f"[DEBUG] transfer_data: Breaking ACK loop - no unacked segments")
                            break
                    
                    # Check timer before trying to receive (important for packet loss scenarios)
                    if self.check_timer():
                        self.retransmit_oldest()
                        consecutive_timeouts = 0  # Reset timeout counter after retransmission
                        # After retransmission, continue loop to check for ACKs
                        # Don't break - we want to keep checking for ACKs
                    
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
                            
                        # Process ACK (this may trigger fast retransmit)
                        print(f"[DEBUG] transfer_data: Processing ACK in sliding window loop")
                        self.process_ack(ack_segment)
                        consecutive_timeouts = 0  # Reset timeout counter after receiving ACK
                        
                        # After processing ACK, check if we should continue or break
                        # If window has space now and we have more data, break to send more segments
                        available = self.get_available_window_space()
                        print(f"[DEBUG] transfer_data: After ACK processing, available={available}, file_pointer={self.file_pointer}, file_size={self.file_size}")
                        if available >= MSS and self.file_pointer < self.file_size:
                            print(f"[DEBUG] transfer_data: Breaking to send more segments")
                            break
                        # Otherwise continue to process more ACKs (including duplicates for fast retransmit)
                            
                    except timeout:
                        # No ACK received - this is normal, continue checking
                        # Timer check happens at the start of the loop
                        consecutive_timeouts += 1
                        if consecutive_timeouts >= max_consecutive_timeouts:
                            print(f"[DEBUG] transfer_data: Too many consecutive timeouts ({consecutive_timeouts}), breaking loop")
                            break
                        print(f"[DEBUG] transfer_data: Timeout in ACK receive loop, continuing (consecutive={consecutive_timeouts})")
                        continue
                    except Exception as e:
                        # Other error, break
                        print(f"[DEBUG] transfer_data: Exception in ACK receive loop: {e}")
                        break
                
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
