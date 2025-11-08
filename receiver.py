"""
URP Receiver Implementation
Implements a reliable UDP-based transport protocol (URP) receiver with:
- Multithreaded server architecture
- Connection setup (LISTEN for SYN)
- Data reception with buffering and in-order delivery
- Connection teardown (TIME_WAIT state)
- Comprehensive logging

Usage: python3 receiver.py receiver_port sender_port txt_file_received max_win
"""
from socket import *
from threading import Thread, Lock
from queue import Queue
import sys
import time
from urpsegment import URPSegment, HEADER_SIZE

# Constants
MSL = 1.0  # Maximum segment lifetime in seconds

# State constants for Receiver
CLOSED = "CLOSED"
LISTEN = "LISTEN"
ESTABLISHED = "ESTABLISHED"
TIME_WAIT = "TIME_WAIT"

class ClientThread(Thread):
    """
    Thread class to handle each client connection.
    Each instance handles one complete URP connection lifecycle.
    """
    def __init__(self, client_address, receiver_socket, sender_port, filename, max_win, message_queue):
        """
        Initialize a client handler thread.
        
        Args:
            client_address: Address of the client (sender)
            receiver_socket: Shared UDP socket for sending ACKs
            sender_port: Port to send ACKs to
            filename: File to write received data
            max_win: Maximum receive window size
            message_queue: Queue to receive segments from main server thread
        """
        Thread.__init__(self)
        self.client_address = client_address
        self.receiver_socket = receiver_socket
        self.sender_port = sender_port
        self.filename = filename
        self.max_win = max_win
        self.message_queue = message_queue
        self.client_alive = True
        
        # Protocol state - reset for new connection
        self.state = LISTEN
        self.expected_seq = 0  # Next expected sequence number
        self.isn = None  # Initial sequence number from SYN
        
        # Receive buffer for out-of-order segments
        self.receive_buffer = {}  # seq_num -> (data, payload_len)
        self.received_seqs = set()  # Track received sequence numbers
        
        # File handling
        self.output_file = None
        
        # Statistics
        self.stats = {
            'original_data_received': 0,
            'total_data_received': 0,
            'original_segments_received': 0,
            'total_segments_received': 0,
            'corrupted_segments_discarded': 0,
            'duplicate_segments_received': 0,
            'total_acks_sent': 0,
            'duplicate_acks_sent': 0
        }
        
        # Logging - use standard receiver_log.txt (per assignment spec)
        self.log_file = open('receiver_log.txt', 'w')
        self.start_time = None
        
    def log_segment(self, direction, status, time_ms, seg_type, seq_num, payload_len):
        """
        Log a segment event to the log file.
        """
        self.log_file.write(f"{direction} {status} {time_ms:.2f} {seg_type} {seq_num} {payload_len}\n")
        self.log_file.flush()  # Real-time logging
        
    def get_elapsed_time(self):
        """Get elapsed time in milliseconds since start."""
        if self.start_time is None:
            return 0.0
        return (time.time() - self.start_time) * 1000.0
        
    def send_ack(self, ack_num, is_duplicate=False):
        """
        Send an ACK segment.
        
        Args:
            ack_num: Acknowledgment number (next expected sequence number)
            is_duplicate: True if this is a duplicate ACK
        """
        ack_segment = URPSegment(ack_num, 0, b'')
        ack_segment.set_flag('ACK')
        
        segment_data = ack_segment.encode()
        self.receiver_socket.sendto(segment_data, ('127.0.0.1', self.sender_port))
        
        self.stats['total_acks_sent'] += 1
        if is_duplicate:
            self.stats['duplicate_acks_sent'] += 1
            
        self.log_segment('snd', 'ok', self.get_elapsed_time(), 'ACK', ack_num, 0)
        
    def write_data_to_file(self):
        """
        Write all in-order data from receive buffer to file.
        Updates expected_seq as data is written.
        """
        while self.expected_seq in self.receive_buffer:
            data, payload_len = self.receive_buffer.pop(self.expected_seq)
            self.output_file.write(data)
            self.expected_seq = (self.expected_seq + payload_len) % 65536
            
    def process_syn(self, segment):
        """
        Process a SYN segment.
        Returns True if connection established, False otherwise.
        """
        if self.state != LISTEN:
            # Unexpected SYN in wrong state
            return False
            
        # Store ISN
        self.isn = segment.seq_num
        self.expected_seq = (self.isn + 1) % 65536
        
        # Send ACK
        self.send_ack(self.expected_seq)
        
        # Transition to ESTABLISHED
        self.state = ESTABLISHED
        
        # Open output file
        self.output_file = open(self.filename, 'wb')
        
        return True
        
    def process_data(self, segment):
        """
        Process a DATA segment.
        Returns True if processed successfully, False otherwise.
        """
        if self.state != ESTABLISHED:
            return False
            
        seq_num = segment.seq_num
        payload = segment.payload
        payload_len = len(payload)
        
        # Check if duplicate (must check BEFORE window check to avoid counting old duplicates as original)
        is_duplicate = seq_num in self.received_seqs
        
        # Check if segment is within receive window (handle wraparound)
        # Segments outside window are old duplicates that should not be counted
        window_end = (self.expected_seq + self.max_win) % 65536
        in_window = False
        if self.expected_seq < window_end:
            # No wraparound case
            in_window = seq_num >= self.expected_seq and seq_num < window_end
        else:
            # Wraparound case: window spans across 65536 boundary
            in_window = seq_num >= self.expected_seq or seq_num < window_end
        
        # Only count as original if not duplicate AND within window
        # Segments outside window are old duplicates (already ACKed)
        if not is_duplicate and in_window:
            self.stats['original_segments_received'] += 1
            self.stats['original_data_received'] += payload_len
            self.stats['total_data_received'] += payload_len
            self.received_seqs.add(seq_num)
        elif is_duplicate:
            self.stats['duplicate_segments_received'] += 1
            # Count duplicate DATA segment's payload in total_data_received
            self.stats['total_data_received'] += payload_len
        # If outside window and not duplicate, it's an old segment - don't count as original
        # but still count in total_segments_received
            
        self.stats['total_segments_received'] += 1
        
        # Check if in-order or out-of-order
        if seq_num == self.expected_seq:
            # In-order segment - write to file immediately
            self.output_file.write(payload)
            self.expected_seq = (self.expected_seq + payload_len) % 65536
            
            # Write any buffered in-order data
            self.write_data_to_file()
            
            # Send ACK
            self.send_ack(self.expected_seq, is_duplicate=False)
            
        else:
            # Out-of-order segment (already checked window above)
            if in_window:
                # Out-of-order segment within window - buffer it
                if seq_num not in self.receive_buffer:
                    self.receive_buffer[seq_num] = (payload, payload_len)
                    
                # Send duplicate ACK
                self.send_ack(self.expected_seq, is_duplicate=True)
            else:
                # Segment outside window - ignore but send ACK
                self.send_ack(self.expected_seq, is_duplicate=True)
            
        return True
        
    def process_fin(self, segment):
        """
        Process a FIN segment.
        Returns True if processed successfully, False otherwise.
        """
        if self.state != ESTABLISHED:
            return False
            
        fin_seq = segment.seq_num
        
        # Write any remaining buffered data
        self.write_data_to_file()
        
        # Close output file
        if self.output_file:
            self.output_file.close()
            self.output_file = None
            
        # Send ACK for FIN
        ack_num = (fin_seq + 1) % 65536
        self.send_ack(ack_num)
        
        # Transition to TIME_WAIT
        self.state = TIME_WAIT
        
        return True
        
    def time_wait_timer(self):
        """
        Timer thread for TIME_WAIT state.
        Waits 2*MSL seconds before transitioning to CLOSED.
        """
        time.sleep(2 * MSL)  # Wait 2 MSL
        self.state = CLOSED
        
    def run(self):
        """
        Main thread execution flow: handle one connection lifecycle.
        Each thread handles a complete connection from SYN to CLOSED.
        Receives segments from message queue (routed by main server thread).
        """
        self.start_time = None
        
        while self.client_alive:
            try:
                # Receive segment from message queue (routed by main server)
                # Use timeout to periodically check if connection should close
                try:
                    data, addr = self.message_queue.get(timeout=0.1)
                except:
                    # Timeout - check if we should continue
                    continue
                
                # Decode segment
                segment = URPSegment.decode(data)
                if segment is None:
                    continue
                    
                # Set start time on first received segment
                if self.start_time is None:
                    self.start_time = time.time()
                    
                # Determine segment type
                if segment.is_syn():
                    seg_type = 'SYN'
                    payload_len = 0
                elif segment.is_fin():
                    seg_type = 'FIN'
                    payload_len = 0
                elif segment.is_data():
                    seg_type = 'DATA'
                    payload_len = len(segment.payload)
                else:
                    continue  # Not a segment we process
                    
                # Verify checksum
                if not segment.verify_checksum():
                    # Corrupted segment - discard
                    # Don't track sequence number yet - only track after successful reception
                    # This way, retransmissions of corrupted segments will be counted as original
                    # Don't count corrupted segment's payload in total_data_received
                    # Don't count corrupted segment in original_segments_received
                    
                    self.stats['corrupted_segments_discarded'] += 1
                    self.stats['total_segments_received'] += 1
                    self.log_segment('rcv', 'cor', self.get_elapsed_time(), seg_type, segment.seq_num, payload_len)
                    continue
                    
                # Log valid segment
                self.log_segment('rcv', 'ok', self.get_elapsed_time(), seg_type, segment.seq_num, payload_len)
                
                # Track statistics for SYN and FIN segments (DATA is tracked in process_data)
                seq_num = segment.seq_num
                if segment.is_syn() or segment.is_fin():
                    # Check if duplicate SYN/FIN
                    is_duplicate = seq_num in self.received_seqs
                    
                    if not is_duplicate:
                        self.stats['original_segments_received'] += 1
                        self.received_seqs.add(seq_num)
                    else:
                        self.stats['duplicate_segments_received'] += 1
                        # Don't count SYN/FIN payload (0) in total_data_received
                    
                    self.stats['total_segments_received'] += 1
                
                # Process segment based on type
                if segment.is_syn():
                    if not self.process_syn(segment):
                        print(f"Connection reset: Unexpected SYN from {addr}")
                        break
                        
                elif segment.is_data():
                    if not self.process_data(segment):
                        print(f"Connection reset: Unexpected DATA from {addr}")
                        break
                        
                elif segment.is_fin():
                    if not self.process_fin(segment):
                        print(f"Connection reset: Unexpected FIN from {addr}")
                        break
                    
                    # Start TIME_WAIT timer
                    timer_thread = Thread(target=self.time_wait_timer)
                    timer_thread.start()
                    
                    # Wait for timer or handle duplicate FINs
                    while self.state == TIME_WAIT:
                        try:
                            # Get segment from queue with timeout
                            try:
                                data, addr = self.message_queue.get(timeout=0.1)
                            except:
                                # Timeout - check if timer expired
                                if self.state == CLOSED:
                                    break
                                continue
                            
                            segment = URPSegment.decode(data)
                            if segment and segment.is_fin():
                                # Duplicate FIN - resend ACK
                                fin_seq = segment.seq_num
                                ack_num = (fin_seq + 1) % 65536
                                self.send_ack(ack_num)
                                
                                if segment.verify_checksum():
                                    self.log_segment('rcv', 'ok', self.get_elapsed_time(), 'FIN', fin_seq, 0)
                                else:
                                    self.stats['corrupted_segments_discarded'] += 1
                                    self.log_segment('rcv', 'cor', self.get_elapsed_time(), 'FIN', fin_seq, 0)
                                    
                        except timeout:
                            # Check if timer expired
                            if self.state == CLOSED:
                                break
                            continue
                            
                    self.client_alive = False  # Connection closed
                    break
                    
            except Exception as e:
                if self.state == CLOSED:
                    break
                print(f"Connection reset: {e} from {self.client_address}")
                break
            
        # Write final statistics
        self.write_statistics()
        self.log_file.close()
        self.client_alive = False
        
        # Signal that this connection is finished
        print(f"===== Connection closed for: {self.client_address}")
        
    def write_statistics(self):
        """Write statistics to log file."""
        self.log_file.write(f"\nOriginal data received: {self.stats['original_data_received']}\n")
        self.log_file.write(f"Total data received: {self.stats['total_data_received']}\n")
        self.log_file.write(f"Original segments received: {self.stats['original_segments_received']}\n")
        self.log_file.write(f"Total segments received: {self.stats['total_segments_received']}\n")
        self.log_file.write(f"Corrupted segments discarded: {self.stats['corrupted_segments_discarded']}\n")
        self.log_file.write(f"Duplicate segments received: {self.stats['duplicate_segments_received']}\n")
        self.log_file.write(f"Total acks sent: {self.stats['total_acks_sent']}\n")
        self.log_file.write(f"Duplicate acks sent: {self.stats['duplicate_acks_sent']}\n")

class URPReceiver:
    """
    Main URP Receiver server implementation.
    Multithreaded server that accepts connections and spawns handler threads.
    """
    def __init__(self, receiver_port, sender_port, filename, max_win):
        """
        Initialize URP Receiver Server.
        
        Args:
            receiver_port: UDP port for receiver
            sender_port: UDP port for sender
            filename: File to write received data
            max_win: Maximum receive window size
        """
        self.receiver_port = receiver_port
        self.sender_port = sender_port
        self.filename = filename
        self.max_win = max_win
        
        # Initialize UDP socket (shared by all connections)
        self.server_socket = socket(AF_INET, SOCK_DGRAM)
        self.server_socket.bind(('127.0.0.1', receiver_port))
        
        # Track active client threads
        self.active_threads = []
        self.threads_lock = Lock()
        # Message routing: client_address -> message queue
        self.client_queues = {}  # client_address -> Queue
        self.queues_lock = Lock()
        
    def run(self):
        """
        Main server loop: listen for connections and spawn handler threads.
        Routes segments to appropriate handler threads based on client address.
        """
        print("\n===== Server is running =====")
        print("===== Waiting for connection request from clients...=====")

        # Track seen clients (for UDP, we identify connections by address)
        seen_clients = {}  # client_address -> ClientHandlerThread

        while True:
            try:
                # Receive segment from any client
                data, client_addr = self.server_socket.recvfrom(1024 + HEADER_SIZE)
                
                # Decode segment
                segment = URPSegment.decode(data)
                if segment is None:
                    continue
                
                # Check if this is a SYN segment (new connection)
                if segment.is_syn() and segment.verify_checksum():
                    # Always check if we need a new connection
                    # (either new client or previous connection finished)
                    need_new_connection = False
                    
                    if client_addr not in seen_clients:
                        need_new_connection = True
                    else:
                        # Check if previous thread is still alive
                        with self.threads_lock:
                            old_thread = seen_clients.get(client_addr)
                            if old_thread is None or not old_thread.is_alive():
                                # Previous connection finished - clean up and allow new connection
                                need_new_connection = True
                                # Clean up old entries
                                if old_thread and old_thread in self.active_threads:
                                    self.active_threads.remove(old_thread)
                                with self.queues_lock:
                                    if client_addr in self.client_queues:
                                        del self.client_queues[client_addr]
                                del seen_clients[client_addr]
                                print(f"===== Previous connection finished for {client_addr}, ready for new connection")
                    
                    if need_new_connection:
                        # Create message queue for this client
                        client_queue = Queue()
                        
                        # Create handler thread
                        client_thread = ClientThread(
                            client_addr, 
                            self.server_socket, 
                            self.sender_port, 
                            self.filename, 
                            self.max_win,
                            client_queue
                        )
                        client_thread.start()
                        seen_clients[client_addr] = client_thread
                        
                        with self.threads_lock:
                            self.active_threads.append(client_thread)
                            
                        with self.queues_lock:
                            self.client_queues[client_addr] = client_queue
                            
                        print(f"===== New connection created for: {client_addr}")
                
                # Route segment to appropriate handler thread (only if thread is alive)
                with self.queues_lock:
                    if client_addr in self.client_queues:
                        # Check if thread is still alive
                        thread_alive = False
                        with self.threads_lock:
                            if client_addr in seen_clients:
                                thread_alive = seen_clients[client_addr].is_alive()
                        
                        if thread_alive:
                            # Put segment in client's message queue
                            try:
                                self.client_queues[client_addr].put((data, client_addr))
                            except:
                                # Queue might be closed, ignore
                                pass
                        else:
                            # Thread is dead, clean up
                            if client_addr in self.client_queues:
                                del self.client_queues[client_addr]
                            with self.threads_lock:
                                if client_addr in seen_clients:
                                    old_thread = seen_clients[client_addr]
                                    if old_thread in self.active_threads:
                                        self.active_threads.remove(old_thread)
                                    del seen_clients[client_addr]
                    
            except KeyboardInterrupt:
                print("\n===== Server shutting down =====")
                break
            except Exception as e:
                print(f"Server error: {e}")
                continue
                
        # Wait for all threads to complete
        with self.threads_lock:
            for thread in self.active_threads:
                thread.join()
                
        self.server_socket.close()

def main():
    """Main entry point for URP Receiver."""
    if len(sys.argv) != 5:
        print("\n===== Error usage, python3 receiver.py receiver_port sender_port txt_file_received max_win ======\n")
        sys.exit(1)
        
    receiver_port = int(sys.argv[1])
    sender_port = int(sys.argv[2])
    filename = sys.argv[3]
    max_win = int(sys.argv[4])
    
    receiver = URPReceiver(receiver_port, sender_port, filename, max_win)
    receiver.run()
    print("\n===== Server is shutting down =====")
    print("===== All connections closed =====")
# If the script is run directly, run the main function
if __name__ == "__main__":
    main()