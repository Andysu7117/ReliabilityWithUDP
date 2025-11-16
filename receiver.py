from socket import *
from threading import Thread, Lock
from queue import Queue
import sys
import time
from urpsegment import URPSegment, HEADER_SIZE

# Constants
MSL = 1.0  # Maximum segment lifetime in seconds

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
        
        self.state = LISTEN
        self.expected_seq = 0  # Next expected sequence number
        self.isn = None  # Initial sequence number from SYN
        
        self.receive_buffer = {}  # seq_num -> (data, payload_len)
        self.received_seqs = set()  # Track received sequence numbers
        
        self.output_file = None
        
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
        
        # Logging
        self.log_file = open('receiver_log.txt', 'w')
        self.start_time = None
        
    def log_segment(self, direction, status, time_ms, seg_type, seq_num, payload_len):
        """
        Log a segment event to the log file.
        """
        self.log_file.write(f"{direction} {status} {time_ms:.2f} {seg_type} {seq_num} {payload_len}\n")
        self.log_file.flush()
        
    def get_elapsed_time(self):
        if self.start_time is None:
            return 0.0
        return (time.time() - self.start_time) * 1000.0
        
    def send_ack(self, ack_num, is_duplicate=False):
        """
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
        while self.expected_seq in self.receive_buffer:
            data, payload_len = self.receive_buffer.pop(self.expected_seq)
            self.output_file.write(data)
            self.expected_seq = (self.expected_seq + payload_len) % 65536
            
    def process_syn(self, segment):
        if self.state != LISTEN:
            return False
            
        self.isn = segment.seq_num
        self.expected_seq = (self.isn + 1) % 65536
        
        self.send_ack(self.expected_seq)

        self.state = ESTABLISHED
        
        self.output_file = open(self.filename, 'wb')
        
        return True
        
    def process_data(self, segment):
        if self.state != ESTABLISHED:
            return False
            
        seq_num = segment.seq_num
        payload = segment.payload
        payload_len = len(payload)
        
        is_duplicate = seq_num in self.received_seqs
        
        window_end = (self.expected_seq + self.max_win) % 65536
        in_window = False
        if self.expected_seq < window_end:
            # No wraparound case.
            in_window = seq_num >= self.expected_seq and seq_num < window_end
        else:
            # Wraparound case.
            in_window = seq_num >= self.expected_seq or seq_num < window_end
        
        if not is_duplicate and in_window:
            self.stats['original_segments_received'] += 1
            self.stats['original_data_received'] += payload_len
            self.stats['total_data_received'] += payload_len
            self.received_seqs.add(seq_num)
        elif is_duplicate:
            self.stats['duplicate_segments_received'] += 1
            self.stats['total_data_received'] += payload_len
            
        self.stats['total_segments_received'] += 1
        
        if seq_num == self.expected_seq:
            # In-order segment.
            self.output_file.write(payload)
            self.expected_seq = (self.expected_seq + payload_len) % 65536
            
            self.write_data_to_file()
            
            self.send_ack(self.expected_seq, is_duplicate=False)
            
        else:
            # Out-of-order segment.
            if in_window:
                if seq_num not in self.receive_buffer:
                    self.receive_buffer[seq_num] = (payload, payload_len)
                    
                self.send_ack(self.expected_seq, is_duplicate=True)
            else:
                # Segment outside window.
                self.send_ack(self.expected_seq, is_duplicate=True)
            
        return True
        
    def process_fin(self, segment):
        if self.state != ESTABLISHED:
            return False
            
        fin_seq = segment.seq_num
        
        self.write_data_to_file()
        
        if self.output_file:
            self.output_file.close()
            self.output_file = None
            
        ack_num = (fin_seq + 1) % 65536
        self.send_ack(ack_num)
        
        self.state = TIME_WAIT
        
        return True
        
    def time_wait_timer(self):
        time.sleep(2 * MSL)  # Wait 2 MSL
        self.state = CLOSED
        
    def run(self):
        self.start_time = None
        
        while self.client_alive:
            try:
                try:
                    data, addr = self.message_queue.get(timeout=0.1)
                except:
                    continue
                
                segment = URPSegment.decode(data)
                if segment is None:
                    continue
                    
                if self.start_time is None:
                    self.start_time = time.time()
                    
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
                    continue 
                    
                # Verify checksum.
                if not segment.verify_checksum():            
                    self.stats['corrupted_segments_discarded'] += 1
                    self.stats['total_segments_received'] += 1
                    self.log_segment('rcv', 'cor', self.get_elapsed_time(), seg_type, segment.seq_num, payload_len)
                    continue
                    
                self.log_segment('rcv', 'ok', self.get_elapsed_time(), seg_type, segment.seq_num, payload_len)
                
                seq_num = segment.seq_num
                if segment.is_syn() or segment.is_fin():
                    is_duplicate = seq_num in self.received_seqs
                    
                    if not is_duplicate:
                        self.stats['original_segments_received'] += 1
                        self.received_seqs.add(seq_num)
                    else:
                        self.stats['duplicate_segments_received'] += 1
                    
                    self.stats['total_segments_received'] += 1
                
                # Process segment based on type.
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
                    
                    timer_thread = Thread(target=self.time_wait_timer)
                    timer_thread.start()
                    
                    while self.state == TIME_WAIT:
                        try:
                            try:
                                data, addr = self.message_queue.get(timeout=0.1)
                            except:
                                if self.state == CLOSED:
                                    break
                                continue
                            
                            segment = URPSegment.decode(data)
                            if segment and segment.is_fin():
                                fin_seq = segment.seq_num
                                ack_num = (fin_seq + 1) % 65536
                                self.send_ack(ack_num)
                                
                                if segment.verify_checksum():
                                    self.log_segment('rcv', 'ok', self.get_elapsed_time(), 'FIN', fin_seq, 0)
                                else:
                                    self.stats['corrupted_segments_discarded'] += 1
                                    self.log_segment('rcv', 'cor', self.get_elapsed_time(), 'FIN', fin_seq, 0)
                                    
                        except timeout:
                            if self.state == CLOSED:
                                break
                            continue
                            
                    self.client_alive = False  # Connection closed.
                    break
                    
            except Exception as e:
                if self.state == CLOSED:
                    break
                print(f"Connection reset: {e} from {self.client_address}")
                break
            
        # Write final statistics.
        self.write_statistics()
        self.log_file.close()
        self.client_alive = False
        
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
    def __init__(self, receiver_port, sender_port, filename, max_win):
        """
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
        
        self.server_socket = socket(AF_INET, SOCK_DGRAM)
        self.server_socket.bind(('127.0.0.1', receiver_port))
        
        # Track active client threads.
        self.active_threads = []
        self.threads_lock = Lock()
        self.client_queues = {}  # client_address -> Queue
        self.queues_lock = Lock()
        
    def run(self):
        print("\n===== Server is running =====")
        print("===== Waiting for connection request from clients...=====")

        # Track seen clients.
        seen_clients = {}

        while True:
            try:
                data, client_addr = self.server_socket.recvfrom(1024 + HEADER_SIZE)

                segment = URPSegment.decode(data)
                if segment is None:
                    continue
                
                if segment.is_syn() and segment.verify_checksum():
                    need_new_connection = False
                    
                    if client_addr not in seen_clients:
                        need_new_connection = True
                    else:
                        with self.threads_lock:
                            old_thread = seen_clients.get(client_addr)
                            if old_thread is None or not old_thread.is_alive():
                                need_new_connection = True
                                if old_thread and old_thread in self.active_threads:
                                    self.active_threads.remove(old_thread)
                                with self.queues_lock:
                                    if client_addr in self.client_queues:
                                        del self.client_queues[client_addr]
                                del seen_clients[client_addr]
                                print(f"===== Previous connection finished for {client_addr}, ready for new connection")
                    
                    if need_new_connection:
                        client_queue = Queue()
                        
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
                
                with self.queues_lock:
                    if client_addr in self.client_queues:
                        thread_alive = False
                        with self.threads_lock:
                            if client_addr in seen_clients:
                                thread_alive = seen_clients[client_addr].is_alive()
                        
                        if thread_alive:
                            try:
                                self.client_queues[client_addr].put((data, client_addr))
                            except:
                                pass
                        else:
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

if __name__ == "__main__":
    main()