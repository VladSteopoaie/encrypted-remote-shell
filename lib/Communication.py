import socket
import threading
import signal
from types import MethodType
from lib.Logger import logger as log
from enum import IntEnum, auto

class Command(IntEnum):
    '''
    Enum for different command types.
    '''
    EXIT = 0
    LIB = 1
    RSA_PUB = 2
    RSA_KE = 3
    DHKE = 4
    EXEC = 5
    FILE = 6
    ERROR = 7
    
class Packet:
    '''
    Class representing a network packet with a command and message.
    '''
    def __init__(self, byte_stream):
        self.size = len(byte_stream)
        self.command = byte_stream[:2]
        self.message = byte_stream[2:]

    def data(self):
        return self.command + self.message

class NetComm:
    '''
    Class for network communication over TCP sockets.
    '''
    def __init__(self, host : str, port : int, sock=None):
        self.host = host
        self.port = port
        if sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"

    def send_packet(self, packet : Packet) -> bool:
        '''
        Sends a Packet over the socket.
        
        Args:
            packet (Packet): The packet to send.

        Returns:
            bool: True if the packet was sent successfully, False otherwise.
        '''
        try:
            self.sock.send(int.to_bytes(packet.size, 4, byteorder='big'))
            self.sock.send(packet.data())
            return True
        except Exception as e:
            log.error(f"[NetComm] Error: {e}")
            return False
        
    def recv_packet(self) -> Packet:
        '''
        Receives a Packet from the socket.
        
        Returns:
            Packet: The received packet, or None if an error occurred.
        '''
        try:
            size = int.from_bytes(self.sock.recv(4), byteorder='big')
            data = self.sock.recv(size)
            return Packet(data)
        except Exception as e:
            log.error(f"[NetComm] Error: {e}")
            return None
class NetServer:
    '''
    Class for a TCP server that handles multiple clients.
    '''
    def __init__(self, func, host='127.0.0.1', port=9000):
        self.comm = NetComm(host, port) # a network communication object to handle the server socket
        self.clients = []
        self.func = MethodType(func, self) # the function to handle each client (implemented outside the class and passed as a method)
        self.accept_thread = None
        self.running = False

    def start(self):
        '''
        Starts the server and begins accepting clients.
        '''
        try:
            # set up signal handler for graceful shutdown on Ctrl+C
            signal.signal(signal.SIGINT, self._handle_sigint)

            # bind and listen
            self.comm.sock.bind((self.comm.host, self.comm.port))
            self.comm.sock.listen(5)
            
            # add a small timeout so accept() doesn’t block forever
            self.comm.sock.settimeout(1.0)

            self.running = True
            self.accept_thread = threading.Thread(target=self.accept_clients)
            log.info(f"[NetServer] Listening on {self.comm}")
            
            self.accept_thread.start()
            self.accept_thread.join()
        except Exception as e:
            log.error(f"[NetServer] Error starting server: {e}")
            raise e

    def accept_clients(self):
        '''
        Accepts incoming client connections in a loop.
        '''
        while self.running:
            try:
                # block until a new client connects
                client_socket, addr = self.comm.sock.accept()
                # create a NetComm object for the client
                client = NetComm(addr[0], addr[1], client_socket)
                self.clients.append(client)
                # start the client handler in a new thread
                threading.Thread(target=self.handle_client, args=(client,), daemon=True).start()

            except socket.timeout:
                # check again whether running
                continue

            except OSError:
                # this happens when the socket is closed in stop()
                break

            except Exception as e:
                log.error(f"[NetServer] Error accepting client: {e}")
                break

        log.warning("[NetServer] No longer accepting clients.")

    def handle_client(self, client: NetComm):
        '''
        Handles communication with a connected client. Implementation is provided by the user-defined function.
        '''
        self.func(client)

    def stop(self):
        '''
        Stops the server and disconnects all clients.
        '''
        if not self.running: # don't stop if already stopped
            return

        log.info("[NetServer] Stopping server...")
        self.running = False

        # close main socket to unblock accept()
        try:
            self.comm.sock.close()
        except Exception as e:
            log.error(f"[NetServer] stop: {e}")

        # close client sockets
        for client in self.clients:
            try:
                client.sock.close()
            except Exception as e:
                log.error(f"[NetServer] stop (client): {e}")
        self.clients.clear()

    def _handle_sigint(self, signum, frame):
        '''
        Signal handler for Ctrl+C (SIGINT).
        '''

        log.warning("[NetServer] Caught Ctrl+C — shutting down gracefully...")
        self.stop()

class NetClient:
    '''
    Class for a TCP client that connects to a server.
    '''
    def __init__(self, host='127.0.0.1', port=9000):
        self.comm = NetComm(host, port) # a network communication object to handle the client socket

    def connect(self):
        '''
        Creates a socket and connects to the server.
        '''
        try:
            self.comm.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.comm.sock.connect((self.comm.host, self.comm.port))
            log.success(f"[NetClient] Connection successful!")
        except Exception as e:
            log.error(f"[NetClient] Connection error!")
            raise e
    
    def send_data(self, command : int, data : bytes) -> bytes:
        '''
        Sends data to the server with the specified command and waits for a response.

        Args:
            command (int): The command type.
            data (bytes): The data to send.

        Returns:
            bytes: The response data from the server.
        '''
        self.comm.send_packet(Packet(command.to_bytes(length=2, byteorder='big') + data))
        packet = self.comm.recv_packet()
        if int.from_bytes(packet.command, byteorder='big') == Command.ERROR:
            raise ValueError(f"[NetClient] Error from server: {packet.message.decode()}")
        return packet.data()[2:]

    def disconnect(self):
        '''
        Disconnects from the server.
        '''
        self.comm.send_packet(Packet(Command.EXIT.to_bytes(2, 'big'))) # the command to exit is 0
        self.comm.sock.close()
        log.warning("[NetClient] Disconnected")
