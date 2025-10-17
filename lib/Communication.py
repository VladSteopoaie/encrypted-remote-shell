import socket
import threading
from types import MethodType
from lib.Logger import logger as log
from enum import IntEnum, auto

class Command(IntEnum):
    EXIT = 0
    LIB = 1
    RSA_PUB = 2
    RSA_KE = 3
    DHKE = 4
    EXEC = 5
    FILE = 6
    ERROR = 7
class Packet:
    def __init__(self, byte_stream):
        self.size = len(byte_stream)
        self.command = byte_stream[:2]
        self.message = byte_stream[2:]

    def data(self):
        return self.command + self.message

class NetComm:
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
        try:
            self.sock.send(int.to_bytes(packet.size, 4, byteorder='big'))
            self.sock.send(packet.data())
            return True
        except Exception as e:
            log.error(f"[NetComm] Error: {e}")
            return False
        
    def recv_packet(self) -> Packet:
        try:
            size = int.from_bytes(self.sock.recv(4), byteorder='big')
            data = self.sock.recv(size)
            return Packet(data)
        except Exception as e:
            log.error(f"[NetComm] Error: {e}")
            return None

class NetServer:
    def __init__(self, func, host='127.0.0.1', port=9000):
        self.comm = NetComm(host, port)
        self.clients = []
        self.running = False
        self.func = MethodType(func, self)

    def start(self):
        try:
            self.comm.sock.bind((self.comm.host, self.comm.port))
            self.comm.sock.listen(5)
            t = threading.Thread(target=self.accept_clients)
            self.running = True

            log.info(f"[NetServer] Listening on {self.comm}")
            t.start()
            t.join()
        except Exception as e:
            log.error(f"[NetServer] Error starting server!")
            self.running = False
            raise e

    def accept_clients(self):
        while self.running:
            client_socket, addr = self.comm.sock.accept()
            client = NetComm(addr[0], addr[1], client_socket)
            self.clients.append(client)
            threading.Thread(target=self.handle_client, args=(client,), daemon=True).start()

    
        
    def handle_client(self, client : NetComm):
        self.func(client)

    def stop(self):
        self.running = False
        self.server_socket.close()
        for client in self.clients:
            client.sock.close()
        log.warn("[NetServer] Server stopped")


class NetClient:
    def __init__(self, host='127.0.0.1', port=9000):
        self.comm = NetComm(host, port)
        self.running = False

    def connect(self):
        try:
            self.comm.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.comm.sock.connect((self.comm.host, self.comm.port))
            self.running = True
            log.success(f"[NetClient] Connection successful!")
        except Exception as e:
            log.error(f"[NetClient] Connection error!")
            self.running = False
            raise e
    
    def send_data(self, command : int, data : bytes):
        self.comm.send_packet(Packet(command.to_bytes(length=2, byteorder='big') + data))
        packet = self.comm.recv_packet()
        if int.from_bytes(packet.command, byteorder='big') == Command.ERROR:
            raise ValueError(f"[NetClient] Error from server: {packet.message.decode()}")
        return packet.data()[2:]

    def disconnect(self):
        self.running = False
        self.comm.send_packet(Packet(Command.EXIT.to_bytes(2, 'big'))) # the command to exit is 0
        self.comm.sock.close()
        log.warning("[NetClient] Disconnected")
