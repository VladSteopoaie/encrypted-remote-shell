import os, sys, argparse

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))  # project root
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


import lib.Communication as comm
from lib.PublicKey import *
from lib.Simetric import *
from lib.Logger import logger as log

dhke = None
rsa = None
cipher = None

def init(lib):
    global rsa, cipher, dhke
    
    if lib == 'pycryptodome':
        rsa = libRSA()
        cipher = libAES()
    elif lib == 'custom':
        rsa = RSA()
        cipher = AES()
    else:
        raise ValueError("Invalid library choice! Choose 'pycryptodome' or 'custom'")

    rsa.generate(2048)

    # the standard value from RFC 3526 for 2048-bit MODP Group (https://www.rfc-editor.org/rfc/rfc3526#page-3)
    dhke_2048_prime = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)

    dhke = DHKE(p=dhke_2048_prime, g=2)
    dhke.generate()


# implementation of the server
def handle_client(self, client : comm.NetComm):
    global rsa, cipher, dhke

    log.info(f"Client connected: {client}")

    while True:
        packet = client.recv_packet()
        command = packet.command
        match int.from_bytes(command, byteorder='big'):
            case 0: # this command is to close the connection 
                log.info(f"Client disconnected: {client}")
                client.sock.close()
                self.clients.remove(client)
                break
            case 1:
                message = (b'\x01' if isinstance(rsa, libRSA) else b'\x00') # 1 byte to indicate which library is used (\x01 -> pycryptodome or \x00 custom)
                # client.send_packet(comm.Packet(command + message))
            case 2: # this command is to perform RSA key exchange with the client
                # sending the public key as a byte array: first key_size // 8 bytes which are N 
                # and the next key_size // 8 bytes wich represent e
                message = rsa.key_size.to_bytes(4, byteorder='big') 
                message += rsa.N.to_bytes(rsa.key_size // 8, byteorder='big') 
                message += rsa.e.to_bytes(rsa.key_size // 8, byteorder='big')
                client.send_packet(comm.Packet(command + message))
                packet = client.recv_packet()
                # response = b''
                try:
                    enc_message = packet.message
                    AES_key = rsa.decrypt(enc_message).lstrip(b'\x00')
                    cipher.change_key(AES_key)
                    message = b'Success'
                    log.success(f"RSA key exchange successful!")
                except Exception as e:
                    log.error(f"RSA key exchange error: {e}")
                    message = str(e).encode()
                    
                # client.send_packet(comm.Packet(packet.command + response))
                # if response != b'Success':
                #     break
            case 3: # this command is to perform DHKE with the client
                command = packet.command
                key_size_bytes = dhke.key_size // 8
                message = dhke.key_size.to_bytes(4, byteorder='big') 
                message += dhke.p.to_bytes(key_size_bytes, byteorder='big') 
                message += dhke.g.to_bytes(key_size_bytes, byteorder='big') 
                message += dhke.public_key.to_bytes(key_size_bytes, byteorder='big')
                client.send_packet(comm.Packet(command + message))
                packet = client.recv_packet()
                try:
                    other_public_key = int.from_bytes(packet.message, byteorder='big')
                    dhke.compute_secret(other_public_key)
                    # log.info(f"Computed shared secret: {dhke.secret}")
                    aes_key = dhke.secret.to_bytes(key_size_bytes, byteorder='big')[:16]
                    # log.info(f"AES key derived from shared secret: {aes_key.hex()}")
                    cipher.change_key(dhke.secret.to_bytes(key_size_bytes, byteorder='big')[:16]) # use the first 16 bytes of the shared secret as AES key
                    message = b'Success'
                    log.success(f"DHKE successful!")
                except Exception as e:
                    log.error(f"DHKE error: {e}")
                    message = str(e).encode()
            case 4: # execute a command and return the result. Cipher text only
                try:
                    exe = cipher.unpad(cipher.decrypt(packet.message)).decode()
                    log.info(f"Executing command: {exe}")
                    result = os.popen(exe).read()
                    if result == '':
                        result = 'Command executed successfully with no output.\n'
                    log.info(f"Command output: {result}")
                except Exception as e:
                    result = str(e)
                    log.error(f"Error executing command: {e}")
                message = cipher.encrypt(cipher.pad(result.encode()))
                # client.send_packet(comm.Packet(command + enc_result))
            case _:
                command = packet.command
                message = "Unknown command".encode()

        client.send_packet(comm.Packet(command + message))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='Server',
        description='Server for encrypted remote shell')

    parser.add_argument('-p', '--port', required=True, help="Port to listen on", type=int)
    parser.add_argument('-a', '--address', required=False, default='127.0.0.1', help="Address of the server", type=str)
    parser.add_argument('-l', '--lib', required=True, help="Cryptography library to use (pycryptodome or custom)", type=str, default='pycryptodome', choices=['pycryptodome', 'custom'])
    
    args = parser.parse_args()

    try:
        init(args.lib)
        server = comm.NetServer(handle_client, args.address, args.port)
        server.start()
    except Exception as e:
        log.error(f"Could not start server: {e}")
        sys.exit(1)