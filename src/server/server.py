import os, sys, argparse

# including the library directory in the path
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))  # project root
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


from lib.Communication import * # for NetComm, Packet, Command
from lib.PublicKey import * # for RSA, libRSA, DHKE
from lib.Simetric import * # for AES, libAES
from lib.Logger import logger as log

# global variables
dhke = None
rsa = None
cipher = None


def init(lib : str):
    """
    Initialization function for the cryptography libraries.

    Args:
        lib (str): The cryptography library to use ('pycryptodome' or 'custom').
    """
    global rsa, cipher, dhke
    
    # initialize RSA and AES based on the chosen library
    if lib == 'pycryptodome':
        rsa = libRSA()
        cipher = libAES()
    elif lib == 'custom':
        rsa = RSA()
        cipher = AES()
    else:
        raise ValueError("Invalid library choice! Choose 'pycryptodome' or 'custom'")

    rsa.generate(2048)

    # initialize DHKE with predefined 2048-bit prime and generator
    # the standard value from RFC 3526 for 2048-bit MODP Group (https://www.rfc-editor.org/rfc/rfc3526#page-3)
    dhke_2048_prime = int("""
        FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
        29024E088A67CC74020BBEA63B139B22514A08798E3404DD
        EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
        E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
        EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D
        C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F
        83655D23DCA3AD961C62F356208552BB9ED529077096966D
        670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
        E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9
        DE2BCBF6955817183995497CEA956AE515D2261898FA0510
        15728E5A8AACAA68FFFFFFFFFFFFFFFF
    """.replace('\n', ''), 16)
    dhke = DHKE(p=dhke_2048_prime, g=2)
    dhke.generate()


def handle_client(self, client : NetComm):
    """
    The client handle function that gets executed whenever a client connects. It
    contains all the server-side logic for handling commands from the client.

    Types of commands:
    - EXIT: Close the connection.
    - LIB: Send back the cryptography library being used, so the client will know what to use.
    - RSA_PUB: Send the RSA public key to the client.
    - RSA_KE: Perform RSA key exchange with the client (the client sends an AES key encrypted with the server's RSA public key).
    - DHKE: Perform Diffie-Hellman Key Exchange with the client.
    - EXEC: Execute a command sent by the client and return the result (encrypted end-to-end with the AES key if provided).
    - FILE: Transfer a file to the client (the server also signs the file with it's RSA private key).

    Args:
        self (NetServer): The NetServer instance (the function will be passed as a parameter).
        client (NetComm): The connected client communication object. 
    """
    global rsa, cipher, dhke

    log.info(f"Client connected: {client}")
    running = True

    while running:
        packet = client.recv_packet() # blocking call, waits for a packet from the client
        command = packet.command

        match int.from_bytes(command, byteorder='big'): # checks which command was sent
            
            case Command.EXIT: # this command is to close the connection 
                log.info(f"Client disconnected: {client}")
                client.sock.close()
                self.clients.remove(client)
                running = False
                continue
            
            case Command.LIB: # this command is to inform the client which library to use
                # only 1 byte to indicate which library is used (\x01 -> pycryptodome or \x00 custom)
                message = (b'\x01' if isinstance(rsa, libRSA) else b'\x00') 
            
            case Command.RSA_PUB: # this command is to send the RSA public key to the client
                message = rsa.key_size.to_bytes(4, byteorder='big') # first append the key size (4 bytes)
                message += rsa.N.to_bytes(rsa.key_size // 8, byteorder='big') # then append N (key_size // 8 bytes)
                message += rsa.e.to_bytes(rsa.key_size // 8, byteorder='big') # then append e (key_size // 8 bytes)
            
            case Command.RSA_KE: # this command is to perform RSA key exchange with the client
                try:
                    enc_message = packet.message
                    # try to decrypt the message using RSA private key and striping leading zeros
                    AES_key = rsa.decrypt(enc_message).lstrip(b'\x00')
                    # set the AES key for further communication
                    cipher.change_key(AES_key)
                    # if decryption is successful, send back success message
                    message = b'Success'
                    log.success(f"RSA key exchange successful!")
                except Exception as e:
                    log.error(f"RSA key exchange error: {e}")
                    # if decryption fails, send back the error message
                    message = str(e).encode()
                    command = int.to_bytes(Command.ERROR, length=2, byteorder='big') # error command
                    running = False

            case Command.DHKE: # this command is to perform DHKE with the client
                key_size_bytes = dhke.key_size // 8 # number of bytes for the key size
                message = dhke.key_size.to_bytes(4, byteorder='big') # first append the key size (4 bytes)
                message += dhke.p.to_bytes(key_size_bytes, byteorder='big') # then append p (key_size // 8 bytes)
                message += dhke.g.to_bytes(key_size_bytes, byteorder='big') # then append g (key_size // 8 bytes)
                message += dhke.public_key.to_bytes(key_size_bytes, byteorder='big') # then append server's public key (key_size // 8 bytes)
                
                # send the DHKE parameters to the client and wait for the client's public key
                client.send_packet(Packet(command + message))
                packet = client.recv_packet()

                try:
                    other_public_key = int.from_bytes(packet.message, byteorder='big')
                    dhke.compute_secret(other_public_key)
                    # the first 16 bytes of the shared secret is used as the AES key for further communication
                    cipher.change_key(dhke.secret.to_bytes(key_size_bytes, byteorder='big')[:16])
                    # send back success message
                    message = b'Success'
                    log.success(f"DHKE successful!")
                except Exception as e:
                    log.error(f"DHKE error: {e}")
                    message = str(e).encode()
                    command = int.to_bytes(Command.ERROR, length=2, byteorder='big') # error command
                    running = False

            case Command.EXEC: # execute a command and return the result. Cipher text only
                try:
                    # decrypt the command using AES key
                    exe = cipher.unpad(cipher.decrypt(packet.message)).decode()
                    log.info(f"Executing command: {exe}")
                    result = os.popen(exe).read() # execute the command and get the result
                    if result == '':
                        result = 'Command executed successfully with no output.\n'
                    log.info(f"Command output:\n{result}")
                except Exception as e:
                    log.error(f"Error executing command: {e}")
                    result = str(e)
                    command = int.to_bytes(Command.ERROR, length=2, byteorder='big') # error command
                finally:
                    # send back the encrypted result
                    message = cipher.encrypt(cipher.pad(result.encode()))

            case Command.FILE: # transfer a file and it's signature to the client
                try:
                    # decrypt the filename using AES key
                    filename = cipher.unpad(cipher.decrypt(packet.message)).decode()
                    log.info(f"Client requested file: {filename}")
                    # check if file exists
                    if not os.path.isfile(filename):
                        raise ValueError(f"File '{filename}' not found.")
                    
                    file_data = open(filename, "rb").read()
                    data_len = len(file_data).to_bytes(4, byteorder='big')
                    signature = rsa.sign(file_data)
                    # append the data length (4 bytes), file data (data length bytes) and signature
                    message = data_len + file_data + signature
                    log.info(f"File '{filename}' sent successfully.")
                except Exception as e:
                    log.error(f"Error sending file: {e}")
                    message = str(e).encode()
                    command = int.to_bytes(Command.ERROR, length=2, byteorder='big') # error command
                finally:
                    message = cipher.encrypt(cipher.pad(message))

            case _:
                message = "Unknown command".encode()

        client.send_packet(Packet(command + message))

if __name__ == "__main__":
    # initialize argument parser
    parser = argparse.ArgumentParser(
        prog='Server',
        description='Server for encrypted remote shell.'
    )

    """
        Usage:

        python server.py [-h] -p PORT [-a ADDRESS] -l {pycryptodome,custom}

        Server for encrypted remote shell.

        options:
        -h, --help                          show this help message and exit
        -p, --port PORT                     Port to listen on
        -a, --address ADDRESS               Address of the server
        -l, --lib {pycryptodome,custom}     Cryptography library to use (pycryptodome or custom)
    """
    parser.add_argument('-p', '--port', required=True, help="Port to listen on", type=int)
    parser.add_argument('-a', '--address', required=False, default='127.0.0.1', help="Address of the server", type=str)
    parser.add_argument('-l', '--lib', required=True, help="Cryptography library to use (pycryptodome or custom)", type=str, default='pycryptodome', choices=['pycryptodome', 'custom'])
    args = parser.parse_args()

    try:
        # start the server
        init(args.lib)
        server = NetServer(handle_client, args.address, args.port)
        server.start()
    except Exception as e:
        log.error(f"Could not start server: {e}")
        sys.exit(1)