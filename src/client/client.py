import os, sys, argparse
from Crypto.Random import get_random_bytes

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))  # project root
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from lib.Communication import * #as comm
from lib.PublicKey import * 
from lib.Simetric import *
# from lib.Logger import logger as log

# this will be initialised at runtime
rsa = None
cipher = None 
dhke = None

def init():
    global rsa, cipher

    lib_byte = client.send_data(1, b'') # the command to indicate which library to use is 0, no data needed
    if lib_byte == b'\x00':
        log.info("Using custom cryptography library")
        rsa = RSA()
        cipher = AES()
    elif lib_byte == b'\x01':
        log.info("Using pycryptodome cryptography library")
        rsa = libRSA()
        cipher = libAES()

def perform_RSA_key_exchange(client : NetClient):
    global rsa, cipher

    if rsa is None or cipher is None:
        raise ValueError("Cryptography libraries not initialized!")
    
    data = client.send_data(2, b'') # the command to perform RSA key exchange is 0, no data needed
    key_size = int.from_bytes(data[:4], byteorder='big') # first 4 bytes represent the key size
    N = int.from_bytes(data[4 : 4 + key_size // 8], byteorder='big') # next key_size // 8 bytes represent N
    e = int.from_bytes(data[4 + key_size // 8 : ], byteorder='big') # the rest of the bytes represent e
    rsa.import_pub_key((N, e))
    log.info(f"Received public key: (N={N}, e={e})")
    cipher.change_key(get_random_bytes(16)) # generate a random AES key of 16 bytes
    enc_message = rsa.encrypt(cipher.key)
    response = client.send_data(2, enc_message)

    if response == b'Success':
        log.success("RSA key exchange successful!")
    else:
        log.error(f"RSA key exchange failed: {response.decode()}")


def perform_DHKE(client : NetClient):
    global dhke, cipher

    if cipher is None:
        raise ValueError("Cryptography libraries not initialized!")
    
    data = client.send_data(3, b'') # the command to perform DHKE is 3, no data needed
    key_size = int.from_bytes(data[:4], byteorder='big') # first 4 bytes represent the key size
    key_size_bytes = key_size // 8
    p = int.from_bytes(data[4 : 4 + key_size_bytes], byteorder='big') # next key_size // 8 bytes represent server's public key
    g = int.from_bytes(data[4 + key_size_bytes : 4 + 2 * key_size_bytes], byteorder='big') # the next key_size // 8 bytes represent g
    server_public_key = int.from_bytes(data[4 + 2 * key_size_bytes : ], byteorder='big') # the rest of the bytes represent the public key of the server
    dhke = DHKE(p, g)
    dhke.generate()
    dhke.compute_secret(server_public_key)

    client_public_key = dhke.public_key
    enc_message = client_public_key.to_bytes(key_size_bytes, byteorder='big')
    response = client.send_data(3, enc_message)

    if response == b'Success':
        # derive AES key from the shared secret (for simplicity, we take the first 16 bytes of the shared secret)
        aes_key = dhke.secret.to_bytes(key_size_bytes, byteorder='big')[:16]
        # log.info(f"AES key derived from shared secret: {aes_key.hex()}")
        cipher.change_key(aes_key)
        log.success("DHKE successful!")
        # log.info(f"AES key derived from shared secret: {aes_key.hex()}")
    else:
        log.error(f"DHKE failed: {response.decode()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='Client',
        description='Client for encrypted remote shell')

    parser.add_argument('-p', '--port', required=True, help="Port to connect to", type=int)
    parser.add_argument('-a', '--address', required=True, help="Address of the server", type=str)
    parser.add_argument('-e', '--exchange', required=True, help="Key exchange algorithm to be used", type=str, default='DHKE', choices=['DHKE', 'RSA'])

    args = parser.parse_args()
    client = NetClient(args.address, args.port)
    try:
        client.connect()
    except Exception as e:
        log.error(f"Could not connect to server: {e}")
        sys.exit(1)

    init()
    if args.exchange == 'DHKE':
        perform_DHKE(client)
    elif args.exchange == 'RSA':
        perform_RSA_key_exchange(client)

    while True:
        command = input("Enter command to execute on server (or 'exit' to quit): ")
        if command.lower() == 'exit':
            client.disconnect()
            break
        enc_command = cipher.encrypt(cipher.pad(command.encode()))
        data = client.send_data(4, enc_command) # the command to execute a command is 2

        try:
            result = cipher.unpad(cipher.decrypt(data)).decode()
            print(f"Command output:\n{result}")
        except Exception as e:
            log.error(f"Error decrypting command output: {e}")
