import os, sys, argparse

# including the library directory in the path
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))  # project root
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from Crypto.Random import get_random_bytes
from lib.Communication import * # for NetComm, Packet, Command
from lib.PublicKey import * # for RSA, libRSA, DHKE
from lib.Symmetric import * # for AES, libAES
from lib.Logger import logger as log

# global variables
rsa = None
cipher = None 
dhke = None

def init():
    """
    Initialization function for the cryptography libraries.
    Determines which cryptography library to use based on server response.
    """
    global rsa, cipher

    lib_byte = client.send_data(Command.LIB, b'') # send a packet with the LIB command, no data needed
    if lib_byte == b'\x00': # \x00 indicates custom library
        log.info("Using custom cryptography library")
        rsa = RSA()
        cipher = AES()
    elif lib_byte == b'\x01': # \x01 indicates pycryptodome library
        log.info("Using pycryptodome cryptography library")
        rsa = libRSA()
        cipher = libAES()

def get_RSA_public_key(client : NetClient):
    """
    Function to get the RSA public key from the server.
    1. Sends a request to the server for its public key.
    2. Receives the public key components (N and e).
    3. Imports the public key into the RSA object.

    Args:
        client (NetClient): The network client instance to communicate with the server.
    """
    global rsa

    if rsa is None:
        raise ValueError("Cryptography libraries not initialized!")
    
    data = client.send_data(Command.RSA_PUB, b'') # send the RSA_PUB command to request public key, no data needed

    key_size = int.from_bytes(data[:4], byteorder='big') # first 4 bytes represent the key size
    N = int.from_bytes(data[4 : 4 + key_size // 8], byteorder='big') # next key_size // 8 bytes represent N
    e = int.from_bytes(data[4 + key_size // 8 : ], byteorder='big') # the rest of the bytes represent e
    rsa.import_pub_key((N, e))
    log.success("Retrieved RSA public key from server.")
    log.debug(f"Received public key (size: {key_size}):\nN: {N}\ne: {e}\n")

def perform_RSA_key_exchange(client : NetClient):
    """
    Function to perform RSA key exchange with the server.
    1. Retrieves the server's RSA public key.
    2. Generates a random AES key.
    3. Encrypts the AES key using the server's RSA public key.
    4. Sends the encrypted AES key to the server.

    Args:
        client (NetClient): The network client instance to communicate with the server.
    """

    global rsa, cipher
    if rsa is None or cipher is None:
        raise ValueError("Cryptography libraries not initialized!")
    
    try:
        get_RSA_public_key(client)
        
        cipher.change_key(get_random_bytes(16)) # generate a random AES key of 16 bytes and set it in the cipher
        enc_message = rsa.encrypt(cipher.key) # encrypt the AES key using the server's RSA public key
        client.send_data(Command.RSA_KE, enc_message) # now we perform the RSA key exchange
        
        # if we reach here, the key exchange was successful
        log.success("RSA key exchange successful!")
        log.debug(f"AES key sent to server: {cipher.key}\n")
    except Exception as e:
        raise e

def perform_DHKE(client : NetClient):
    """
    Function to perform Diffie-Hellman Key Exchange (DHKE) with the server.
    1. Sends a DHKE request to the server.
    2. Receives the server's DH parameters (p, g, and public key).
    3. Generates the client's DH key pair.
    4. Computes the shared secret using the server's public key.
    5. Sends the client's public key to the server.
    6. Derives the AES key from the shared secret and updates the cipher.
    
    Args:
        client (NetClient): The network client instance to communicate with the server.
    """

    global dhke, cipher
    if cipher is None:
        raise ValueError("Cryptography libraries not initialized!")
    
    try:
        data = client.send_data(Command.DHKE, b'') # sends the DHKE command, no data needed

        key_size = int.from_bytes(data[:4], byteorder='big') # first 4 bytes represent the key size
        key_size_bytes = key_size // 8
        p = int.from_bytes(data[4 : 4 + key_size_bytes], byteorder='big') # next key_size // 8 bytes represent server's public key
        g = int.from_bytes(data[4 + key_size_bytes : 4 + 2 * key_size_bytes], byteorder='big') # the next key_size // 8 bytes represent g
        server_public_key = int.from_bytes(data[4 + 2 * key_size_bytes : ], byteorder='big') # the rest of the bytes represent the public key of the server
        
        # instantiate DHKE and generate keys
        dhke = DHKE(p, g)
        dhke.generate()

        # compute shared secret with the server's public key
        dhke.compute_secret(server_public_key)
        log.debug(f"DHKE parameters (size: {key_size}):\np: {p}\ng: {g}\nserver_public_key: {server_public_key}\nclient_public_key: {dhke.public_key}\nsecret: {dhke.secret}\n")

        # send our public key to the server
        enc_message = dhke.public_key.to_bytes(key_size_bytes, byteorder='big')
        client.send_data(Command.DHKE, enc_message)

        # if we reach here, the DHKE was successful

        # derive AES key from the shared secret (for simplicity, we take the first 16 bytes of the shared secret)
        aes_key = dhke.secret.to_bytes(key_size_bytes, byteorder='big')[:16]
        cipher.change_key(aes_key)
        log.success("DHKE successful!")
        log.debug(f"Derived AES key from shared secret: {aes_key}\n")
    except Exception as e:
        log.error(f"DHKE failed: {str(e)}")
        raise e

if __name__ == "__main__":
    # initialize argument parser
    parser = argparse.ArgumentParser(
        prog='Client',
        description='Client for encrypted remote shell.'
    )

    """
    Usage:
        python client.py [-h] -p PORT -a ADDRESS -e {DHKE,RSA}

        Client for encrypted remote shell.

        options:
        -h, --help                  show this help message and exit
        -p, --port PORT             Port to connect to
        -a, --address ADDRESS       Address of the server
        -e, --exchange {DHKE,RSA}   Key exchange algorithm to be used
    """
    parser.add_argument('-p', '--port', required=True, help="Port to connect to", type=int)
    parser.add_argument('-a', '--address', required=True, help="Address of the server", type=str)
    parser.add_argument('-e', '--exchange', required=True, help="Key exchange algorithm to be used", type=str, default='DHKE', choices=['DHKE', 'RSA'])
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose logging")
    args = parser.parse_args()
    
    # set the logging level
    if args.verbose:
        log.remove()
        log.add(sys.stdout, colorize=True, format="<level>{level.icon}</level> <level>{message}</level>", level="DEBUG")

    client = NetClient(args.address, args.port)
    try:
        # starting connection
        client.connect()
    except Exception as e:
        log.error(f"Could not connect to server: {e}")
        sys.exit(1)

    # initializing cryptography libraries
    init()
    # performing key exchange
    if args.exchange == 'DHKE':
        perform_DHKE(client)
    elif args.exchange == 'RSA':
        perform_RSA_key_exchange(client)

    # main loop to send commands to the server
    while True:
        command = input("Enter command to execute on server ('exit', 'getfile' or any linux command): ")
        
        try:
            if command.lower() == 'exit': # if exit command, disconnect and break the loop 
                client.disconnect()
                break
            elif command.lower() == 'getfile': # if getfile command, request a file from the server
                # file name should be provided by the user
                filename = input("Enter filename to retrieve from server: ")

                # if we performed DHKE, we need to get the RSA public key for signature verification
                if rsa.N == 0 or rsa.e == 0:
                    get_RSA_public_key(client)

                # send the encrypted filename to the server
                enc_filename = cipher.encrypt(cipher.pad(filename.encode()))
                enc_data = client.send_data(Command.FILE, enc_filename) # send the FILE command to request the file
                
                # decrypt the received data
                data = cipher.unpad(cipher.decrypt(enc_data))

                data_len = int.from_bytes(data[:4], byteorder='big') # first 4 bytes represent the length of the file data
                file_data = data[4: 4 + data_len] # next data_len bytes represent the file data
                signature = data[4 + data_len : ] # the rest of the bytes represent the signature
                log.debug(f"Received signature: {signature}\n")
                # verify the signature
                if not rsa.verify(file_data, signature):
                    log.error("Signature verification failed! The file may be tampered with.")
                    continue

                log.success("Signature verified successfully.")
                with open(f"{ROOT}/src/client/download/{os.path.basename(filename)}", "wb") as f:
                    f.write(file_data)
                log.success(f"File '{filename}' downloaded successfully as 'download/{os.path.basename(filename)}'")
            else: # execute any other command
                # encrypt the command and send it to the server
                enc_command = cipher.encrypt(cipher.pad(command.encode()))
                data = client.send_data(Command.EXEC, enc_command) # send the EXEC command to execute the command
                
                # decrypt and print the result
                result = cipher.unpad(cipher.decrypt(data)).decode()
                print(result + "\n")
        except Exception as e:
            log.error(str(e))
