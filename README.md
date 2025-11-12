# encrypted-remote-shell

## Table of contents <!-- omit in toc -->
- [Project structure](#project-structure)
- [Installation \& Usage](#installation--usage)
- [Overview](#overview)
- [Implementation](#implementation)
  - [Communication](#communication)
  - [Symmetric Cryptography](#symmetric-cryptography)
  - [Asymmetric Cryptography](#asymmetric-cryptography)
  - [Server](#server)
  - [Client](#client)

## Project structure
```
├── lib/
│   ├── Communication.py
│   ├── Logger.py
│   ├── PublicKey.py
│   └── Symmetric.py
└── src/
    ├── client
    │   ├── client.py
    │   └── download/
    └── server
        └── server.py
```

## Installation & Usage

```sh
# create a python environment and activate it
python -m venv venv
source venv/bin/activate # for linux
# ./venv/bin/Activate.ps1 # for Windows

# get the repository
git clone https://github.com/VladSteopoaie/encrypted-remote-shell
cd encrypted-remote-shell

# install requirements
pip install -r requirements.txt

# ready to use, see the help pages of the server and client scripts
python src/server/server.py -h
python src/client/client.py -h
```

Check [client usage](#client) and [server usage](#server) for specific examples.

## Overview

**Summary:**

This project implements a simple client-server architecture for a remote command execution program (like SSH). It implements symmetric cryptography (AES) to create a secure communication channel, and asymmetric cryptography (RSA) and Diffie-Hellman (DHKE) for key exchange.

**Server:**

The server provides a network interface for communicating with the client. It cannot perform actions unless the communication is encrypted. <br> 
To encrypt communication the server generates the RSA key pair and DHKE parameters and can share the public keys with the clients. The server receives the AES key in a secure way and the communication is encrypted using ECB mode of operation. <br>
After the secure communication channel is established, the client can send commands to the server and it will execute them and return the response. The server also provides the functionality to download a file using cryptographic signatures with RSA.

**Client:**

The client can access the server's network interface and retrieve the public key (for RSA or DHKE) and sends a generated AES key using the public key. <br>
After the communication channel is establish the client can send commands and download files. It can also verify a file’s signature using the server’s public key.

## Implementation

The communication is implemented using some helpful classes defined in the files below. I will go through each class and explain its use, for more details check the files and the comments.

### Communication
File location: [`lib/Communication.py`](./lib/Communication.py)

**Command Enum:**

For the communication between the client and server rules must be defined to specify which operations can be performed. To do that I created a `Command` enum that contains an ID for each command available.

``` python
EXIT = 0 # for closing the connection
LIB = 1 # for choosing which library should be used
RSA_PUB = 2 # for requesting the RSA public key
RSA_KE = 3 # for performing RSA key exchange
DHKE = 4 # for Diffe-Hellman key exchange
EXEC = 5 # for executing a command
FILE = 6 # for downloading a file
ERROR = 7 # for sending an error message
```

Cryptography with RSA and AES are implemented in two ways (one custom implementation, and one implementation using `pycryptodome`) and each implementation has some details that make them incompatible with one another, this is why we need to specify the `LIB` command so the client will use the appropriate implementation.

**Packet Class:**

The `Packet` class is a simple python class to make working with network buffers more intuitive. It treats a byte stream as follows:
- first 2 bytes represent the command
- the rest of the bytes represent the message

**NetComm Class:**

This is a class designed to abstract the network communication with sockets. Communication can be performed using the `recv_packet()` and `send_packet()` and yes it uses the `Packet` class by default.

**NetServer Class:**

This class implements most of the generic network features a server would need. It binds to a port, then starts listening for and accepting client connections (uses the methods `start()` and `accept_clients()`).

For each accepted client it creates a `NetComm` object and creates a thread that will handle the client connection using `handle_connection()`.

`handle_connection()` is not defined in the class and a user should define it outside the class and pass it as an argument when creating a `NetServer` object, the logic within that function is up to the user.

Graceful stopping is also provided through signal management (`handle_sigint()`) and the `stop()` function, which closes all active client connections and the listening socket.

**NetClient Class:**

The `NetClient` class provides a minimalistic interface to be used by clients. It abstracts away the socket connection / closing (`connect()`, `disconnect()`), data transmission (`send_data()`).

### Symmetric Cryptography
File location: [`lib/Symmetric.py`](./lib/Symmetric.py)

This file contains two classes `AES` and `libAES`. The `libAES` class is just a wrapper class for the `pycryptodome`'s `Crypto.Cipher.AES` class in `MODE_ECB`. The custom implementation of the algorithm is in the other class which can be studied in detail directly from the source code.

Both classes provide an interface for users:
- `change_key()` - allows you to provide a key or change the current key that the class is using
- `pad()`, `unpad()` - functions that manage the padding of data (the padding scheme used is the default padding scheme from `pycryptodome`)
- `encrypt()`, `decrypt()` - encrypt/decrypt a stream of bytes in ECB mode

### Asymmetric Cryptography
File location: [`lib/PublicKey.py`](./lib/PublicKey.py)

In this file are defined three classes `RSA`, `libRSA` and `DHKE`, and some other utility functions used within the classes: functions related to generating and checking prime numbers.

As with symmetric cryptography, the `libRSA` class is a wrapper for of the `pycryptodome`'s `Crypto.PublicKey.RSA` class and the `RSA` class contains the custom implementation of the algorithm (besides the signature, that is done using `pycryptodome` as well). `DHKE` is a simple class that helps with storing DHKE parameters and manages the logic required by the algorithm.

`libRSA` and `RSA` provide the next interface for the users:
- `generate()` - generate the prime integers $p$ and $q$ and computes the RSA parameters
- `import_pub_key()` - imports a public key (if you need only for encryption or verifying signatures)
- `encrypt()`, `decrypt()` - performs the algorithm on the data provided
- `sign()`, `verify()` - uses RSA to sign messages (using the private key) and verify them (using the public key)

`DHKE` provides the following interface:
- `generate()` - generates a random private key and computes the public key associated
- `compute_secret()` - calculates the shared secret

### Server
File location: [`src/server/server.py`](./src/server/server.py)

**Overview:**

This is the file that contains the server logic. The server is defined as an instance of the `NetServer` class which receives as a parameter the function `handle_client()` which defines how each client communication will be processed.

The `handle_client()` function defines how each command is processed by the server (see [Communication](#communication)
). It implements the cryptographic protocols and handles possible errors.

Within this file it's defined the initialization of the cryptographic protocols as well, see the function `init()`.

**Usage:**

Usage menu:
```
usage: Server [-h] -p PORT [-a ADDRESS] -l {pycryptodome,custom} [-v]

Server for encrypted remote shell.

options:
  -h, --help            show this help message and exit
  -p, --port PORT       Port to listen on
  -a, --address ADDRESS
                        Address of the server
  -l, --lib {pycryptodome,custom}
                        Cryptography library to use (pycryptodome or custom)
  -v, --verbose         Enable verbose logging
```

Example:
```sh
# I assume the python environment is already activated

# starting the server on 127.0.0.1:5000 using the pycryptodome implementation with DEBUG messages
python src/server/server.py --port 5000 --lib pycryptodome --verbose

# starting the server on 0.0.0.0:1337 using the custom implementation without DEBUG messages
python src/server/server.py -a 0.0.0.0 -p 1337 -l custom
```

### Client
File location: [`src/client/client.py`](./src/client/client.py)

**Overview:**

`client.py` defines the client's logic. It provides a user with a minimalistic interface in which they can type their commands that will be sent to the server. Available commands: `getfile` which lets the user download a file from the server (the file will be cryptographically signed with the RSA private key to ensure it was not tampered with and it will be stored in the folder `src/client/download/`), and any other generic linux commands (depends on what the server is able to execute).

The key exchange is performed automatically when connecting to a server and, if successful, the communication that follows will be encrypted with `AES-128 ECB`.

**Usage:**

Usage menu:
```
usage: Client [-h] -p PORT -a ADDRESS -e {DHKE,RSA} [-v]

Client for encrypted remote shell.

options:
  -h, --help            show this help message and exit
  -p, --port PORT       Port to connect to
  -a, --address ADDRESS
                        Address of the server
  -e, --exchange {DHKE,RSA}
                        Key exchange algorithm to be used
  -v, --verbose         Enable verbose logging
```

Example:
```sh
# I assume the python environment is activated

# connects to a server listening on localhost:1337 using the RSA as a key exchange protocol, DEBUG messages will be shown
python src/client/client.py --address 127.0.0.1 --port 1337 --exchange RSA --verbose

# connects to a server listening on 192.168.200.98:1337 using the Diffie-Hellman key exchange protocol, DEBUG messages are off
python src/client/client.py -a 192.168.200.98 -p 1337 -e DHKE
```