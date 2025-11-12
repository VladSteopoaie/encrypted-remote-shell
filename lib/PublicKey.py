import random
import math
from lib.Logger import logger as log
from Crypto.PublicKey import RSA as pycryptoRSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import random as pycryptoRandom
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

'''
This file contains code from:

**Cracking Codes with Python - An Introduction to Building and Breaking Ciphers** by Al Sweigart
January 2018, 416 pp.
ISBN-13:9781593278229

All codes (BSD Licensed) are available at https://nostarch.com/crackingcodes
'''

def prime_sieve(sieveSize):
    # Returns a list of prime numbers calculated using
    # the Sieve of Eratosthenes algorithm.

    sieve = [True] * sieveSize
    sieve[0] = False # Zero and one are not prime numbers.
    sieve[1] = False

    # Create the sieve:
    for i in range(2, int(math.sqrt(sieveSize)) + 1):
        pointer = i * 2
        while pointer < sieveSize:
            sieve[pointer] = False            
            pointer += i

    # Compile the list of primes:
    primes = []
    for i in range(sieveSize):
        if sieve[i] == True:
            primes.append(i)

    return primes

LOW_PRIMES = prime_sieve(100)

def rabin_miller(num):
    # Returns True if num is a prime number.
    if num % 2 == 0 or num < 2:
        return False # Rabin-Miller doesn't work on even integers.
    if num == 3:
        return True
    s = num - 1
    t = 0
    while s % 2 == 0:
        # Keep halving s until it is odd (and use t
        # to count how many times we halve s):
        s = s // 2
        t += 1
    for trials in range(5): # Try to falsify num's primality 5 times.
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1: # (This test does not apply if v is 1.)
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True

def is_prime(num):
    # Return True if num is a prime number. This function does a quicker
    # prime number check before calling rabin_miller().
    if (num < 2):
        return False # 0, 1, and negative numbers are not prime.
    # See if any of the low prime numbers can divide num:
    for prime in LOW_PRIMES:
        if (num == prime):
            return True
    for prime in LOW_PRIMES:
        if (num % prime == 0):
            return False
    # If all else fails, call rabin_miller() to determine if num is a prime:
    return rabin_miller(num)

def generate_large_prime(key_size=1024):
    # Return a random prime number that is key_size bits in size.
    i=0
    while True:
        num = random.randrange(2**(key_size-1), 2**(key_size))
        #print('random number', i, hex(num))
        i = i + 1
        if is_prime(num):
            # print('number of tries:', i)
            return num

class RSA:
    '''
    Class to manage RSA based encryption, decryption and signatures.
    '''
    def __init__(self):
        self.p = 0
        self.q = 0
        self.e = 0
        self.d = 0
        self.N = 0
        self.key_size = 0
        self.signer = None
        self.verifier = None

    # function from the book
    def generate(self, key_size : int):
        self.key_size = key_size

        # Step 1: Create two prime numbers, p and q. Calculate n = p * q.
        # log.debug('[RSA] Generating p & q primes...')
        self.p = generate_large_prime(key_size // 2)
        self.q = generate_large_prime(key_size // 2)
        self.N = self.p * self.q

        # Step 2: Create a number e that is relatively prime to (p-1)*(q-1):
        # log.debug('[RSA] Generating e that is relatively prime to (p-1)*(q-1)...')

        phi = (self.p-1)*(self.q-1)
        self.e = 65537

        # Step 3: Calculate d, the mod inverse of e:
        # log.debug('[RSA] Calculating d that is mod inverse of e...')
        
        self.d = pow(self.e, -1, phi)

        self.signer = pkcs1_15.new(pycryptoRSA.construct((self.N, self.e, self.d)))
        self.verifier = pkcs1_15.new(pycryptoRSA.construct((self.N, self.e)))

        publicKey = (self.N, self.e)
        privateKey = (self.N, self.d)
        return (publicKey, privateKey)
    
    def import_pub_key(self, pub_key : tuple):
        '''
        With this function we can import the public key shared by the peer and initializes the verifier.
        '''
        self.N, self.e = pub_key
        self.key_size = self.N.bit_length()
        self.verifier = pkcs1_15.new(pycryptoRSA.construct(pub_key))
    
    # this is not a secure encryption since I do not use any padding
    def encrypt(self, message : bytes) -> bytes:
        '''
        RSA encryption WITHOUT padding.

        Args:
            message (bytes): the byte array that will be encrypted.

        Returns:
            The ciphertext as a byte array.
        '''
        if self.N == 0 or self.e == 0:
            raise ValueError("[RSA] Public key not set!")
        
        message_int = int.from_bytes(message, byteorder='big')
        if message_int.bit_length() > self.key_size:
            raise ValueError(f"[RSA] Message larger than {self.key_size} bits!")
        ciphertext_int = pow(message_int, self.e, self.N)

        return ciphertext_int.to_bytes(length=self.key_size, byteorder='big')
    
    # does not consider any paddings
    def decrypt(self, ciphertext : bytes) -> bytes:
        '''
        RSA decryption WITHOUT padding.

        Args:
            ciphertext (bytes): the byte array to be decrypted

        Returns:
            The plaintext as a byte array.
        '''
        if self.N == 0 or self.d == 0:
            raise ValueError("[RSA] Private key not set!")
        
        ciphertext_int = int.from_bytes(ciphertext, byteorder='big')
        if ciphertext_int > self.N:
            raise ValueError(f"[RSA] Message larger than {self.key_size} bits!")
        message_int = pow(ciphertext_int, self.d, self.N)

        return message_int.to_bytes(length=self.key_size, byteorder='big')

    def sign(self, message : bytes) -> bytes:
        '''
        Performs RSA signing using the private key. It hashes the message with sha256
        and encrypts the hash.

        Args:
            message (bytes): the byte array which hash will be signed

        Returns:
            The signature of the message's hash as a byte array.
        '''
        if self.signer is None:
            raise ValueError("[RSA] Private key not set!")
        
        hash_msg = SHA256.new(message)
        signature = self.signer.sign(hash_msg)
        return signature
    
    def verify(self, message : bytes, signature : bytes) -> bool:
        '''
        Performs RSA verification of a signed message using the public key. It hashes the
        received message and decrypts the signature. If both outputs match the signature is valid.

        Args:
            message (bytes): the byte array to be verified.
            signature (bytes): the signature of the message received from the peer.

        Returns:
            True/False depending if the verification was successful or not.
        '''
        if self.verifier is None:
            raise ValueError("[RSA] Public key not set!")
        
        hash_msg = SHA256.new(message)
        try:
            self.verifier.verify(hash_msg, signature)
            return True
        except (ValueError, TypeError):
            return False

# the following class is just a wrapper for the pycryptodome RSA class
# I made it only for ease of implementation since it respects the 
# same function scheme as the previous class
class libRSA:
    def __init__(self):
        self.rsa = None
        self.cipher = None
        self.p = 0
        self.q = 0
        self.e = 0
        self.d = 0
        self.N = 0
        self.key_size = 0
        self.signer = None
        self.verifier = None

    def init_values(self, public_key=False):
        '''
        Function to initialize the pycryptodome used within this class considering the class values.

        Args:
            public_key (bool): specifies if only the public key related structures should be initialized
        '''
        self.e = self.rsa.e
        self.N = self.rsa.n
        self.verifier = pkcs1_15.new(pycryptoRSA.construct((self.N, self.e)))

        if public_key: # if only public key -> only encryption and signature verification will be prossible
            self.cipher = PKCS1_OAEP.new(self.rsa.publickey())
            return
        
        self.p = self.rsa.p
        self.q = self.rsa.q
        self.d = self.rsa.d
        self.signer = pkcs1_15.new(pycryptoRSA.construct((self.N, self.e, self.d)))
        self.cipher = PKCS1_OAEP.new(self.rsa)
        self.key_size = self.rsa.size_in_bits()

    def generate(self, key_size : int):
        self.rsa = pycryptoRSA.generate(key_size)
        self.init_values()

    def import_pub_key(self, pub_key : tuple):
        self.rsa = pycryptoRSA.construct(pub_key, consistency_check=True)
        self.init_values(public_key=True)

    def encrypt(self, message : bytes) -> bytes:
        if self.rsa is None:
            raise ValueError("[libRSA] Public key not set!")
        return self.cipher.encrypt(message)
    
    def decrypt(self, ciphertext : bytes) -> bytes:
        if self.rsa is None:
            raise ValueError("[libRSA] Private key not set!")
        return self.cipher.decrypt(ciphertext)

    def sign(self, message : bytes) -> bytes:
        if self.signer is None:
            raise ValueError("[RSA] Private key not set!")
        
        hash_msg = SHA256.new(message)
        signature = self.signer.sign(hash_msg)
        return signature
    
    def verify(self, message : bytes, signature : bytes) -> bool:
        if self.verifier is None:
            raise ValueError("[RSA] Public key not set!")
        
        hash_msg = SHA256.new(message)
        try:
            self.verifier.verify(hash_msg, signature)
            return True
        except (ValueError, TypeError):
            return False
    

class DHKE:
    '''
    Class to manage Diffie-Hellman Key Exchange.
    '''
    def __init__(self, p=None, g=None):
        self.p = p
        self.g = g
        self.private_key = None
        self.public_key = None
        self.secret = None
        self.key_size = 0 if p is None else p.bit_length()

    def generate(self):
        '''
        This function is meant to be called after the object initialization.
        It will generate a random private key between (2, p - 2) and it will compute the public key associated.
        '''
        if self.p is None or self.g is None:
            raise ValueError("p and g must be set before generating private key!")
        self.private_key = pycryptoRandom.StrongRandom().randint(2, self.p - 2)
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_secret(self, other_public_key : int):
        '''
        Computes the shared DHKE secret using the provided public key of the other party.

        Args:
            other_public_key (int): the public key of the peer

        Returns:
            The computed shared secret.
        '''
        if self.public_key is None or self.private_key is None:
            raise ValueError("Public and private keys must be set before computing shared secret!")
        self.secret = pow(other_public_key, self.private_key, self.p)
        return self.secret