import random
import math
from lib.Logger import logger as log
from Crypto.PublicKey import RSA as pycryptoRSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import random as pycryptoRandom

#######################
### Code form class ###
#######################

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

################
### New code ###
################

class RSA:
    def __init__(self):
        self.p = 0
        self.q = 0
        self.e = 0
        self.d = 0
        self.N = 0
        self.key_size = 0

    # code from class
    def generate(self, key_size : int):
        self.key_size = key_size

        # Step 1: Create two prime numbers, p and q. Calculate n = p * q.
        log.info('[RSA] Generating p & q primes...')
        self.p = generate_large_prime(key_size // 2)
        self.q = generate_large_prime(key_size // 2)
        self.N = self.p * self.q

        # Step 2: Create a number e that is relatively prime to (p-1)*(q-1):
        log.info('[RSA] Generating e that is relatively prime to (p-1)*(q-1)...')

        phi = (self.p-1)*(self.q-1)
        self.e = 65537

        # Step 3: Calculate d, the mod inverse of e:
        log.info('[RSA] Calculating d that is mod inverse of e...')
        
        self.d = pow(self.e, -1, phi)

        publicKey = (self.N, self.e)
        privateKey = (self.N, self.d)

        return (publicKey, privateKey)
    
    def import_pub_key(self, pub_key : tuple):
        self.N, self.e = pub_key
        self.key_size = self.N.bit_length()
    
    # this is not a secure encryption since I do not use any padding
    def encrypt(self, message : bytes) -> bytes:
        if self.N == 0 or self.e == 0:
            raise ValueError("[RSA] Public key not set!")
        
        message_int = int.from_bytes(message, byteorder='big')
        if message_int.bit_length() > self.key_size:
            raise ValueError(f"[RSA] Message larger than {self.key_size} bits!")
        ciphertext_int = pow(message_int, self.e, self.N)
        # byte_length = (ciphertext_int.bit_length() + 7) // 8
        return ciphertext_int.to_bytes(length=self.key_size, byteorder='big')
        # return ciphertext_int.to_bytes(length=byte_length, byteorder='big')
    
    # does not consider any paddings
    def decrypt(self, ciphertext : bytes) -> bytes:
        if self.N == 0 or self.d == 0:
            raise ValueError("[RSA] Private key not set!")
        
        ciphertext_int = int.from_bytes(ciphertext, byteorder='big')
        if ciphertext_int > self.N:
            raise ValueError(f"[RSA] Message larger than {self.key_size} bits!")
        message_int = pow(ciphertext_int, self.d, self.N)
        # byte_length = (message_int.bit_length() + 7) // 8
        return message_int.to_bytes(length=self.key_size, byteorder='big')
        # return message_int.to_bytes(length=byte_length, byteorder='big')

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

    def init_values(self, public_key=False):
        self.e = self.rsa.e
        self.N = self.rsa.n
        
        if public_key:
            self.cipher = PKCS1_OAEP.new(self.rsa.publickey())
            return
        
        self.p = self.rsa.p
        self.q = self.rsa.q
        self.d = self.rsa.d
        self.cipher = PKCS1_OAEP.new(self.rsa)
        self.key_size = self.rsa.size_in_bits()

    # code from class
    def generate(self, key_size : int):
        self.rsa = pycryptoRSA.generate(key_size)
        self.init_values()

    def import_pub_key(self, pub_key : tuple):
        self.rsa = pycryptoRSA.construct(pub_key, consistency_check=True)
        self.init_values(public_key=True)

    # this is not a secure encryption since I do not use any padding
    def encrypt(self, message : bytes) -> bytes:
        if self.rsa is None:
            raise ValueError("[libRSA] Public key not set!")
        return self.cipher.encrypt(message)
    
    # does not consider any paddings
    def decrypt(self, ciphertext : bytes) -> bytes:
        if self.rsa is None:
            raise ValueError("[libRSA] Private key not set!")
        return self.cipher.decrypt(ciphertext)
    

class DHKE:
    def __init__(self, p=None, g=None):
        self.p = p
        self.g = g
        self.private_key = None
        self.public_key = None
        self.secret = None
        self.key_size = 0 if p is None else p.bit_length()

    def generate(self):
        if self.p is None or self.g is None:
            raise ValueError("p and g must be set before generating private key!")
        self.private_key = pycryptoRandom.StrongRandom().randint(2, self.p - 2)
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_secret(self, other_public_key : int):
        if self.public_key is None or self.private_key is None:
            raise ValueError("Public and private keys must be set before computing shared secret!")
        self.secret = pow(other_public_key, self.private_key, self.p)
        return self.secret