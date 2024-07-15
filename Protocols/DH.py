# Генерация простых чисел и КГПСЧ
from Crypto.Util.number import getStrongPrime
from Crypto.Random import random
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import gmpy2
import uuid
from Crypto.Util.number import long_to_bytes
from Crypto.Random import get_random_bytes

KEY_LENGTH = 32
MASTER = get_random_bytes(16)

def randint(a, b):
    native_a = int(a)
    native_b = int(b)
    return random.randint(native_a, native_b)

class DiffieHellmanParams():
    'Класс параметров DH'
    def __init__(self, prime_bits = 512):
        self.p = gmpy2.mpz(getStrongPrime(prime_bits))
        self.g = randint(2, self.p - 2)
        print(f'p = {self.p}, g = {self.g}')
        
class DiffieHellmanUser():
    'Класс пользователя DH'
    def __init__(self, params):
        self.p = params.p
        self.g = params.g
        self.id = uuid.uuid4()
        self.key = None
    
    def initiate_key_exchange(self, client2):
        'Инициализация выработки общего ключа'
        a = randint(1, self.p - 2)
        m = client2.accept_key_exchange(gmpy2.powmod(self.g, a, self.p))
        self.key = HKDF(MASTER, KEY_LENGTH, long_to_bytes(int(gmpy2.powmod(m, a, self.p))), SHA256, 1)
        print(f'Выработанный ключ 1 стороной: {self.key}')
        
    def accept_key_exchange(self, m):
        'Вторая сторона выработки общего ключа'
        b = randint(1, self.p - 2)
        self.key = HKDF(MASTER, KEY_LENGTH, long_to_bytes(int(gmpy2.powmod(m, b, self.p))), SHA256, 1)
        print(f'Выработанный ключ 2 стороной: {self.key}')
        return gmpy2.powmod(self.g, b, self.p)
    
if __name__ == '__main__':
    params = DiffieHellmanParams()
    alice = DiffieHellmanUser(params)
    bob = DiffieHellmanUser(params)
    alice.initiate_key_exchange(bob)