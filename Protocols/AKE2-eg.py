from Crypto.Util.number import getStrongPrime
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Cipher import AES
import uuid
from Crypto.Util.number import long_to_bytes
from DH import *
    
RSA_KEY_LENGTH = 2048
KEY_LENGTH = 32
MASTER = get_random_bytes(16)
ENCRYPTION_KEY_SIZE = AES.key_size[2]

class AKE1egParams():
    def __init__(self, prime_bits):
        self.p = gmpy2.mpz(getStrongPrime(prime_bits))
        self.g = randint(2, self.p - 2)

class AKE1egUser():
    
    def __init__(self, params, pk=None):
        self.p = params.p
        self.g = params.g
        self.id = uuid.uuid4()
        self.key = None
        self.private_key = RSA.generate(RSA_KEY_LENGTH)
        self.public_key  = self.private_key.publickey() if pk is None else pk
        self.dh_private = randint(1, self.p - 2)
        self.dh_public = gmpy2.powmod(self.g, self.dh_private, self.p) if pk is None else pk
    
    def initiate_key_exchange(self, client2):

        Cert1 = (self.id, self.public_key)
        signature = pss.new(self.private_key).sign(SHA256.new(long_to_bytes(int(self.dh_public))))
    
        try:
            v, signature, Cert2 = client2.accept_key_exchange(self.dh_public, signature, Cert1)
        except TypeError:
            return False
        id2 = Cert2[0]
        if not self.check_signature(self.dh_public, v, self.id, signature, Cert2[1]):
            print('Неправильная подпись сообщения! Клиент 1 разорвал соединение')
            self.key = None
            return False
        key_mes = long_to_bytes(int(gmpy2.powmod(v, self.dh_private, self.p)) + int(self.dh_public) + int(v) + int(id2))
        self.key = HKDF(MASTER, KEY_LENGTH, key_mes, SHA256, 1)
        print('Общий ключ выработан!')
        print(f'Ключ 1 клиента: {self.key}')
        print(f'Ключ 2 клиента: {client2.key}')
        return True
        
    def accept_key_exchange(self, pk1, signature, Cert1):
        'Принятие инициализации второй стороной'
        id1 = Cert1[0]
        try:
            pss.new(Cert1[1]).verify(SHA256.new(long_to_bytes(int(pk1))), signature)
        except:
            print('Неправильная подпись! Клиент 2 разорвал соединение')
            return False
        key_mes = long_to_bytes(int(gmpy2.powmod(pk1, self.dh_private, self.p)) + int(self.dh_public) + int(pk1) + int(self.id))
        self.key = HKDF(MASTER, KEY_LENGTH, key_mes, SHA256, 1)
        signature = self.sign_values(pk1, self.dh_public, id1)
        Cert2 = (self.id, self.public_key)
        return self.dh_public, signature, Cert2

    def sign_values(self, pk1, v, id1):
        'Подпись сообщения pk1 + v + id1'
        pk1 = long_to_bytes(int(pk1))
        v = long_to_bytes(int(v))
        id1 = long_to_bytes(int(id1))
        h = SHA256.new(pk1 + v + id1)
        return pss.new(self.private_key).sign(h)
    
    def check_signature(self, pk1, v, id1, signature, pk):
        'Проверка подпись сообщения pk1 + v + id1'
        pk1 = long_to_bytes(int(pk1))
        id1 = long_to_bytes(int(id1))
        v = long_to_bytes(int(v))
        h = SHA256.new(pk1 + v + id1)
        verifier = pss.new(pk)
        try:
            verifier.verify(h, signature)
            return True
        except:
            return False
    
if __name__ == '__main__':
    # успешные кейсы
    params = AKE1egParams(512)
    alice = AKE1egUser(params)
    bob = AKE1egUser(params)
    alice.initiate_key_exchange(bob)
    print('')

    # неудачные кейсы
    eve = AKE1egUser(params, pk=alice.dh_public)
    bob.initiate_key_exchange(eve)
    print('')
    eve.initiate_key_exchange(bob)