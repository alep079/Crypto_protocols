from Crypto.Util.number import getStrongPrime
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Cipher import AES
import gmpy2
import uuid
from Crypto.Util.number import long_to_bytes
from DH import *

RSA_KEY_LENGTH = 4096
KEY_LENGTH = 32
MASTER = get_random_bytes(16)

class STSParams():
    def __init__(self, prime_bits):
        self.p = gmpy2.mpz(getStrongPrime(prime_bits))
        self.g = randint(2, self.p - 2)
    
class STSUser():
    
    def __init__(self, params, pk=None):
        self.p = params.p
        self.g = params.g
        self.id = uuid.uuid4()
        self.key = None
        self.private_key = RSA.generate(RSA_KEY_LENGTH)
        self.public_key = self.private_key.publickey() if pk is None else pk
    
    def initiate_key_exchange(self, client2):

        x = randint(1, self.p - 2)
        ma = gmpy2.powmod(self.g, x, self.p)
    
        mb, mes = client2.accept_key_exchange(ma)
        self.key = HKDF(MASTER, KEY_LENGTH, long_to_bytes(int(gmpy2.powmod(mb, x, self.p))), SHA256, 1)
        nonce, ct = mes
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        signature = cipher.decrypt(ct)
        
        if not self.check_signature(ma, mb, signature, client2.public_key):
            print('Неправильная подпись сообщения! Клиент 1 разорвал соединение')
            self.key = None
            return False

        signature = self.sign_values(ma, mb)
        cipher = AES.new(self.key, AES.MODE_CTR)
        if not client2.check_key_exchange(ma, mb, (cipher.nonce, cipher.encrypt(signature)), self.public_key):
            self.key = None
            return False
        print('Общий ключ выработан!')
        print(f'Ключ 1 клиента: {self.key}')
        print(f'Ключ 2 клиента: {client2.key}')
        return True
        
        
    def accept_key_exchange(self, ma):
        'Принятие инициализации второй стороной'

        y = randint(1, self.p - 2)
        mb = gmpy2.powmod(self.g, y, self.p)
        self.key = HKDF(MASTER, KEY_LENGTH, long_to_bytes(int(gmpy2.powmod(ma, y, self.p))), SHA256, 1)
        
        signature = self.sign_values(ma, mb)
        cipher = AES.new(self.key, AES.MODE_CTR)
        mes = (cipher.nonce, cipher.encrypt(signature))
        
        return mb, mes
    
    
    def check_key_exchange(self, ma, mb, encrypted_signature, pk):
        nonce, mes = encrypted_signature
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        received_signature = cipher.decrypt(mes)
        
        if not self.check_signature(ma, mb, received_signature, pk):
            print('Неправильная подпись сообщения! Клиент 2 разорвал соединение')
            self.key = None
            return False
        return True
    
    def sign_values(self, ma, mb):
        'Подпись сообщения ma + mb'
        ma  = long_to_bytes(int(ma))
        mb = long_to_bytes(int(mb))
        
        h = SHA256.new(ma + mb)
        return pss.new(self.private_key).sign(h)
    
    def check_signature(self, ma, mb, signature, pk):
        'Проверка подпись сообщения ma + mb'
        ma  = long_to_bytes(int(ma))
        mb = long_to_bytes(int(mb))
        h = SHA256.new(ma + mb)
        verifier = pss.new(pk)
        
        try:
            verifier.verify(h, signature)
            return True
        except:
            return False
    
if __name__ == '__main__':
    # успешные кейсы
    params = STSParams(512)
    alice = STSUser(params)
    bob   = STSUser(params)
    alice.initiate_key_exchange(bob)
    print('')

    # неудачные кейсы
    eve = STSUser(params, pk=alice.public_key)
    eve.initiate_key_exchange(bob)
    print('')
    bob.initiate_key_exchange(eve)