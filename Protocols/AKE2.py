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
    
class AKE2User():
    
    def __init__(self, pk=None):
        self.id = uuid.uuid4()
        self.key = None
        self.private_key = RSA.generate(RSA_KEY_LENGTH)
        self.public_key = self.private_key.publickey() if pk is None else pk
    
    def initiate_key_exchange(self, client2):

        Cert1 = (self.id, self.public_key)
        signature = pss.new(self.private_key).sign(SHA256.new(self.public_key.export_key()))
    
        try:
            c, signature, Cert2 = client2.accept_key_exchange(self.public_key, signature, Cert1)
        except TypeError:
            return False
        id2 = Cert2[0]
        if not self.check_signature(self.public_key.export_key(), c, self.id, signature, client2.public_key):
            print('Неправильная подпись сообщения! Клиент 1 разорвал соединение')
            self.key = None
            return False
        pk = HKDF(MASTER, ENCRYPTION_KEY_SIZE, self.public_key.export_key(), SHA256, 1)
        cipher = AES.new(pk, AES.MODE_CTR, nonce = c[0])
        mes = cipher.decrypt(c[1])
        if mes[-len(id2.bytes):] != id2.bytes:
            print('Сообщение подписано не тем! Клиент 1 разорвал соединение')
            self.key = None
            return False
        self.key = mes[:-len(id2.bytes)]
        print('Общий ключ выработан!')
        print(f'Ключ 1 клиента: {self.key}')
        print(f'Ключ 2 клиента: {client2.key}')
        return True
        
    def accept_key_exchange(self, pk1, signature, Cert1):
        'Принятие инициализации второй стороной'
        id1 = Cert1[0]
        try:
            pss.new(pk1).verify(SHA256.new(pk1.export_key()), signature)
        except:
            print('Неправильная подпись! Клиент 2 разорвал соединение')
            return False
        
        k = get_random_bytes(ENCRYPTION_KEY_SIZE)
        self.key = k
        pk = HKDF(MASTER, ENCRYPTION_KEY_SIZE, Cert1[1].export_key(), SHA256, 1)
        cipher = AES.new(pk, AES.MODE_CTR)
        c = (cipher.nonce, cipher.encrypt(k + self.id.bytes))
        signature = self.sign_values(Cert1[1].export_key(), c, id1)
        Cert2 = (self.id, self.public_key)
        return c, signature, Cert2

    def sign_values(self, pk1, c, id1):
        'Подпись сообщения r + c + id1'
        id1 = long_to_bytes(int(id1))
        h = SHA256.new(pk1 + c[0] + c[1] + id1)
        return pss.new(self.private_key).sign(h)
    
    def check_signature(self, pk1, c, id1, signature, pk2):
        'Проверка подпись сообщения r + c + id1'
        id1 = long_to_bytes(int(id1))
        h = SHA256.new(pk1 + c[0] + c[1] + id1)
        verifier = pss.new(pk2)
        try:
            verifier.verify(h, signature)
            return True
        except:
            return False
    
if __name__ == '__main__':
    # успешные кейсы
    alice = AKE2User()
    bob = AKE2User()
    alice.initiate_key_exchange(bob)
    print('')

    # неудачные кейсы
    eve = AKE2User(pk=alice.public_key)
    bob.initiate_key_exchange(eve)
    print('')
    eve.initiate_key_exchange(bob)