from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import uuid

SESSION_KEY_SIZE = AES.key_size[2]
ENCRYPTION_KEY_SIZE = AES.key_size[2]
AUTH_KEY_SIZE = AES.key_size[2]
NUMBER_SIZE = 4

def find_mac(key, id, ra, rb, c):
    'Нахождение MAC от заданных параметров и ключа'
    mac = HMAC.new(key, id.bytes, digestmod=SHA256)
    mac.update(ra)
    mac.update(rb)
    mac.update(c)
    return(mac)

class PKD_CA():
    def __init__(self):
        self.db = {}
        
    def register_client(self, client_id, client_key):
        'Регистрация клиента по id и ключу'
        if client_id in self.db:
            print(f'Клиент {client_id} уже существует')
            raise ValueError(f'Клиент {client_id} уже существует')
        self.db[client_id] = client_key
        print('Клиент успешно зарегестрирован')
        
    def accept(self, ra, rb, client1_id, client2_id):
        'Прием сообщений и генерация общего ключа'
        
        # проверка, что клиенты зарегестрированы
        if client1_id not in self.db:
            print('Нет общего ключа с 1 клиентом')
            return(None)
        if client2_id not in self.db:
            print('Нет общего ключа с 2 клиентом')
            return(None)
        
        # генерируем сессионный ключ
        session_key = get_random_bytes(SESSION_KEY_SIZE)
        print(f'Общий ключ:           {session_key}')

        # шифрование сообщений
        cipher1 = AES.new(self.db[client1_id][0], AES.MODE_CTR)
        mes1 = (cipher1.nonce, cipher1.encrypt(session_key))
        cipher2 = AES.new(self.db[client2_id][0], AES.MODE_CTR)
        mes2 = (cipher2.nonce, cipher2.encrypt(session_key))

        # получение меток
        mac1 = find_mac(self.db[client1_id][1], client2_id, ra, rb, mes1[1])
        mac2 = find_mac(self.db[client2_id][1], client1_id, ra, rb, mes2[1])

        return mes1, mes2, mac1, mac2
    
    
class PKDClient():
    def __init__(self, id):
        self.id = id
        self.key_e = get_random_bytes(ENCRYPTION_KEY_SIZE)
        self.key_a = get_random_bytes(AUTH_KEY_SIZE)
        
    def register(self, ca: PKD_CA):
        'Регистрация клиентов в УЦ'
        ca.register_client(self.id, (self.key_e, self.key_a))
        
    def initiate_protocol(self, second_client, ca):
        'Инициализация протокола 1 стороной'
        ra = get_random_bytes(NUMBER_SIZE)
        
        # проверяем, что второй клиент нормально прошел свой этап
        ans = second_client.accept_initiation(ra, self.id, ca)
        if ans == None:
            return False
        mes1, mac1, idb, rb = ans

        # проверка MAC меток
        if find_mac(self.key_a, idb, ra, rb, mes1[1]).digest() != mac1.digest():
            print('Неверный MAC! Клиент 1 разорвал подключение!')
            return False
        
        # расшифровка и получение ключа
        cipher = AES.new(self.key_e, AES.MODE_CTR, nonce=mes1[0])
        k = cipher.decrypt(mes1[1])
        print(f'Ключ первого клинета: {k}')
        return True
        
    def accept_initiation(self, ra, client1, ca):
        'Принятие инициализации 2 стороной'
        rb = get_random_bytes(NUMBER_SIZE)

        # инициализация с УЦ
        result = ca.accept(ra, rb, client1, self.id)
        if result is None:
            print(f'СА отказал в инициализации')
            return None
        mes1, mes2, mac1, mac2 = result
        
        # проверка MAC меток
        if find_mac(self.key_a, client1, ra, rb, mes2[1]).digest() != mac2.digest():
            print('Неверный MAC! Клиент 2 разорвал подключение!')
            return None

        # расшифровка и получение ключа
        cipher = AES.new(self.key_e, AES.MODE_CTR, nonce=mes2[0])
        k = cipher.decrypt(mes2[1])
        print(f'Ключ второго клинета: {k}')
        
        return mes1, mac1, self.id, rb
    
if __name__ == '__main__':
    # успешный кейс
    ca = PKD_CA()
    alice = PKDClient(uuid.uuid4())
    bob = PKDClient(uuid.uuid4())
    alice.register(ca)
    bob.register(ca)
    alice.initiate_protocol(bob, ca)
    print('')

    # кейс с подменным идентификатором
    eve = PKDClient(bob.id)
    alice.initiate_protocol(eve, ca)
    eve.initiate_protocol(alice, ca)