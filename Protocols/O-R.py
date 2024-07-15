from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import uuid

SESSION_KEY_SIZE = AES.key_size[2]
ENCRYPTION_KEY_SIZE = AES.key_size[2]
NUMBER_SIZE = 4

class OR_CA():
    def __init__(self):
        self.db = {}
        
    def register_client(self, client_id, client_key):
        'Регистрация клиента по id и ключу'
        if client_id in self.db:
            print(f'Клиент {client_id} уже существует')
            raise ValueError(f'Клиент {client_id} уже существует')
        self.db[client_id] = client_key
        print('Клиент успешно зарегестрирован')
        
    def accept(self, I, client1, client2, mes1, mes2):
        'Прием сообщений и генерация общего ключа'
        
        # проверка, что клиенты зарегестрированы
        if client1.id not in self.db:
            print('Нет общего ключа с 1 клиентом')
            return(None)
        if client2.id not in self.db:
            print('Нет общего ключа с 2 клиентом')
            return(None)

        # расшифровываем 1 сообщение
        cipher = AES.new(self.db[client1.id], AES.MODE_CTR, nonce=mes1[0])
        mes1_r = cipher.decrypt(mes1[1])
        Na = mes1_r[:NUMBER_SIZE]
        if not self.checking(client1.id.bytes, client2.id.bytes, mes1_r, I):
            print('Поврежденный пакет')
            return None
        
        # расшифровываем 2 сообщение
        cipher = AES.new(self.db[client2.id], AES.MODE_CTR, nonce=mes2[0])
        mes2_r = cipher.decrypt(mes2[1])
        Nb = mes2_r[:NUMBER_SIZE]
        if not self.checking(client1.id.bytes, client2.id.bytes, mes2_r, I):
            print('Поврежденный пакет')
            return None  
        
        # генерация общего ключа
        session_key = get_random_bytes(SESSION_KEY_SIZE)
        print(f'Общий ключ:           {session_key}')
        
        # шифруем сообщения для каждого клиента
        cipher = AES.new(self.db[client1.id], AES.MODE_CTR)
        mes1 = (cipher.nonce, cipher.encrypt(Na + session_key))
        
        cipher = AES.new(self.db[client2.id], AES.MODE_CTR)
        mes2 = (cipher.nonce, cipher.encrypt(Nb + session_key))
        
        return mes1, mes2
    
    def checking(self, idA, idB, mes, I):
        'Проверка на валидность данных'
        Ir = mes[NUMBER_SIZE:2*NUMBER_SIZE] # Na + I + self.id.bytes + client2.id.bytes
        idA_r = mes[2*NUMBER_SIZE:2*NUMBER_SIZE + len(idA)]
        idB_r = mes[2*NUMBER_SIZE + len(idA):]
        if idA != idA_r:
            return False
        elif idB != idB_r:
            return False
        elif Ir != I:
            print(I)
            return False
        return True

class ORClient():
    def __init__(self, id):
        self.id = id
        self.key = get_random_bytes(ENCRYPTION_KEY_SIZE)
        
    def register(self, ca):
        'Регистрация клиента'
        ca.register_client(self.id, self.key)
        
    def initiate_protocol(self, client2, ca):
        'Инициализация протокола 1 стороной'
 
        I  = get_random_bytes(NUMBER_SIZE)
        Na = get_random_bytes(NUMBER_SIZE)
        
        # шифруем сообщение
        cipher = AES.new(self.key, AES.MODE_CTR)
        mes1 = (cipher.nonce, cipher.encrypt(Na + I + self.id.bytes + client2.id.bytes))

        # оправляем данные 2 стороне и получаем ответ
        encrypted_key = client2.accept_initiation(I, self, mes1, ca)
        if encrypted_key is None:
            print(f'Ключ не получен')
            return False
        nonce, mes1 = encrypted_key
        
        # расшифровываем полученное сообщение
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        mes1 = cipher.decrypt(mes1)
        
        # сверяем nonce
        if Na != mes1[:NUMBER_SIZE]:
            print(f'Nonce не совпадает! Клиент 1 разорвал подключение')
            return False
        
        s = mes1[NUMBER_SIZE:]
        print(f'Ключ первого клинета: {s}')
        return True
        
    def accept_initiation(self, I, first_client, mes1, ca):
        'Принятие инициализации 2 стороной'
        Nb = get_random_bytes(NUMBER_SIZE)
        
        # шифруем свои данные
        cipher = AES.new(self.key, AES.MODE_CTR)
        mes2 = (cipher.nonce, cipher.encrypt(Nb + I + first_client.id.bytes + self.id.bytes))
        
        # посылаем запрос на проверку в УЦ
        result = ca.accept(I, first_client, self, mes1, mes2)
        if result is None:
            print(f'УЦ отказал в соединении')
            return None
        mes1, mes2 = result

        # расшифровываем полученное сообщение
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=mes2[0])
        mes2 = cipher.decrypt(mes2[1])
        
        # сверяем nonce
        if Nb != mes2[:NUMBER_SIZE]:
            print(f'Nonce не совпадает! Клиент 2 разорвал подключение')
            return None
        
        s = mes2[NUMBER_SIZE:]
        print(f'Ключ первого клинета: {s}')
        return mes1
    
if __name__ == '__main__':
    # успешный кейс
    ca = OR_CA()
    alice = ORClient(uuid.uuid4())
    bob = ORClient(uuid.uuid4())
    alice.register(ca)
    bob.register(ca)
    alice.initiate_protocol(bob, ca)
    print('')

    # кейс с подменным идентификатором
    eve = ORClient(bob.id)
    alice.initiate_protocol(eve, ca)
    print('')
    eve.initiate_protocol(alice, ca)
