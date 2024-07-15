from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import uuid
from Crypto.Util import number

SESSION_KEY_SIZE = AES.key_size[2]
ENCRYPTION_KEY_SIZE = AES.key_size[2]
NUMBER_SIZE = 4

class NeedhamSchroederCA():
    def __init__(self):
        self.db = {}
    
    def register_client(self, client_id, client_key):
        'Регистрация клиента по id и ключу'
        if client_id in self.db:
            print(f'Клиент {client_id} уже существует')
            raise ValueError(f'Клиент {client_id} уже существует')
        self.db[client_id] = client_key
        print('Клиент успешно зарегестрирован')
        
    def accept(self, client1_id, client2_id, Na):
        'Этап соединения со строны УЦ'

        # проверка, что клиенты зарегестрированы
        if client1_id not in self.db:
            print('Нет общего ключа с 1 клиентом')
            return(None)
        if client2_id not in self.db:
            print('Нет общего ключа с 2 клиентом')
            return(None)
            
        # генерация сессионного ключа
        session_key = get_random_bytes(SESSION_KEY_SIZE)
        print(f'Исходный ключ:        {session_key}')
        
        #шифрование сообщений для клиента A
        cipher = AES.new(self.db[client2_id], AES.MODE_CTR)
        nonce, mes = cipher.nonce, cipher.encrypt(session_key + client1_id.bytes)
        
        cipher = AES.new(self.db[client1_id], AES.MODE_CTR)
        return cipher.nonce, cipher.encrypt(Na + client2_id.bytes + session_key + nonce + mes)
    
class NeedhamSchroederClient():
    def __init__(self, id):
        self.id = id
        self.key = get_random_bytes(ENCRYPTION_KEY_SIZE)
        self.Session_list = {}
        
    def register(self, ca):
        'Регистрация клиента'
        ca.register_client(self.id, self.key)
        
    def initiate_protocol(self, client2, ca):
        'Инициализация протокола 1 стороной'

        Na = get_random_bytes(NUMBER_SIZE)
        nonce, encrypted_data = ca.accept(self.id, client2.id, Na)
        
        # расшифровка
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        mes = cipher.decrypt(encrypted_data) # Na + client2.id.bytes + session_key + nonce + mes
        
        if mes[:NUMBER_SIZE] != Na:
            print('Поврежденный пакет')
            return False
            
        start = len(Na) + len(client2.id.bytes)
        session_key = mes[start: start + SESSION_KEY_SIZE]

        # получаем сообщение для В
        mes = mes[start + SESSION_KEY_SIZE:]
        nonce, mes2 = mes[:AES.block_size // 2], mes[AES.block_size // 2:]
        
        ans = client2.accept_packet(nonce, mes2, self.id)
        if ans is None:
            print(f'Na не совпадает! Клиент 1 разорвал подключение')
            return False
        
        # пытаемся расшифровать
        nonce, ans = ans
        cipher = AES.new(session_key, AES.MODE_CTR, nonce=nonce)
        Nb = cipher.decrypt(ans)
        Nb_digit = number.bytes_to_long(Nb)
        Nb_new = number.long_to_bytes(Nb_digit - 1)
        
        cipher = AES.new(session_key, AES.MODE_CTR)
        if not client2.verify_response(cipher.nonce, cipher.encrypt(Nb_new), self.id):
            print('Общий ключ не выработан')
            return False
        
        self.Session_list[client2.id] = (None, session_key)
        print(f'Ключ первого клинета: {session_key}')
        return True

    def accept_packet(self, nonce, mes2, client1_id):
        'Принятие пакета второй стороной'

        # расшифровка сообщений. получение idA и ключа
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        mes = cipher.decrypt(mes2)
        session_key = mes[:SESSION_KEY_SIZE]
        id = mes[SESSION_KEY_SIZE:]
        
        if id != client1_id.bytes:
            print(f'ID не совпадает! Клиент 2 разорвал подключение')
            return None

        self.Session_list[client1_id] = (get_random_bytes(NUMBER_SIZE), session_key)
        cipher = AES.new(session_key, AES.MODE_CTR)
        print(f'Ключ второго клиента: {session_key}')
        return (cipher.nonce, cipher.encrypt(self.Session_list[client1_id][0]))
    
    def verify_response(self, nonce, mes, client1_id):
        'Подверждение получения верного ключа'
        # расшифровываем сообщение
        cipher = AES.new(self.Session_list[client1_id][1], AES.MODE_CTR, nonce=nonce)
        Nb_r = cipher.decrypt(mes)
        Nb_digit = number.bytes_to_long(self.Session_list[client1_id][0])
        Nb = number.long_to_bytes(Nb_digit - 1)
        if Nb_r == Nb:
            return True
        print('Ключ не подтвержден')
        return False
    
if __name__ == '__main__':
    # успешный кейс
    ca = NeedhamSchroederCA()
    alice = NeedhamSchroederClient(uuid.uuid4())
    bob   = NeedhamSchroederClient(uuid.uuid4())
    alice.register(ca)
    bob.register(ca)
    alice.initiate_protocol(bob, ca)
    print('')
    
    # нейдачные кейсы
    mallory = NeedhamSchroederClient(bob.id)
    alice.initiate_protocol(mallory, ca)
    print('')
    mallory.initiate_protocol(alice, ca)