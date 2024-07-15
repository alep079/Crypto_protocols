from pygost.gost34112012256 import GOST34112012256
import string
from Crypto.Random import get_random_bytes

N_SIZE = 16

def streebog_hash(*args):
    'Функция хеширования Стрибог'
    hash = GOST34112012256()
    for arg in args:
        hash.update(arg)
    return hash.digest()

def strong_checking(password):
    'Проверка сложности пароля'
    if len(password) < 8:
        raise ValueError('Малая длина пароля')
    flag = [False, False, False, False]
    for s in password:
        if s in string.ascii_lowercase:
            flag[0] = True
        elif s in string.ascii_uppercase:
            flag[1] = True
        elif s in string.digits:
            flag[2] = True
        elif s in string.punctuation:
            flag[3] = True
    if flag == [True, True, True, True]:
        return (True)
    raise ValueError('Пароль недостаточно сложный')


class CHAPServer():
    def __init__(self, login, password):
        self.s_login = login
        strong_checking(password)
        self.s_password = password
        self.clients = {}
    
    def register_user(self, login, password):
        'Регистрация нового пользователя'
        if login in self.clients:
            print(f'Пользователь {login} уже зарегистрирован')
            return False
        self.clients[login] = [password.encode(), 0]
        print(f'Пользователь {login} успешно зарегистрирован')
        return self.s_login, self.s_password
        
    def login(self, login, digest1, N2 = None):
        
        if login not in self.clients:
            print('Пользователь не зарегистрирован')
            return False
        
        N1 = self.clients[login][1]
        self.clients[login][1] = None
        
        if N1 is False:
            print(f'Пользователь {login} еще не зарегестрирован')
            return False
        
        digest1_calc = streebog_hash(N1, self.clients[login][0])
        print(f'Полученный хэш от клиента: {digest1}')
        print(f'Посчитанный хэш сервером:  {digest1_calc}')
        if digest1_calc != digest1:
            print('Получен неправильный хеш')
            return False
        if N2 == None:
            print('Успешная аутентификация!')
            return False
        digest2 = streebog_hash(N2, self.s_password.encode())
                                               
        return self.s_login, digest2
    
    def get_N(self, login):
        'Генерация случайного N'
        if login not in self.clients:
            print('Пользователь не зарегистрирован')
            return False
        N = get_random_bytes(N_SIZE)
        self.clients[login][1] = N
        return N
    
class CHAPClient():
    def __init__(self, login, password):
        self.id = login
        strong_checking(password)
        self.password = password
        self.servers_db = {}
        self.mode = 'double'
        
    def register(self, srv):
        'Регистрация клиента'
        login, password = srv.register_user(self.id, self.password)
        self.servers_db[login] = password

    def login(self, server, mode = 'double'):
        'Авторизация на сервере'
        self.mode = mode
        N1 = server.get_N(self.id)
        if N1 is False:
            return False
        digest1 = streebog_hash(N1, self.password.encode())

        if self.mode == 'one-way':
            print ('Работает однонаправленная версия!')
            ans = server.login(self.id, digest1)
        else: 
            N2 = self.get_N(server)
            ans = server.login(self.id, digest1, N2)
        
        if ans is not False:
            s_login, digest2 = ans
            
            if s_login not in self.servers_db:
                print('Не установлено соединение с сервером')
                return False
            
            digest2_calc = streebog_hash(N2, self.servers_db[s_login].encode())
            print(f'Полученный хэш с сервера:  {digest2}')
            print(f'Посчитанный хэш клиентом:  {digest2_calc}')
            
            if digest2_calc == digest2:
                print(f'Успешная аутентификация!')
                return True
            else:
                print(f'Аутентификация не удалась')
                return False
        return False
        
    def get_N(self, server):
        if server.s_login not in self.servers_db:
            print('Не установлено соединение с сервером')
            return False
        return get_random_bytes(N_SIZE)
    
if __name__ == '__main__':
    server = CHAPServer('Bob', 'Strong_pass0')
    alice = CHAPClient('Alice', 'Strong_pass1')
    alice.register(server)
    # успешный кейс
    alice.login(server)
    print('')

    # попытка выдать себя за другого
    eve = CHAPClient('Alice', 'Strong_pass2')
    eve.login(server)
    print('')

    # Однонаправленная версия
    alice.login(server, 'one-way')
    print('')

    # неудачная попытка
    eve.login(server)
    print('')