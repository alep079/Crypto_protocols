from pygost.gost34112012256 import GOST34112012256
import string

ROUNDS = 4

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

def generate_tmp_passwords(password):
    'Генерируем последовательность временных паролей'
    result = []
    hash = password 
    for _ in range(ROUNDS):
        hash = streebog_hash(hash)
        result.append(hash)
    return result


class SKEYServer(object):
    def __init__(self):
        self.clients = {} 
        
    def register_user(self, login, password):
        'Регистрация нового пользователя'
        if login in self.clients:
            print(f'Пользователь {login} уже зарегистрирован')
            return False
        self.clients[login] = [generate_tmp_passwords(password.encode())[-1], 1]
        print(f'Пользователь {login} успешно зарегистрирован')
        return 
    
    
    def login(self, login, tmp_password):
        'Вход пользователя на сервер'
        
        if login not in self.clients:
            print('Пользователь еще не зарегистрирован')
            return False
        
        if self.checking_password(login, tmp_password):
            if self.update_transaction_number(login) != False:
                print('Пользователь успешно авторизирован')
                return True
        return False
    
    def get_transaction_number(self, login):
        'Получение пользователем текущей транзакции'
        if login not in self.clients:
            print('Пользователь еще не зарегистрирован')
            return None
              
        return self.clients[login][1]
    
    def checking_password(self, login, tmp_password):
        'Проверка пароля пользователя'
        hash = tmp_password
        for _ in range(self.clients[login][1]-1):
            hash = streebog_hash(hash)
        if hash == self.clients[login][0]:
            return True
        else:
            print('Хэш пользователя не совпадает')
            return False

    
    def update_transaction_number(self, login):
        'Вычисление нового номера транзакции'
        
        self.clients[login][1] += 1
        if self.clients[login][1] > ROUNDS:
            print('Количество раундов закончилось')
            return False
            
        return self.clients[login][1]
    
class SKEYClient(object):
    
    def __init__(self, login, password):
        self.id = login
        strong_checking(password)
        self.password = password
        self.tmp_passwords = []
        
    def register(self, server):
        'Регистрация клиента'
        server.register_user(self.id, self.password)
        self.tmp_passwords = generate_tmp_passwords(self.password.encode())
    
    def login(self, server):
        'Авторизация на сервере'
        # получаем транзакцию
        transaction_number = server.get_transaction_number(self.id)
        if transaction_number is None:
            return False
        try:
            server.login(self.id, self.tmp_passwords[-transaction_number])
        except IndexError:
            print('Пользователь не зарегистрирован')

if __name__ == '__main__':
    server = SKEYServer()
    alice = SKEYClient('Alice', 'Strong_pass0')
    alice.register(server)
    # успешный кейс
    alice.login(server)
    alice.login(server)
    alice.login(server)
    print('')

    # истечение раундов
    alice.login(server)
    print('')

    # неверное имя
    eve = SKEYClient('Alice', 'Strong_pass1')
    eve.login(server)