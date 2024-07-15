from pygost.gost34112012256 import GOST34112012256
import string

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

class PAPServer():
    def __init__(self):
        self.clients = {}
        
    def register_user(self, login, password):
        'Регистрация нового пользователя'
        if login in self.clients:
            print(f'Пользователь {login} уже зарегистрирован')
            return False
        self.clients[login] = GOST34112012256(password.encode()).digest()
        print(f'Пользователь {login} успешно зарегистрирован')
        return True
        
    def login(self, login, password):
        'Авторизация пользователя'
        if login not in self.clients:
            return False
        pass_hash = GOST34112012256(password.encode()).digest()
        real_hash = self.clients[login]
        print(f'Полученный пароль: {pass_hash}')
        print(f'Пароль из БД:      {real_hash}')
        return pass_hash == real_hash
    
class PAPClient():
    'Класс клиента'
    def __init__(self, login, password):
        self.id = login
        strong_checking(password)
        self.passwd = password

    def register(self, srv):
        'Регистрация пользователя'
        if srv.register_user(self.id, self.passwd):
            return True
        return False

    def login(self, srv):
        'Авторизация пользователя'
        if srv.login(self.id, self.passwd):
            print(f'Пользователь {self.id} успешно авторизован')
        else:
            print(f'Неправильное имя пользователя или пароль')

if __name__ =='__main__':
    # уданчый кейс
    server = PAPServer()
    alice = PAPClient('Alice', 'Strong_pass0')
    eve = PAPClient('Eve', 'Srong_pass1')
    alice.register(server)
    alice.login(server)
    print('')

    # кейс с неправильным id
    eve = PAPClient('Alice', 'Srong_pass1')
    eve.login(server)
    print('')

    # кейс со слабым паролем
    try:
        bob = PAPClient('Bob', '1234')
    except ValueError:
        print('Пароль не соответсвует требованиям')
    