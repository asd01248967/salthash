# Module Imports
import mariadb
import sys
import base64
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import hashlib
import random

userid = sys.argv[1]
passwordid = sys.argv[2]    

def sha256(password):
    data_sha = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return data_sha

def encode(password):
    EncodePassword = base64.b64encode(password.encode("UTF-8"))
    strPassword = EncodePassword.decode("UTF-8")
    return strPassword

def cryptoAES(password):
    # 用get_random_bytes(32)產生一個byte類型的32位元組的字串
    salt = b'|A{E\x1c6\xe49\xc6\xac\x0ez5\xde\xba\xca\x11\xc4\xfb\n#\xf0h\x07\xe2\r\xbc\xa1TN\x81c'
    password = 'my#password'
    key = PBKDF2(password, salt, dkLen=32)

    # 金鑰儲存位置
    keyPath = "my_key.bin"

    # 儲存金鑰
    with open(keyPath, "wb") as f:
        f.write(key)

    # 讀取金鑰
    with open(keyPath, "rb") as f:
        keyFromFile = f.read()

    # 檢查金鑰儲存
    assert key == keyFromFile, '金鑰不符'

    # 輸出的加密檔案名稱
    outputFile = 'encrypted.bin'

    # 要加密的資料（必須為 bytes）
    data = password.encode('utf-8')

    # 以金鑰搭配 CFB 模式建立 cipher 物件
    cipher = AES.new(key, AES.MODE_CFB)

    # 將輸入資料進行加密
    cipheredData = cipher.encrypt(data)

    # 將初始向量與密文寫入檔案並回傳轉回base64格式的字串的密碼密文
    with open(outputFile, 'wb') as f:
        f.write(cipheredData)
        f.write(cipher.iv)
    return b64encode(cipheredData).decode('utf-8')

def registered(username, password, salt):
    # Connect to MariaDB Platform
    try:
        conn = mariadb.connect(
            user="root",
            password="123456",
            host="127.0.0.1",
            port=3306,
            database="SALT"
        )
    except mariadb.Error as e:
        print("Error connecting to MariaDB Platform: {}".format(e))
        sys.exit(1)

    # Get Cursor
    cur = conn.cursor()
    try:
        cur.execute('CREATE TABLE IF NOT EXISTS `JASPER`(`username` VARCHAR(64),`password` VARCHAR(64), `salt` VARCHAR(16), PRIMARY KEY (`username`) USING BTREE)')
        try:
            cur.execute("""
                INSERT INTO jasper (username, password, salt)
                VALUES (%s, %s, %s);
                """,
                (username, password, salt)
            )
            conn.commit()
            cur.close()
            conn.close()
        except mariadb.IntegrityError as e:
            print(e)
        except Exception as e:
            print(e)
    except Exception as e:
        print(e)

def login(username, password):
    # Connect to MariaDB Platform
    try:
        conn = mariadb.connect(
            user="root",
            password="123456",
            host="127.0.0.1",
            port=3306,
            database="SALT"
        )
    except mariadb.Error as e:
        print("Error connecting to MariaDB Platform: {}".format(e))
        sys.exit(1)
    
    # Get Cursor
    cur = conn.cursor()
    try:
        cur.execute('SELECT username, password, salt FROM JASPER WHERE username=?',
        (username,))
        result = cur.fetchall()
        print(result)
        saltcheck = result[0][2]
        print(saltcheck)
        sha1_obj = hashlib.sha1()
        sha1_obj.update((saltcheck+password).encode('utf-8'))
        a = sha1_obj.hexdigest()
        print(a)

        if len(result) == 1:
            if result[0][0] == username and  result[0][1] == a:
                return "login successed"
        else:
            return "login failed, redirection to registered page"
    except Exception as e:
        print(e)

def salt(password):
    ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+"
    salt = ''.join(random.choice(ALPHABET) for i in range(16))
    sha1_obj = hashlib.sha1()
    sha1_obj.update((salt+password).encode('utf-8'))
    return sha1_obj.hexdigest(), salt

if __name__ == '__main__':
    # strPassword = encode(passwordid)
    # newpwd = cryptoAES(passwordid)
    # sha256PD = sha256(passwordid)
    saltPD, salt_str = salt(passwordid)
    registered(userid, saltPD, salt_str)
    loginMessage = login(userid, passwordid)
    print(loginMessage)


