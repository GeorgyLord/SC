from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Функция для генерации ключа
def generate_key():
    return os.urandom(16)  # AES-128, ключ длиной 16 байт

# Функция для шифрования текста
def encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  # Инициализационный вектор
    cipher_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return iv + cipher_text  # Возвращаем iv и шифртекст

# Функция для расшифровки текста
def decrypt(cipher_text, key):
    iv = cipher_text[:16]  # Извлекаем IV (первые 16 байт)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipher_text[16:]), AES.block_size).decode()

# Пример использования
key = generate_key()
print('Ключ:', key)
plain_text = "Hello!"
cipher_text = encrypt(plain_text, key)
print("Шифрованный текст:", cipher_text)

decrypted_text = decrypt(cipher_text, key)
print("Расшифрованный текст:", decrypted_text)
