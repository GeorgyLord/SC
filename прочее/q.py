from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def encrypt_aes256(key: bytes, plaintext: str) -> str:
    # Генерация случайного вектора инициализации (IV)
    iv = get_random_bytes(AES.block_size)
    
    # Создание шифратора с использованием ключа и IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Шифрование текста с дополнением
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    
    # Возвращение IV и зашифрованного текста в base64
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_aes256(key: bytes, encrypted_text: str) -> str:
    # Декодирование base64
    data = base64.b64decode(encrypted_text)
    
    # Извлечение IV и зашифрованного текста
    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]
    
    # Создание шифратора для расшифровки
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Расшифровка текста и удаление дополнения
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
    
    return plaintext

# Пример использования
if __name__ == "__main__":
    # Секретный ключ (32 байта для AES-256)
    secret_key = get_random_bytes(32)

    print(str(secret_key))

    # Исходное сообщение
    message = "Привет, мир!"

    # Шифрование
    encrypted_message = encrypt_aes256(secret_key, message)
    print(f"Зашифрованное сообщение: {encrypted_message}")

    # Расшифровка
    decrypted_message = decrypt_aes256(secret_key, encrypted_message)
    print(f"Расшифрованное сообщение: {decrypted_message}")