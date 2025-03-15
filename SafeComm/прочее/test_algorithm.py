import time
import matplotlib.pyplot as plt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from scipy import stats
import numpy as np

# Функция для шифрования строки с использованием AES-256
def encrypt_aes_256(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, cipher.nonce, tag

# Функция для дешифрования строки с использованием AES-256
def decrypt_aes_256(ciphertext, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# Генерация случайного ключа AES-256 (32 байта)
key = get_random_bytes(32)

# Список для хранения данных: [количество символов, время дешифрования]
data = []

# Диапазон длин строк для тестирования
string_lengths = range(100, 50001, 1000)  # От 100 до 10000 символов с шагом 1000

for length in string_lengths:
    # Создаем строку заданной длины
    test_data = b'a' * length  # Используем байтовую строку

    # Шифруем данные
    start_time = time.time()
    ciphertext, nonce, tag = encrypt_aes_256(test_data, key)
    end_time = time.time()

    # Измеряем время дешифрования
    # start_time = time.time()
    # decrypt_aes_256(ciphertext, key, nonce, tag)
    # end_time = time.time()

    # Вычисляем время в миллисекундах
    decryption_time = (end_time - start_time) * 1000

    # Добавляем данные в список
    data.append([length, decryption_time])

# Разделяем данные на два списка: количество символов и время
char_counts = [item[0] for item in data]
times = [item[1] for item in data]

# Удаляем выбросы с использованием IQR
Q1 = np.percentile(times, 25)
Q3 = np.percentile(times, 75)
IQR = Q3 - Q1
lower_bound = Q1 - 1.5 * IQR
upper_bound = Q3 + 1.5 * IQR

filtered_char_counts = []
filtered_times = []
for i in range(len(times)):
    if lower_bound <= times[i] <= upper_bound:
        filtered_char_counts.append(char_counts[i])
        filtered_times.append(times[i])

char_counts = np.array(filtered_char_counts)
times = np.array(filtered_times)

# Применяем сглаживание скользящим средним
def moving_average(data, window_size):
    return np.convolve(data, np.ones(window_size) / window_size, mode='valid')

window_size = 3
smoothed_times = moving_average(times, window_size)
smoothed_char_counts = char_counts[:len(smoothed_times)]

# Вычисляем линейную регрессию
slope, intercept, r_value, p_value, std_err = stats.linregress(smoothed_char_counts, smoothed_times)

# Создаем массив значений для линии регрессии
regression_line = intercept + slope * smoothed_char_counts

# Построение графика
plt.figure(figsize=(10, 6))
plt.plot(smoothed_char_counts, smoothed_times, marker='o', linestyle='-', color='b', label='Сглаженное время шифрования')

# Добавляем линию регрессии
plt.plot(smoothed_char_counts, regression_line, color='r', linestyle='--', label=f'Линия регрессии: y = {slope:.6f}x + {intercept:.2f}')

# Добавляем подписи осей и заголовок
plt.xlabel('Количество символов в строке')
plt.ylabel('Время шифрования (мс)')
plt.title('Скорость шифрования AES-256 (сглаженные данные)')

# Включаем сетку для удобства чтения
plt.grid(True)

# Добавляем легенду
plt.legend()

# Показываем график
plt.show()