import sys
# from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QMessageBox, QLineEdit
from PyQt5.QtWidgets import *

# from PyQt5.QtCore import Qt, QPoint
# from PyQt5.QtCore import QTimer
from PyQt5.QtCore import *
from PyQt5.QtGui import *

from PyQt5 import QtCore, QtGui, QtWidgets
# from safecomm import Ui_MainWindow  # Импортируйте сгенерированный класс
# from login import Ui_MainWindow

from PyQt5 import *

import safecomm
import login
import setting

import smtplib
import imaplib
import email
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

import os
from random import randint

from PIL import Image, ImageDraw, ImageFont

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
import base64
import binascii
import json
import asyncio


use_default_key = True
private_key = b""
# Генерация ключа
def generate_key():
    global private_key
    key = os.urandom(32)

    if use_default_key:
        private_key = key
    else:
        private_key = key

# Загрузка ключа
def load_key():
    current_folder = os.path.dirname(__file__)
    if use_default_key:
        file_path = os.path.join(current_folder, "..", "key", "default_key")
    else:
        file_path = os.path.join(current_folder, "..", "key", "your_key")
    print(file_path)
    return open(file_path, 'rb').read()

    # if use_default_key:
    #     return open('default_key.key', 'rb').read()
    # else:
    #     return open('your_key.key', 'rb').read()

# Шифрование файла
def encrypt_file(file_name):
    key = load_key()
    key = base64.urlsafe_b64encode(key)
    f = Fernet(key)

    with open(file_name, 'rb') as file:
        file_data = file.read()

    encrypted_data = f.encrypt(file_data)
    current_folder = os.path.dirname(__file__)
    file_name = file_name[file_name.rfind('/')+1::]
    file_path = os.path.join(current_folder, "..", "encrypted_files", file_name + ".encrypted")
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)
        print('!!')
        print(file_name + '.encrypted')

# Дешифрование файла
def decrypt_file(file_name):
    current_folder = os.path.dirname(__file__)
    # Загружаем ключ для дешифрования
    key = load_key()
    # Кодируем ключ в формат, совместимый с Fernet
    key = base64.urlsafe_b64encode(key)
    # Создаём объект Fernet, используя загруженный и закодированный ключ
    f = Fernet(key)

    # Открываем зашифрованный файл в бинарном режиме для чтения
    file_path = os.path.join(current_folder, "..", "downloads", file_name)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    # Дешифруем данные с помощью объекта Fernet
    decrypted_data = f.decrypt(encrypted_data)

    file_path = os.path.join(current_folder, "..", "downloads", file_name.replace('.encrypted', ''))
    with open(file_path, 'wb') as file:
        # Записываем дешифрованные данные в новый файл
        file.write(decrypted_data)

def encrypt_aes256(key: bytes, plaintext: str) -> str:
    # Генерация случайного вектора инициализации (IV)
    iv = get_random_bytes(AES.block_size)
    
    # Создание шифратора с использованием ключа и IV
    # cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher = AES.new(key, AES.MODE_EAX, iv)
    
    # Шифрование текста с дополнением
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    
    # Возвращение IV и зашифрованного текста в base64
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_aes256(key: bytes, encrypted_text: str) -> str:
    try:
        # Декодирование base64
        data = base64.b64decode(encrypted_text)
        
        # Извлечение IV и зашифрованного текста
        iv = data[:AES.block_size]
        ciphertext = data[AES.block_size:]
        
        # Создание шифратора для расшифровки
        # cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher = AES.new(key, AES.MODE_EAX, iv)
        
        # Расшифровка текста и удаление дополнения
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
        
        return plaintext
    except:
        return encrypted_text

def create_avatar(letter="Q", random_background_color=False, random_font_color=False):
    # Настройки аватара
    size = (200, 200)  # Размер аватара
    if random_background_color:
        background_color = (randint(0, 256), randint(0, 256), randint(0, 256))
    else:
        background_color = (255, 185, 128)  # Цвет фона (белый)
    font_size = 100  # Размер шрифта
    if random_font_color:
        font_color = (randint(0, 256), randint(0, 256), randint(0, 256))
    else:
        font_color = (194, 91, 33)  # Цвет буквы (черный)

    # Создание нового изображения
    avatar = Image.new('RGB', size, background_color)

    # Загружаем шрифт
    font = ImageFont.truetype("arial.ttf", font_size)  # Замените "arial.ttf" на путь к шрифту на вашей системе

    # Создание объекта для рисования
    draw = ImageDraw.Draw(avatar)

    # Получаем размеры текста
    bbox = draw.textbbox((0, 0), letter, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]

    # Вычисление позиции для буквы
    text_x = (size[0] - text_width) / 2
    text_y = (size[1] - text_height) / 3

    # Рисуем букву на изображении
    draw.text((text_x, text_y), letter, fill=font_color, font=font)

    current_folder = os.path.dirname(__file__)
    file_path = os.path.join(current_folder, "..", "avatar", "avatar.png")
    # Сохраняем аватар
    avatar.save(file_path)

    # Если нужно, можно показать изображение
    # avatar.show()

# Функция для декодирования заголовков
def decode_mime_words(s):
    decoded_bytes = decode_header(s)
    decoded_str = ''
    for text, encoding in decoded_bytes:
        if isinstance(text, bytes):
            text = text.decode(encoding if encoding else 'utf-8')
        decoded_str += text
    return decoded_str

class MainWindow(QMainWindow, safecomm.Ui_MainWindow):
    def __init__(self, imap_server, username, password, smtp_server):
        super().__init__()
        self.setupUi(self)  # Настройка UI

        self.last_size = self.size()
        self.is_moving = False
        body = ''
        
        self.smtp_server = smtp_server
        self.imap_server = imap_server
        self.username = username
        self.password = password

        # Секретный ключ (32 байта для AES-256)
        # self.secret_key = b'\xa2\x0c\xf1\x16V\x13na\xc4\x94_\xe8\xe9\x85\x94Y\x1a\xe7T\xc9\xd5\x10@%n=\xec\xe0j=\x07;'
        self.secret_key = load_key()
        # t = str(base64.urlsafe_b64encode(load_key()))[2:-1:]
        # print(t, len(t))
        # self.secret_key = t
        # key = base64.urlsafe_b64encode(self.secret_key)
        # print(key==b'PYgzLMPAP6tFVYEkR9MBscA32erSAQOvHkiNHS35s_M=')


        self.form_sending.hide()
        self.data_message.hide()
        self.scrollArea_3.hide()
        self.pushButton_4.hide()

        self.btn_new_message.clicked.connect(self.new_message)
        self.btn_show_incoming.clicked.connect(self.show_incoming)
        self.btn_show_sent_messages.clicked.connect(self.show_sent_messages)
        self.btn_sent_email.clicked.connect(self.sent_email)
        self.pushButton_10.clicked.connect(self.open_file_dialog)
        self.checkBox.stateChanged.connect(self.select_all)
        self.pushButton.clicked.connect(self.delete_message)
        self.cancel.clicked.connect(self.canceling_sending_message)
        self.btn_sort.clicked.connect(self.sort_emails)
        self.pushButton_4.clicked.connect(self.show_last_folder)
        self.pushButton_3.clicked.connect(self.open_settings)
        self.btn_show_tomyself.clicked.connect(self.show_tomyself)

        self.last_folder = "in"

        self.settings_window = SettingWindow()

        self.list_selected_files = []
        self.list_sent_file = []
        self.array_mes = []

        self.label_7.setText(username[:username.find("@")])
        self.label_6.setText(username)

        create_avatar(username[0])
        # Загружаем изображение
        current_folder = os.path.dirname(__file__)
        file_path = os.path.join(current_folder, "..", "avatar", "avatar.png")
        pixmap = QPixmap(file_path)
        self.label_13.setPixmap(pixmap)

        self.temp_sort = True # сортировка: сначала старые
        
        # Создаем таймер
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_content)  # Подключаем таймер к функции
        self.timer.start(5000)  # Таймер срабатывает каждые 5000 мс (5 секунд)

        # Таймер, который будет использоваться для отслеживания ввода
        self.timer2 = QTimer(self)
        self.timer2.setSingleShot(True)
        self.timer2.timeout.connect(self.on_input_finished)

        # Настраиваем таймер
        self.timer3 = QTimer(self)
        self.timer3.timeout.connect(self.check_size)
        self.timer3.start(100)  # Проверяем каждые 100 мс

        # Настраиваем таймер
        self.timer4 = QTimer(self)
        self.timer4.setSingleShot(True)
        self.timer4.timeout.connect(self.movement_finished)

        # Подключаем сигнал изменения текста к слоту
        self.search_input.textChanged.connect(self.on_text_changed)
        self.text_changed = False

        self.can_timer = True


        # Укажите ваши данные
        # username = "q@a-25.bizml.ru"
        # password = "mf6tB7Bi6fE0WmPZbiGQ"
        # imap_server = "imap.mail.ru"  # Замените на адрес вашего IMAP-сервера

        # Подключение к серверу
        self.mail = imaplib.IMAP4_SSL(self.imap_server) # 1 способ
        # self.mail = aioimaplib.IMAP4_SSL(self.imap_server)
        
        # Логин
        self.mail.login(self.username, self.password)

        # Получение списка почтовых ящиков
        # mailboxes = self.mail.list()
        # print(mailboxes)
        # print(mailboxes[1])
        self.get_mailbox()


        # Выбор почтового ящика (например, "INBOX")
        self.mail.select("INBOX")

        # Булевая переменная для отслеживания завершения перемещения
        self.is_moving = False

        self.mail_ids = []
        body = []


        self.dr()
        # # Поиск писем
        # status, messages = self.mail.search(None, 'ALL')
        # # imap.search(None, "UNSEEN") непрочиатнные письма

        # # Преобразуем список идентификаторов писем в список
        # self.mail_ids = messages[0].split()

        # temp_ind = 0
        # self.array_mes = []
        # self.list_msg = []


        # f = 0
        # for i in self.mail_ids[-5:]:
        #     # Получаем письмо
        #     status, msg_data = self.mail.fetch(i, '(RFC822)')
            
        #     # Получаем сообщение
        #     msg = email.message_from_bytes(msg_data[0][1])
            
        #     # print(email.message_from_bytes(msg_data[0][1]))
        #     # print(msg["Message-ID"]) # айди письма
        #     sender = msg["Return-path"][1:-1] # e-mail отправителя

        #     # Декодируем заголовок темы
        #     subject, encoding = decode_header(msg["Subject"])[0]
        #     if isinstance(subject, bytes):
        #         subject = subject.decode(encoding if encoding else 'utf-8')
            
        #     # Получаем дату
        #     date_str = msg["Date"]
        #     date = email.utils.parsedate_to_datetime(date_str)

        #     # Получаем текстовое содержание письма
        #     if msg.is_multipart():
        #         # Если письмо многосоставное, получаем текст из частей
        #         for part in msg.walk():
        #             if part.get_content_type() == "text/plain":  # Только текстовые части
        #                 body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
        #                 break
        #     else:
        #         # Если письмо одночастное
        #         body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8')

        #     # Выводим информацию
        #     # print(f"Subject: {subject}")
        #     # print(f"Date: {date.strftime('%Y-%m-%d %H:%M:%S')}")
        #     # print(f"Body: {body}...")
        #     # print("=" * 40)
        #     bool_attachments = False
        #     if self.check_attachments_in_email(msg):
        #         # print(f"Письмо имеет вложения.")
        #         # сохраниение
        #         # self.save_attachments(email.message_from_bytes(msg_data[0][1]), "download")
        #         bool_attachments = True
        #     else:
        #         pass
        #         # print(f"Письмо не имеет вложений.")
            
        #     frame = ClickableFrame("framet"+str(temp_ind), sender, subject, date.strftime('%S:%M:%H %d-%m-%Y'), body, bool_attachments, msg)

        #     self.verticalLayout.addWidget(frame)

        #     # self.verticalLayout
        #     # usert.setText("qwe")
        #     # subt.setText("Subject")
        #     # labelt.setText("uhjfeurh uh qke eqdrfre f wef")
        #     temp_ind += 1
        #     # framet.mousePressEvent = self.on_frame_click
        #     # array_mes.append([framet, checkbox, icont, usert, subt, labelt])
        #     self.array_mes.append(frame)
        #     self.list_msg.append(msg)
        
        # # for i in self.array_mes:
        # #     print(i[0].objectName())
        # # self.frame_19.setAlignment(QtCore.Qt.Alignment)
        # # self.frame_19.mousePressEvent = self.on_frame_click
        
        
        # # Закрываем соединение
        # # self.mail.logout()
        # self.last_size = self.size()

    def get_mailbox(self):
        # Получение списка почтовых ящиков
        status, mailbox_list = self.mail.list()

        # Обработка результата
        if status == 'OK':
            mailboxes = []
            for mailbox in mailbox_list:
                # Разделяем строку и извлекаем название ящика
                mailbox_name = mailbox.decode().split(' "/" ')[-1]
                mailboxes.append(mailbox_name.split()[-1])
            print("Доступные почтовые ящики:", mailboxes)
        else:
            print("Ошибка при получении списка ящиков")

    def dr(self, must_render=False):
        if len(self.search_input.toPlainText())>0:
            return
        # self.mail.select('Outbox')
        try:
            status, messages = self.mail.search(None, 'ALL')
        except:
            self.mail.select("INBOX")
            status, messages = self.mail.search(None, 'ALL')
        if not must_render:
            if len(messages[0].split()) == len(self.mail_ids):
                return 0
        self.d()
        self.mail_ids = messages[0].split()
        temp_ind = 0
        self.array_mes = []
        self.list_msg = []
        print("SORT", self.temp_sort)
        if not self.temp_sort:
            self.mail_ids = self.mail_ids[::-1]
        for i in self.mail_ids[-10::]:
            # Получаем письмо
            status, msg_data = self.mail.fetch(i, '(RFC822)')
            
            # Получаем сообщение
            msg = email.message_from_bytes(msg_data[0][1])

            sender = msg["Return-path"][::] # e-mail отправителя

            # Декодируем заголовок темы
            subject, encoding = decode_header(msg["Subject"])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding if encoding else 'utf-8')
            
            # Получаем дату
            date_str = msg["Date"]
            date = email.utils.parsedate_to_datetime(date_str)
            body = ''
            # Получаем текстовое содержание письма
            if msg.is_multipart():
                # Если письмо многосоставное, получаем текст из частей
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":  # Только текстовые части
                        body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
                        break
            else:
                # Если письмо одночастное
                body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8')

            bool_attachments = False
            if self.check_attachments_in_email(msg):
                bool_attachments = True
            
            # decrypt_aes256(self.secret_key, body)
            frame = ClickableFrame("framet"+str(temp_ind), sender, subject, date.strftime('%S:%M:%H %d-%m-%Y'), decrypt_aes256(self.secret_key, body), bool_attachments, msg)

            self.verticalLayout.addWidget(frame)
            temp_ind += 1
            self.array_mes.append(frame)
            self.list_msg.append(msg)

    def show_last_folder(self):
        if self.last_folder == "in":
            self.show_incoming()
        elif self.last_folder == "se":
            self.show_sent_messages()
        elif self.last_folder == 'yo':
            self.show_tomyself()
        else:
            print("ERROR")

    def moveEvent(self, event):
        if not self.is_moving:
            self.is_moving = True
            self.can_timer = False
        # Перезапускаем таймер каждый раз при перемещении
        self.timer4.start(200)  # 200 мс, чтобы ожидать остановки

    def movement_finished(self):
        self.is_moving = False
        if not self.text_changed:
            self.can_timer = True

    def resizeEvent(self, event):
        self.can_timer = False

    def check_size(self):
        current_size = self.size()
        if current_size == self.last_size and not self.is_moving:
            self.on_no_resize()
        else:
            # Обновляем последние размеры, если они изменились
            self.last_size = current_size

    def on_no_resize(self):
        if not self.text_changed:
            self.can_timer = True

    def open_settings(self):
        self.settings_window.show()

    def on_text_changed(self):
        self.can_timer = False
        self.text_changed = True
        # Сброс таймера при каждом изменении текста
        self.timer2.start(1000)  # 1000 мс (1 секунда)

    def stop_timer(self):
        self.timer.stop()
        self.timer2.stop()

    def on_input_finished(self):
        self.text_changed = False
        input_text = self.search_input.toPlainText()
        print(f"Ввод закончен: <{input_text}>")
        if input_text != "":
            self.can_timer = False
            self.search_message(input_text)
            # self.stop_timer()
        else:
            self.can_timer = True

            self.dr()
            # new
            # self.receiving_emails()
            # self.rendering_messages()


            # self.timer.start(5000)
            # self.timer2.start(1000)

    def search_message(self, find_text):
        # for i in range(len(self.array_mes)):
        #     if self.array_mes[i].sende.find(find_text) != -1 or self.array_mes[i].subject.find(find_text) != -1 or self.array_mes[i].tbody.find(find_text) != -1:
        #         # print(self.array_mes[i].sende.find(find_text), self.array_mes[i].subject.find(find_text))
        #         continue
        #     self.array_mes[i].deleteLater()
        #     print('del')

        i = 0
        while i < len(self.array_mes):
            if self.array_mes[i].sende.find(find_text) != -1 or self.array_mes[i].subject.find(find_text) != -1 or self.array_mes[i].tbody.find(find_text) != -1:
                i += 1
                continue
            self.array_mes[i].deleteLater()
            self.array_mes.pop(i)
            self.list_msg.pop(i)
            self.mail_ids.pop(i)
        print(self.array_mes, self.mail_ids)

    def sort_emails(self):
        # self.receiving_emails()
        self.temp_sort = not self.temp_sort
        # self.list_msg.sort(key=lambda x: email.utils.parsedate(x['Date']), reverse=self.temp_sort)
        # print(self.list_msg)
        if not self.temp_sort:
            self.btn_sort.setText("Сначала новые")
            # self.mail_ids = self.mail_ids[::-1]
        else:
            self.btn_sort.setText("Сначала старые")
        
        # print(self.mail_ids)

        self.dr(must_render=True)
        # self.rendering_messages()

    def canceling_sending_message(self):
        self.show_incoming()
        self.clear_message_sending_form()

    def rendering_messages(self):
        self.d()
        temp_ind = 0
        self.array_mes = []

        print('start rendering')
        print("len list msg:", len(self.list_msg))
        for i in self.list_msg[-5:]:
            sender = i["Return-path"][1:-1] # e-mail отправителя

            # Декодируем заголовок темы
            subject, encoding = decode_header(i["Subject"])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding if encoding else 'utf-8')
            
            # Получаем дату
            date_str = i["Date"]
            date = email.utils.parsedate_to_datetime(date_str)

            # Получаем текстовое содержание письма
            if i.is_multipart():
                # Если письмо многосоставное, получаем текст из частей
                for part in i.walk():
                    if part.get_content_type() == "text/plain":  # Только текстовые части
                        body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
                        break
            else:
                # Если письмо одночастное
                body = i.get_payload(decode=True).decode(i.get_content_charset() or 'utf-8')

            bool_attachments = False
            if self.check_attachments_in_email(i):
                bool_attachments = True
            else:
                pass
            # print(type(body))
            # print(decrypt_aes256(self.secret_key, body))
            frame = ClickableFrame("framet"+str(temp_ind), sender, subject, date.strftime('%S:%M:%H %d-%m-%Y'), decrypt_aes256(self.secret_key, body), bool_attachments, i)
            # print(decrypt_aes256(self.secret_key, body))
            self.verticalLayout.addWidget(frame)
            temp_ind += 1
            self.array_mes.append(frame)
        print('end rendering')

    def receiving_emails(self): # получение писем
        # Поиск писем
        status, messages = self.mail.search(None, 'ALL')
        # imap.search(None, "UNSEEN") непрочиатнные письма
        if len(messages[0].split()) != len(self.mail_ids):
            print("Есть что-то новое")
            # Преобразуем список идентификаторов писем в список
        self.mail_ids = messages[0].split()

        self.list_msg = []
        for i in self.mail_ids:
            # Получаем письмо
            status, msg_data = self.mail.fetch(i, '(RFC822)')

            # Получаем сообщение
            msg = email.message_from_bytes(msg_data[0][1])
            self.list_msg.append(msg)

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Message',
                                     "Are you sure you want to quit?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            # Закрываем соединение
            self.mail.logout()
            event.accept()  # Закрыть приложение
        else:
            event.ignore()  # Игнорировать событие закрытия

    def delete_message(self):
        for i in range(len(self.array_mes)):
            if self.array_mes[i].checkbox.isChecked():
                self.mail.store(self.mail_ids[i], '+FLAGS', '\\Deleted')
        self.mail.expunge()
        self.checkBox.setChecked(False)
        self.dr()
        # self.receiving_emails()
        # self.rendering_messages()

    def select_all(self, checked):
        if checked:
            for i in range(len(self.array_mes)):
                self.array_mes[i].checkbox.setChecked(True)
        else:
            for i in range(len(self.array_mes)):
                self.array_mes[i].checkbox.setChecked(False)

    def save_attachments(self, email_message, save_dir):
        """
        Сохраняет вложения из сообщения электронной почты.
        Args:
            email_message: Объект email.message.Message.
            save_dir: Директория, куда сохранить вложения.
        """
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                if part.get('Content-Disposition'):
                    filename = part.get_filename()
                    if filename:
                        filename = decode_header(filename)[0][0]
                        if isinstance(filename, bytes):
                            filename = filename.decode('utf-8')
                        filepath = os.path.join(save_dir, filename)
                        with open(filepath, 'wb') as f:
                            f.write(part.get_payload(decode=True))
                        print(f"Сохранён файл: {filename} в {save_dir}")

    def check_attachments_in_email(self, email_message):
        """
        Проверяет, есть ли вложения в сообщении электронной почты.
        Args:
            email_message: Объект email.message.Message.

        Returns:
            bool: True, если есть вложения, False в противном случае.
        """
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                if part.get('Content-Disposition'):
                    return True
        return False

    def on_frame_click(self, event):
        print(self.sender().objectName())

    def truncate_text(self, text, available_width):
        # Обрезаем текст и добавляем многоточие, если он слишком длинный
        if self.label.fontMetrics().width(text) <= available_width:
            return text
        else:
            # Обрезаем текст
            truncated_text = text
            while self.label.fontMetrics().width(truncated_text + "...") > available_width:
                truncated_text = truncated_text[:-1]  # Убираем один символ
            return truncated_text + "..."

    def new_message(self): # новое сообщение
        # self.stop_timer()
        print("Новое письмо")
        if self.form_sending.isVisible():
            self.form_sending.hide()  # Или self.form_sending.setVisible(False)
            self.form_messages.show()
            self.form_configuration.show()
            self.search_input.show()
            self.data_message.hide()
        else:
            self.form_sending.show()  # Или self.form_sending.setVisible(True)
            self.form_messages.hide()
            self.form_configuration.hide()
            self.search_input.hide()
            self.data_message.hide()

    def show_incoming(self): # Входящие
        # self.timer.start(5000)
        # self.timer2.start(500)
        for i in range(len(self.list_sent_file)):
            self.list_sent_file[i].deleteLater()
        self.list_sent_file = []
        self.checkBox.show()
        self.label_14.show()
        self.btn_sort.show()
        print("Показать входящие")
        self.mail.select("INBOX")
        # self.receiving_emails()
        # self.rendering_messages()
        if not self.form_messages.isVisible():
            self.form_sending.hide()  # Или self.form_sending.setVisible(False)
            self.form_messages.show()
            self.form_configuration.show()
            self.search_input.show()
            self.data_message.hide()
            self.pushButton_4.hide()
        else:
            self.data_message.hide()
            self.pushButton_4.hide()

        if self.last_folder != 'in':
            self.dr()
            # self.receiving_emails()
            # self.rendering_messages()
        self.last_folder = 'in'

    def show_sent_messages(self): # Отправленные
        self.data_message.hide()
        self.form_messages.show()
        print("Показать отправленные сообщения")
        try:
            self.mail.select("&BB4EQgQ,BEAEMAQyBDsENQQ9BD0ESwQ1-")
        except:
            self.mail.select("INBOX")
        # self.receiving_emails()
        # self.rendering_messages()
        # # Получаем текущий выбранный почтовый ящик
        # status, current_mailbox = self.mail.status('INBOX', "(MESSAGES UNSEEN)")
        # print(f"Выбранный почтовый ящик: {current_mailbox}")
        # self.d()
        if not self.form_messages.isVisible():
            self.form_sending.hide()  # Или self.form_sending.setVisible(False)
            self.form_messages.show()
            self.form_configuration.show()
            self.search_input.show()
            self.data_message.hide()
            self.pushButton_4.hide()
        else:
            self.data_message.hide()
            self.pushButton_4.hide()
        if self.last_folder != 'se':
            self.dr()
            # self.receiving_emails()
            # self.rendering_messages()
        self.last_folder = 'se'

    def show_tomyself(self): # Письма себе
        self.data_message.hide()
        self.form_messages.show()
        print("Показать письма себе")
        try:
            self.mail.select("INBOX/ToMyself")
        except:
            self.mail.select("INBOX")
        if self.last_folder != 'yo':
            self.dr()
            # self.receiving_emails()
            # self.rendering_messages()
        # self.receiving_emails()
        # self.rendering_messages()
        self.last_folder = 'yo'

    def d(self):
        for i in range(len(self.array_mes)):
            self.array_mes[i].deleteLater()
        self.array_mes.clear()
    
    def show_data_message(self, sender, subject, date, body, bool_attachments, msg):
        print(sender, subject, date,)
        # self.stop_timer()
        self.checkBox.hide()
        self.label_14.hide()
        self.btn_sort.hide()
        for i in range(len(self.list_sent_file)):
            self.list_sent_file[i].hide()
        self.list_sent_file = []
        if not self.data_message.isVisible():
            self.label_4.setText(sender)
            self.label_5.setText(subject)
            self.label_11.setText(date)
            # self.label_12.setText(body)
            self.label_12.setText(decrypt_aes256(self.secret_key, body))
            self.data_message.show()
            self.form_messages.hide()
            self.form_sending.hide()
            # self.form_configuration.hide()
            self.search_input.hide()
            if bool_attachments:
                self.scrollArea.show()
            else:
                self.scrollArea.hide()
            self.pushButton_4.show()
            if bool_attachments:
                self.scrollArea.show()
                print("Есть прикреплённые файлы")
                # Проверяем, есть ли вложения
                if msg.is_multipart():
                    for part in msg.walk():
                        # Если часть является вложением
                        if part.get_content_maintype() == 'multipart':
                            continue
                        if part.get('Content-Disposition') is None:
                            continue
                        
                        try:
                            filename = decode_mime_words(part.get_filename())
                        except:
                            filename = "error"
                        # filename = part.get_filename()
                        # print(filename)
                        f = SentFile(len(self.list_sent_file), filename, part)
                        self.list_sent_file.append(f)
                        self.horizontalLayout_17.addWidget(f)
                    else:
                        print("Нет прикреплённых файлов")
        else:
            self.scrollArea.hide()
            self.data_message.hide()
            self.form_messages.hide()
            self.form_sending.hide()
            self.pushButton_4.hide()
    
    def download_file(self, filename, part):
        if filename:
            current_folder = os.path.dirname(__file__)
            # Создаем папку для загрузок, если она не существует
            if not os.path.exists(os.path.join(current_folder, "..", "downloads")):
                os.makedirs('downloads')
            # Скачиваем файл
            filename = filename[filename.rfind('\\')+1::]
            file_path = os.path.join(current_folder, "..", "downloads", filename)
            with open(file_path, 'wb') as f:
                f.write(part.get_payload(decode=True))
            print(f'Скачан: {file_path}')
            decrypt_file(file_path)
            QMessageBox.information(self, "Уведомление", f'Скачан: {file_path}')

    def sent_email(self):
        # Создаем сообщение
        msg = MIMEMultipart()
        msg['From'] = win.textEdit_2.toPlainText()
        msg['To'] = self.textEdit_3.toPlainText()
        msg['Subject'] = self.textEdit_2.toPlainText()

        # Текст сообщения
        # body = self.input_text_email.toPlainText()
        # msg.attach(MIMEText(body, 'plain'))
        # win.server.send_message(msg)

        # Текст сообщения
        body = encrypt_aes256(self.secret_key, self.input_text_email.toPlainText())
        msg.attach(MIMEText(body, 'plain'))

        for i in range(len(self.list_selected_files)):
            encrypt_file(self.list_selected_files[i].file_address)

            # Открываем файл в двоичном режиме
            current_folder = os.path.dirname(__file__)
            file_name = self.list_selected_files[i].file_address[self.list_selected_files[i].file_address.rfind('/')+1::]
            file_path = os.path.join(current_folder, "..", "encrypted_files", file_name + ".encrypted")
            with open(file_path, 'rb') as attachment:
                # Создаем объект MIMEBase
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())

            # Кодируем файл в base64
            encoders.encode_base64(part)
            temp = self.list_selected_files[i].file_address[self.list_selected_files[i].file_address.rfind('/')+1::].replace(' ', '_')[-10::]
            print(temp)
            current_folder = os.path.dirname(__file__)
            file_path = os.path.join(current_folder, "..", "encrypted_files", temp + ".encrypted")
            part.add_header('Content-Disposition', f'attachment; filename={file_path}')
            # part.add_header('Content-Disposition', f'attachment; filename={self.list_selected_files[i].file_address + ".encrypted"}')

            # Прикрепляем файл к сообщению
            msg.attach(part)

        # Отправка сообщения
        try:
            win.server = smtplib.SMTP(win.textEdit.toPlainText(), 587)
            win.server.starttls()  # Защита соединения
            win.server.login(win.textEdit_2.toPlainText(), win.textEdit_3.toPlainText())
            win.server.send_message(msg)
            print('Письмо отправлено успешно! 😊')
            self.show_incoming()
            self.clear_message_sending_form()

        except Exception as e:
            print(f'Произошла ошибка: {e} 😞')

    def clear_message_sending_form(self):
        self.textEdit_3.setText("")
        self.textEdit_2.setText("")
        self.input_text_email.setText("")
        self.delete_all_selected_files()

    def update_content(self):
        if self.can_timer:
            try:
                print("<!> Обновление!", self.can_timer)
                self.dr()
                return
                last_count_emails = len(self.mail_ids)
                self.receiving_emails()
                new_count_emails = len(self.mail_ids)
                if last_count_emails != new_count_emails:
                    self.d()
                    self.rendering_messages()
            except:
                pass

    def open_file_dialog(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Выберите файл", "", "Все файлы (*);;Текстовые файлы (*.txt)", options=options)
        if file_name:
            if len(self.list_selected_files) == 0:
                self.scrollArea_3.show()

            print(f"Выбранный файл: {file_name}")  

            t = file_name[file_name.rfind("/")+1::]

            ts = SelectedFile(len(self.list_selected_files), t, file_name)
            # self.scrollArea_3.setWidget(ts)
            self.horizontalLayout_15.addWidget(ts)
            # self.horizontalLayout_15.addWidget(ts)
            self.list_selected_files.append(ts)
            # self.pushButton_112 = QtWidgets.QPushButton(self.scrollAreaWidgetContents_3)
            # sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
            # sizePolicy.setHorizontalStretch(0)
            # sizePolicy.setVerticalStretch(0)
            # sizePolicy.setHeightForWidth(self.pushButton_112.sizePolicy().hasHeightForWidth())
            # self.pushButton_112.setSizePolicy(sizePolicy)
            # self.pushButton_112.setMinimumSize(QtCore.QSize(100, 100))
            # self.pushButton_112.setMaximumSize(QtCore.QSize(100, 100))
            # self.pushButton_112.setObjectName("pushButton_112")
            # self.horizontalLayout_15.addWidget(self.pushButton_112, 0, QtCore.Qt.AlignLeft)
            # self.pushButton_112.setText(file_name[file_name.rfind("/")+1::])

    def delete_selected_file(self, number):
        self.list_selected_files[number].deleteLater()
        self.list_selected_files.pop(number)
        print(self.list_selected_files)
        for i in range(number, len(self.list_selected_files)):
            self.list_selected_files[i].number -= 1
        if len(self.list_selected_files) == 0:
            self.scrollArea_3.hide()

    def delete_all_selected_files(self):
        for i in range(len(self.list_selected_files)):
            self.list_selected_files[0].deleteLater()
            self.list_selected_files.pop(0)
        print("Удалены все прикреплённые файлы")

class ClickableFrame(QFrame):
    def __init__(self, name, sender, subject, date, body, bool_attachments, msg, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # print(name, sender, subject, date)
        self.name = name
        self.sende = sender
        self.subject = subject
        self.date = date
        self.body = body
        # self.body = decrypt_aes256(win.window.secret_key, self.body)
        self.tbody = body
        self.bool_attachments = bool_attachments
        self.msg = msg

        self.tbody = self.tbody.replace("\n", " ")
        # print(self.body)
        self.tl = self.tbody

        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.sizePolicy().hasHeightForWidth())
        self.setSizePolicy(sizePolicy)
        self.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.setFrameShadow(QtWidgets.QFrame.Raised)
        horizontalLayout_17 = QtWidgets.QHBoxLayout(self)
        horizontalLayout_17.setSpacing(11)
        horizontalLayout_17.setObjectName("horizontalLayout_17")
        self.checkbox = QtWidgets.QCheckBox(self)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.checkbox.sizePolicy().hasHeightForWidth())
        self.checkbox.setSizePolicy(sizePolicy)
        self.checkbox.setText("")
        self.checkbox.setObjectName("checkbox")
        horizontalLayout_17.addWidget(self.checkbox)
        self.usert = QtWidgets.QLabel(self)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.usert.sizePolicy().hasHeightForWidth())
        self.usert.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.usert.setFont(font)
        self.usert.setObjectName("usert")
        horizontalLayout_17.addWidget(self.usert)
        self.subt = QtWidgets.QLabel(self)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.subt.sizePolicy().hasHeightForWidth())
        self.subt.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.subt.setFont(font)
        self.subt.setObjectName("subt")
        horizontalLayout_17.addWidget(self.subt)
        self.labelt = QtWidgets.QLabel(self)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.labelt.sizePolicy().hasHeightForWidth())
        self.labelt.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.labelt.setFont(font)
        self.labelt.setObjectName("labelt")
        horizontalLayout_17.addWidget(self.labelt, 0, QtCore.Qt.AlignLeft)
        self.time = QtWidgets.QLabel(self)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.time.sizePolicy().hasHeightForWidth())
        self.time.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.time.setFont(font)
        self.time.setObjectName("time")
        horizontalLayout_17.addWidget(self.time, 0, QtCore.Qt.AlignRight)

        self.usert.setText(self.sende)
        # l2_max = fr.width() - 49 - self.usert.size().width()
        # self.subt.setText("")
        self.time.setText(self.date)
        # # self.subt.setText(self.subject[0:l2_max])
        # if len(self.subject) > 40:
        #     self.subt.setText(self.subject[0:40]+"...")
        # else:
        #     self.subt.setText(self.subject[0:40])
        if len(self.subject) > 20:
            self.subt.setText(self.subject[:20]+"...")
        else:
            self.subt.setText(self.subject)

    def resizeEvent(self, event):
        self.fr = self.size().width()
        l = self.fr - 82 - self.usert.size().width() - self.subt.size().width() - self.time.size().width()
        # Получаем текущий шрифт и шрифтографику для измерения текста
        font_metrics = QFontMetrics(self.labelt.font())
        max_length = 0
        # Проверяем каждую длину текста и находим максимальную длину, которая помещается в заданной ширине
        for i in range(len(self.tl) + 1):  # +1 для включения полного текста
            if font_metrics.horizontalAdvance(self.tl[:i]) <= l:
                max_length = i
            else:
                break
        self.labelt.setText(self.tbody[:max(0, max_length-13)]+"...")

    def mousePressEvent(self, event):
        print(f"{self.name} was clicked!")
        win.window.show_data_message(self.sende, self.subject, self.date, self.body, self.bool_attachments, self.msg)

class SelectedFile(QFrame):
    def __init__(self, num, text, file_address, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.number = num
        self.text = text
        self.file_address = file_address
        print(num, text, file_address)

        # self.frame_17 = QtWidgets.QFrame(self.scrollAreaWidgetContents_3)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.sizePolicy().hasHeightForWidth())
        self.setSizePolicy(sizePolicy)
        self.setMinimumSize(QtCore.QSize(100, 100))
        self.setMaximumSize(QtCore.QSize(100, 100))
        self.setStyleSheet("background-color: rgb(211, 211, 211)")
        self.setFrameShape(QtWidgets.QFrame.Box)
        self.setFrameShadow(QtWidgets.QFrame.Raised)
        self.setObjectName("frame_17")
        self.gridLayout_3 = QtWidgets.QGridLayout(self)
        self.gridLayout_3.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.label_13 = QtWidgets.QLabel(self)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_13.sizePolicy().hasHeightForWidth())
        self.label_13.setSizePolicy(sizePolicy)
        self.label_13.setMinimumSize(QtCore.QSize(0, 0))
        self.label_13.setMaximumSize(QtCore.QSize(100, 16777215))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.label_13.setFont(font)
        self.label_13.setFrameShadow(QtWidgets.QFrame.Plain)
        self.label_13.setLineWidth(1)
        self.label_13.setMidLineWidth(0)
        self.label_13.setWordWrap(True)
        self.label_13.setObjectName("label_13")
        self.gridLayout_3.addWidget(self.label_13, 0, 0, 1, 1, QtCore.Qt.AlignHCenter|QtCore.Qt.AlignVCenter)
        win.window.horizontalLayout_15.addWidget(self)
        self.label_13.setText(self.text)
    
    def mousePressEvent(self, event):
        print(self.number)
        win.window.delete_selected_file(self.number)

class SentFile(QFrame):
    def __init__(self, num, text, part, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.number = num
        self.text = text
        self.part = part

        # self.frame_17 = QtWidgets.QFrame(self.scrollAreaWidgetContents_3)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.sizePolicy().hasHeightForWidth())
        self.setSizePolicy(sizePolicy)
        self.setMinimumSize(QtCore.QSize(100, 100))
        self.setMaximumSize(QtCore.QSize(100, 100))
        self.setStyleSheet("background-color: rgb(211, 211, 211)")
        self.setFrameShape(QtWidgets.QFrame.Box)
        self.setFrameShadow(QtWidgets.QFrame.Raised)
        self.setObjectName("frame_17")
        self.gridLayout_3 = QtWidgets.QGridLayout(self)
        self.gridLayout_3.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.label_13 = QtWidgets.QLabel(self)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_13.sizePolicy().hasHeightForWidth())
        self.label_13.setSizePolicy(sizePolicy)
        self.label_13.setMinimumSize(QtCore.QSize(0, 0))
        self.label_13.setMaximumSize(QtCore.QSize(100, 16777215))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.label_13.setFont(font)
        self.label_13.setFrameShadow(QtWidgets.QFrame.Plain)
        self.label_13.setLineWidth(1)
        self.label_13.setMidLineWidth(0)
        self.label_13.setWordWrap(True)
        self.label_13.setObjectName("label_13")
        self.gridLayout_3.addWidget(self.label_13, 0, 0, 1, 1, QtCore.Qt.AlignHCenter|QtCore.Qt.AlignVCenter)
        win.window.horizontalLayout_15.addWidget(self)
        self.label_13.setText(self.text)
    
    def mousePressEvent(self, event):
        print(self.number)
        win.window.download_file(self.text, self.part)
        # win.window.delete_selected_file(self.number)

class LoginWindow(QMainWindow, login.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)  # Настройка UI


        w = 0
        if w == 0:
            self.textEdit.setText("smtp.mail.ru") # или imap.mail.ru
            self.textEdit_2.setText("safecomm@mail.ru")
            self.textEdit_3.setText("X5vcL2BsRucWJpZ2z0rU")
        elif w == 1:
            self.textEdit.setText("smtp.yandex.ru") # или imap.mail.ru
            self.textEdit_2.setText("moscowt34@yandex.ru")
            self.textEdit_3.setText("pbweobblozkzbapr")
        elif w == 2:
            self.textEdit.setText("smtp.mail.ru")
            self.textEdit_2.setText("safecomm@mail.ru")
            self.textEdit_3.setText("cbJAyX5sPtUdeZ92aBUx")
        else:
            self.textEdit.setText("smtp.mail.ru")
            self.textEdit_2.setText("safecomm1@mail.ru")
            self.textEdit_3.setText("urKs6CfzthyEVttc5C1L")

        self.pushButton.clicked.connect(self.login)
        self.pushButton_2.clicked.connect(self.close)
    
    def login(self):
        ser = self.textEdit.toPlainText() # по умолчанию smtp.mail.ru
        email = self.textEdit_2.toPlainText()
        password = self.textEdit_3.toPlainText()
        print(ser, email, password, 'imap'+ser[ser.find('.'):ser.rfind('.'):]+ser[ser.rfind('.')::])

        try:
            with smtplib.SMTP(ser, 587) as self.smtp_server: # 587 или 465
                self.smtp_server.starttls()  # Начало защищенной сессии
                self.smtp_server.login(email, password)
                self.window = MainWindow('imap'+ser[ser.find('.'):ser.rfind('.'):]+ser[ser.rfind('.')::], email, password, self.smtp_server)
                self.window.show()
                self.close()
        except smtplib.SMTPAuthenticationError:
            QMessageBox.critical(self, 'Ошибка', 'Неверный логин или пароль.', QMessageBox.Ok)
        except Exception as e:
            QMessageBox.critical(self, 'Ошибка', f'Ошибка: {e}', QMessageBox.Ok)

class SettingWindow(QMainWindow, setting.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)  # Настройка UI

        self.use_your_own_key = False # если Fasle то ключ по умолчанию, иначе свой
        self.radioButton.toggled.connect(self.use_default_key)
        self.radioButton_2.toggled.connect(self.use_own_key)
        self.pushButton_2.clicked.connect(self.copy_to_clipboard)
        self.pushButton_3.clicked.connect(self.safe_setting)
        self.pushButton.clicked.connect(self.generate_key)
        # print(str(base64.urlsafe_b64encode(open('your_key.key', 'rb').read()))[2:-1:])

        current_folder = os.path.dirname(__file__)
        file_path = os.path.join(current_folder, "..", "key", "your_key")
        self.textEdit.setText(str(base64.urlsafe_b64encode(open(file_path, 'rb').read()))[2:-1:])
        # self.textEdit.setText(str(base64.urlsafe_b64encode(open('your_key.key', 'rb').read()))[2:-1:])

    def safe_setting(self):
        global use_default_key
        if self.use_your_own_key:
            if len(self.textEdit.toPlainText())==44:
                use_default_key = False
                win.window.secret_key = load_key()

                current_folder = os.path.dirname(__file__)
                file_path = os.path.join(current_folder, "..", "key", "your_key")

                with open(file_path, 'wb') as key_file:
                    key_file.write(private_key)
                QMessageBox.information(self, "Успех", "Настойки успешно изменены.")
            else:
                QMessageBox.critical(self, "Ошибка", "Ошибка формата ключа") # Показываем диалог ошибки
        else:
            use_default_key = True
            win.window.secret_key = load_key()
            QMessageBox.information(self, "Успех", "Настойки успешно изменены.")

    def use_default_key(self):
        # use_default_key = True
        self.use_your_own_key = False
        self.textEdit.setEnabled(False)
        self.pushButton.setEnabled(False)
        self.pushButton_2.setEnabled(False)

    def use_own_key(self):
        # use_default_key = False
        self.use_your_own_key = True
        self.textEdit.setEnabled(True)
        self.pushButton.setEnabled(True)
        self.pushButton_2.setEnabled(True)

    def copy_to_clipboard(self):
        # Получаем текст из поля ввода
        text_to_copy = self.textEdit.toPlainText()
        
        # Копируем текст в буфер обмена
        clipboard = QApplication.clipboard()
        clipboard.setText(text_to_copy)

    def generate_key(self):
        generate_key()
        self.textEdit.setText(str(base64.urlsafe_b64encode(private_key))[2:-1:])
        # win.window.secret_key = get_random_bytes(32)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = LoginWindow()
    win.show()
    sys.exit(app.exec_())
