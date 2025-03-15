import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Данные для подключения
smtp_server = "smtp.yandex.ru"
smtp_port = 465  # Для SSL
login = "moscowt34@yandex.ru"
password = "cmdlcrpngybvqsnm"

# Создание письма
msg = MIMEMultipart()
msg["From"] = login
msg["To"] = "moscowt34@yandex.ru"
msg["Subject"] = "Тестовое письмо"
body = "Это тестовое письмо, отправленное через SMTP Yandex."
msg.attach(MIMEText(body, "plain"))

# Подключение и отправка
try:
    with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
        server.login(login, password)
        server.sendmail(login, msg["To"], msg.as_string())
        print("Письмо успешно отправлено!")
except Exception as e:
    print(f"Ошибка при отправке письма: {e}")