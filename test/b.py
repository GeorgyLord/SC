import sys
import imaplib
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QMessageBox

class IMAPChecker(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('IMAP Connection Checker')
        self.setGeometry(100, 100, 300, 200)

        layout = QVBoxLayout()

        self.check_button = QPushButton('Check IMAP Connection', self)
        self.check_button.clicked.connect(self.check_imap_connection)
        layout.addWidget(self.check_button)

        self.setLayout(layout)

    def check_imap_connection(self):
        imap_server = 'imap.mail.ru'
        imap_port = 993
        imap_user = 'safecomm@mail.ru'
        imap_password = 'X5vcL2BsRucWJpZ2z0rU'

        try:
            print(1)
            # Пытаемся подключиться к IMAP-серверу
            with imaplib.IMAP4_SSL(imap_server, imap_port) as server:
                print(2)
                server.login(imap_user, imap_password)
                print(3)
                server.logout()  # Закрываем соединение после успешной проверки
            QMessageBox.information(self, 'Success', 'IMAP connection successful!')
        except Exception as e:
            print(4)
            # В случае ошибки выводим сообщение и закрываем окно
            QMessageBox.critical(self, 'Error', f'Failed to connect to IMAP server: {str(e)}')
            self.close()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = IMAPChecker()
    window.show()
    sys.exit(app.exec_())