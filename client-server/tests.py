import unittest
from server import TrentServer
from client_a import Participant
from utils import (
    generate_ec_key_pair,
    serialize_public_key,
    deserialize_public_key,
    generate_shared_key,
    encrypt_message,
    decrypt_message,
)

class TestDASS(unittest.TestCase):

    def setUp(self):
        # Инициализируем сервер и двух клиентов
        self.server = TrentServer('localhost', 8080)
        self.alice = Participant('Alice', 'localhost', 8080)
        self.bob = Participant('Bob', 'localhost', 8080)

        # Регистрация клиентов на сервере
        self.server.keys['Alice'] = serialize_public_key(self.alice.public_key).decode('utf-8')
        self.server.keys['Bob'] = serialize_public_key(self.bob.public_key).decode('utf-8')

    def test_registration(self):
        """Проверяем регистрацию клиентов на сервере"""
        self.assertIn('Alice', self.server.keys, "Alice не зарегистрирована")
        self.assertIn('Bob', self.server.keys, "Bob не зарегистрирован")

    def test_key_exchange(self):
        """Проверяем корректность получения публичного ключа"""
        # Получаем ключи из сервера
        alice_key = self.server.keys['Alice']
        bob_key = self.server.keys['Bob']

        # Убеждаемся, что ключи есть
        self.assertIsNotNone(alice_key, "Публичный ключ Alice не найден на сервере")
        self.assertIsNotNone(bob_key, "Публичный ключ Bob не найден на сервере")

        # Проверяем, что публичные ключи корректно сериализуются и десериализуются
        alice_deserialized = deserialize_public_key(alice_key.encode('utf-8'))
        bob_deserialized = deserialize_public_key(bob_key.encode('utf-8'))

        # Сравниваем исходный и десериализованный ключи
        self.assertEqual(
            serialize_public_key(self.alice.public_key),
            serialize_public_key(alice_deserialized),
            "Публичный ключ Alice не совпадает"
        )
        self.assertEqual(
            serialize_public_key(self.bob.public_key),
            serialize_public_key(bob_deserialized),
            "Публичный ключ Bob не совпадает"
        )

    def test_shared_key_generation(self):
        """Проверяем корректность генерации общего ключа"""
        # Alice генерирует общий ключ с Bob
        alice_shared_key = generate_shared_key(self.alice.private_key, self.bob.public_key)

        # Bob генерирует общий ключ с Alice
        bob_shared_key = generate_shared_key(self.bob.private_key, self.alice.public_key)

        # Общие ключи должны совпадать
        self.assertEqual(alice_shared_key, bob_shared_key, "Общие ключи не совпадают")

    def test_message_encryption_and_decryption(self):
        """Проверяем шифрование и расшифровку сообщений"""
        # Генерация общего ключа
        shared_key = generate_shared_key(self.alice.private_key, self.bob.public_key)

        # Alice шифрует сообщение
        plaintext = b"Hello, Bob!"
        encrypted_message = encrypt_message(shared_key, plaintext)

        # Bob расшифровывает сообщение
        decrypted_message = decrypt_message(shared_key, encrypted_message)

        # Проверяем, что расшифрованное сообщение совпадает с исходным
        self.assertEqual(plaintext, decrypted_message, "Сообщение после расшифровки не совпадает с исходным")

    def test_end_to_end_communication(self):
        """Тестируем обмен сообщениями между Alice и Bob"""
        # Alice получает публичный ключ Bob с сервера
        bob_public_key = deserialize_public_key(self.server.keys['Bob'].encode('utf-8'))

        # Генерация общего ключа
        shared_key = generate_shared_key(self.alice.private_key, bob_public_key)

        # Alice шифрует сообщение и отправляет его Bob
        plaintext = b"Hi Bob, it's Alice!"
        encrypted_message = encrypt_message(shared_key, plaintext)

        # Bob получает сообщение и расшифровывает его
        decrypted_message = decrypt_message(shared_key, encrypted_message)

        # Проверяем, что сообщение расшифровано корректно
        self.assertEqual(plaintext, decrypted_message, "Расшифрованное сообщение не совпадает с исходным")

if __name__ == '__main__':
    unittest.main()
