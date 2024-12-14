import socket
import json
import threading
import logging
import traceback
from concurrent.futures import ThreadPoolExecutor



class TrentServer:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.clients = []  # [...,[Name,socket,key],...]
        self.lock = threading.Lock()
        
        self.logger = logging.getLogger('TrentServer')
        self.logger.setLevel(logging.INFO)
        self.set_up_logger_config()
        
    def set_up_logger_config(self):
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler('trent_server.log')
        file_handler.setLevel(logging.DEBUG)

        # Форматирование логов
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)

        # Добавляем обработчики к логгеру
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        
    def broadcast(self, message, sender_socket, name):
        clients_to_send = []
        for client in self.clients:
            if client[1] != sender_socket: 
                try:
                    client[1].sendall(message)
                    clients_to_send.append(client[0])
                except (socket.error, OSError) as e:
                    self.logger.error(f"Failed to send message to {client[0]}: {e}")
        return clients_to_send
                
    def handle_client(self, client_socket, addr):
        name = None
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    continue
                request = json.loads(data.decode('utf-8'))
                self.logger.info(f"Received request from {addr}: {request}")
                
                # Регистрация клиента
                if request['type'] == 'register':
                    name = request['name']
                    with self.lock:
                        self.clients.append([name, client_socket, request['public_key']])
                    # self.logger.debug(f'Active clients:')
                    # for cl in self.clients:
                    #     self.logger.debug(f'Name: {cl[0]} \n\t socket: {cl[1]}, \n\t key: {cl[2]}')
                    client_socket.sendall(b'Registration successful')
                    self.logger.info(f"Registered {name} with public key.")

                # Запрос публичного ключа [need to fix (threads competition)]
                elif request['type'] == 'get_key':
                    key = None
                    for cl in self.clients:
                        if cl[0] == request['target']:
                            key = cl[2]
                            self.logger.debug(f'Transfred key owner: {cl[0]}')
                    if key:
                        key_msg = json.dumps({
                                    'type': 'key',
                                    'from': name,
                                    'public_key': key
                                }).encode('utf-8')
                        clients_to_send = self.broadcast(key_msg, cl[1], cl[0])
                        self.logger.debug(f"Sent public key for {request['target']} to {clients_to_send}.")
                    else:
                        self.logger.debug('Key not found')


                # Пересылка сообщений
                elif request['type'] == 'send_message':
                    target = request['target']
                    message = request['message']
                    with self.lock:  # Блокировка при доступе к self.clients
                        actual_clients = [cl_name[0] for cl_name in self.clients]
                        self.logger.debug(f'Actual clients: {actual_clients}')
                        if target in actual_clients:
                            try:
                                print('msg', message.encode('utf-8'))
                                cl = self.broadcast(json.dumps({
                                    'from': name,
                                    'message': message
                                }).encode('utf-8'),client_socket, name)
                                self.logger.info(f"Forwarded message from {name} to {cl}.")
                            except (OSError, socket.error) as e:
                                self.logger.error(f"Error sending message to {target}: {e}")
                                client_socket.sendall(b'Target not available')
        except Exception as e:
            self.logger.info(f"Error with client {addr}: {e}")
            error_details = traceback.format_exc()
            self.logger.error(f"{e}\n{error_details}")
            client_socket.close()
            self.remove_client(client_socket)
        finally:
            pass


    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            self.logger.info(f"Server is listening on {self.host}:{self.port}")
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                while True:
                    client_socket, addr = server_socket.accept()
                    self.logger.info(f"Connection from {addr}")
                    executor.submit(self.handle_client, client_socket, addr)

    def remove_client(self, client_socket):
        with self.lock:
            self.clients = [cl for cl in self.clients if cl[1] != client_socket]
            self.logger.info(f"Removed client with socket {client_socket}")


if __name__ == "__main__":
    trent = TrentServer('localhost', 8080)
    trent.start()