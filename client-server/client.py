import socket
import json
import threading
from utils import *


class Participant:
    def __init__(self, name, trent_host, trent_port, client_s = None):
        self.name = name
        self.trent_host = trent_host
        self.trent_port = trent_port
        # self.private_key, self.public_key = generate_ec_key_pair()
        self.private_key, self.public_key = load_keys_from_files(f'{name}_private_key.pem', f'{name}_public_key.pem')
        self.client_socket = client_s
        # save_keys_to_files(self.private_key, self.public_key, f'{name}_private_key.pem', f'{name}_public_key.pem')

    def register_with_trent(self):
        request = {
            'type': 'register',
            'name': self.name,
            'public_key': serialize_public_key(self.public_key).decode('utf-8')
        }
        self.client_socket.send(json.dumps(request).encode('utf-8'))
        print(serialize_public_key(self.public_key).decode('utf-8').encode('utf-8'))
        response = self.client_socket.recv(1024)
        print(f"Trent response: {response.decode('utf-8')}")
    
    def get_peer_key(self, peer_name):
        request = {
            'type': 'get_key',
            'target': peer_name
        }
        self.client_socket.sendall(json.dumps(request).encode('utf-8'))
        response = self.client_socket.recv(2048)
        request = json.loads(response.decode('utf-8'))
        print(f'TYPE {type(request['public_key'])}')
        print(f'TYPE {request['public_key'].encode('utf-8')}')
        

        pk = request['public_key'].encode('utf-8')
        return deserialize_public_key(pk)

    def send_message(self, target, message, shared_key):
        encrypted_message = encrypt_message(shared_key, message.encode('utf-8'))
        request = {
            'type': 'send_message',
            'target': target,
            'message': encrypted_message.hex()
        }
        print('encode hex:', encrypted_message.hex())
        self.client_socket.sendall(json.dumps(request).encode('utf-8'))

    def listen_for_messages(self, shared_key):
        while True:
            data = self.client_socket.recv(2048)
            if data:
                try:
                    response = json.loads(data.decode('utf-8'))
                    if response['from']:
                        # print('OKOK')
                        encrypted_message = bytes.fromhex(response['message'])
                        # print('encr_msg', encrypted_message)
                        # shared_key = generate_shared_key(self.private_key, self.get_peer_key(response['from']))
                        decrypted_message = decrypt_message(shared_key, encrypted_message)
                        # print(decrypted_message)
                        print(f"\n{response['from']} > {decrypted_message.decode('utf-8')}")
                except Exception as e:
                    print(f'data- {data}')
                    print(f"Error processing message: {e}")
            else:
                break

    def chat(self, peer_name):
        peer_public_key = self.get_peer_key(peer_name)
        name = 'Bob' if self.name == 'Alice' else 'Alice'
        print('loaded for ', name )
        # _, peer_public_key = load_keys_from_files(f'{name}_private_key.pem', f'{name}_public_key.pem')
        # print(f'ppk {serialize_public_key(peer_public_key)}')
        shared_key = generate_shared_key(self.private_key, peer_public_key)
        threading.Thread(target=self.listen_for_messages, args=(shared_key,)).start()
        print(f"You can now chat with {peer_name}. Type 'exit' to end the chat.")

        while True:
            message = input(f"{self.name} > ")
            if message.lower() == 'exit':
                break
            self.send_message(peer_name, message, shared_key)


if __name__ == "__main__":
    client_name = input("Enter client name (Alice or Bob): ")
    peer_name = 'Bob' if client_name == 'Alice' else 'Alice'

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8080))
    client = Participant(client_name, 'localhost', 8080, client_socket)
    client.register_with_trent()
    input("Little pause")
    client.chat(peer_name)