from packet import PacketTCP, PacketType
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey,RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.padding import PKCS7 
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import socket, json
from util import handshake
from os import urandom


user_not_auth_menu_str = "\nSelect your action:\n" + \
                         " 1 -> LOGIN\n" + \
                         " 2 -> REGISTER\n"

user_auth_menu_str = '\nSelect your action:\n' + \
                ' 1 -> ACTIVE DEVICE LIST\n' + \
                " 2 -> CONNECT TO DEVICE\n" + \
                " 3 -> SEND MESSAGE TO DEVICE\n" + \
                " 4 -> DISCONNECT FROM DEVICE (auto by '3')\n" + \
                " 5 -> CHANGE DEVICE LEVEL\n" + \
                " 6 -> CHANGE PASSWORD\n" + \
                " 7 -> CHANGE USERNAME\n" + \
                " 8 -> USER LIST\n" + \
                " 9 -> CHANGE USER LEVEL\n" + \
                " 10 -> DELETE USER\n" + \
                " 11 -> LOW TIER REGISTER\n" \
                " 12 -> LOGOUT\n"

class UserSimulation:
    def __init__(self,server_ip:str,server_port:int,ca_cert:crypto.X509,user_cert:crypto.X509,user_prv:RSAPrivateKey):
        self.socket = socket.socket()
        self.cert_store = crypto.X509Store()
        self.cert_store.add_cert(ca_cert)
        self.server_ip = server_ip
        self.server_port = server_port
        self.ca_cert = ca_cert
        self.user_cert = user_cert
        self.user_prv = user_prv
        self.recv_cipher = None
        self.send_cipher = None

    def simulate(self):
        try:
            # connects to the server
            self.socket.connect((self.server_ip,self.server_port))
            print(f'Connected to {self.server_ip}:{self.server_port}.')

            # handshake protocol
            master, keys = handshake(socket=self.socket,client_cert=self.user_cert,client_prv=self.user_prv,cert_store=self.cert_store)

            client_write_mac_key = keys[:32]
            server_write_mac_key = keys[32:64]
            client_write_key = keys[64:80]
            server_write_key = keys[80:96]
            client_write_iv = keys[96:112]
            server_write_iv = keys[112:128]

            self.recv_cipher = Cipher(algorithms.AES(server_write_mac_key), modes.CBC(server_write_iv), backend=default_backend())
            self.send_cipher = Cipher(algorithms.AES(client_write_mac_key), modes.CBC(client_write_iv), backend=default_backend())
            print('Created AES ciphers for communication using derived keys.')

            # sends iot type
            self.__send_secure(packet_type=PacketType.CLIENT_TYPE,data='user'.encode('UTF-8'))
            print("Sent IoT type packet. Message: 'user'")

            
            authenticated = False
            while True:
                while not authenticated:
                    action = self.__not_auth_actions()

                    if action == '1':   # LOGIN
                        details = {}
                        details['username'] = input('Type your username: ')
                        details['password'] = input('Type your password: ')

                        data = json.dumps(details).encode('UTF-8')
                        packet = self.__send_secure(PacketType.USER_LOGIN,data)
                        print(f'Sent USER_LOGIN packet: {packet}')

                        (packet_type,data) = PacketTCP.parse(self.__recv_secure())

                        if packet_type == PacketType.USER_LOGIN_FINISHED:
                            authenticated = True
                            print('Received USER_LOGIN_FINISHED, auth success.')
                            print(f"(0:admin,1:privileged,2:guest) your role is {data.decode('UTF-8')}")
                        elif packet_type == PacketType.USER_LOGIN_DENIED:
                            print(f"Received USER_LOGIN_DENIED, {data.decode('UTF-8')}")
                        elif packet_type == PacketType.DISCONNECT:
                            raise Exception(f"Received DISCONNECT, terminating...")
                        
                    elif action == '2': # REGISTER
                        details = {}
                        details['username'] = input('Type your username: ')
                        details['password'] = input('Type your password: ')

                        data = json.dumps(details).encode('UTF-8')
                        packet = self.__send_secure(PacketType.USER_REGISTER,data)
                        print(f'Sent USER_REGISTER packet: {packet}')

                        (packet_type,data) = PacketTCP.parse(self.__recv_secure())

                        if packet_type == PacketType.USER_REGISTER_FINISHED:
                            print('Received USER_REGISTER_FINISHED, register success.')
                        elif packet_type == PacketType.USER_REGISTER_DENIED:
                            print(f"Received USER_REGISTER_DENIED, {data.decode('UTF-8')}")
                        elif packet_type == PacketType.DISCONNECT:
                            raise Exception(f"Received DISCONNECT, terminating...")

                while authenticated:
                    action = self.__auth_actions()

                    if action == '1': # ACTIVE DEVICE LIST
                        packet = self.__send_secure(PacketType.ACTIVE_DEVICE_LIST,b'')
                        print(f'Sent ACTIVE_DEVICE_LIST packet: {packet}')

                        (packet_type,data) = PacketTCP.parse(self.__recv_secure())

                        if packet_type == PacketType.ACTIVE_DEVICE_LIST:
                            devices:dict = json.loads(data.decode('UTF-8'))
                            print(f"Received ACTIVE_DEVICE_LIST, listing devices:")
                            [print(f"ID: {k} NAME: {v}") for k, v in devices.items()]
                        elif packet_type == PacketType.ADMIN_AUTH_REQUIRED:
                            print(f"Received ADMIN_AUTH_REQUIRED, this action is not allowed.")
                        elif packet_type == PacketType.DISCONNECT:
                            raise Exception(f"Received DISCONNECT, terminating...")

                    elif action == '2': # CONNECT TO DEVICE
                        device_id = input('Type device id: ')

                        packet = self.__send_secure(PacketType.CONNECT_TO_DEVICE,device_id.encode('UTF-8'))
                        print(f'Sent CONNECT_TO_DEVICE packet: {packet}')

                        (packet_type,data) = PacketTCP.parse(self.__recv_secure())

                        if packet_type == PacketType.DEVICE_CONNECTION_FINISHED:
                            print('Received DEVICE_CONNECTION_FINISHED, data will start coming.')

                            count = 0
                            while count < 5:
                                (packet_type,data) = PacketTCP.parse(self.__recv_secure())

                                if packet_type == PacketType.MESSAGE:
                                    print(f"Received MESSAGE, data-{count} : {data}")
                                    count += 1
                                elif packet_type == PacketType.DEVICE_CONNECTION_DENIED:
                                    print('Received DEVICE_CONNECTION_DENIED, data will not be coming.')
                                    break
                                elif packet_type == PacketType.DISCONNECT:
                                    raise Exception(f"Received DISCONNECT, terminating...")

                            if count == 5:
                                packet = self.__send_secure(PacketType.DISCONNECT_FROM_DEVICE,device_id.encode('UTF-8'))
                                print(f'Sent DISCONNECT_FROM_DEVICE packet: {packet}')

                    elif action == '4': # DISCONNECT FROM DEVICE
                        pass # AUTO BY '3'

                    elif action == '5': # CHANGE DEVICE LEVEL
                        details = {}
                        details['target_device'] = input('Type device id: ')
                        details['new_device_level'] = input('Type its new level: ')

                        data = json.dumps(details).encode('UTF-8')

                        packet = self.__send_secure(PacketType.CHANGE_DEVICE_LEVEL,data)
                        print(f'Sent CHANGE_DEVICE_LEVEL packet: {packet}')

                        (packet_type,data) = PacketTCP.parse(self.__recv_secure())

                        if packet_type == PacketType.CHANGE_DEVICE_LEVEL_FINISHED:
                            print(f"Received CHANGE_DEVICE_LEVEL_FINISHED, success.")
                        elif packet_type == PacketType.CHANGE_DEVICE_LEVEL_DENIED:
                            print(f"Received CHANGE_DEVICE_LEVEL_DENIED, failure: {data.decode('UTF-8')}")
                        elif packet_type == PacketType.DISCONNECT:
                            raise Exception(f"Received DISCONNECT, terminating...")
                        else:
                            print(f"Received {packet_type.name}, {data.decode('UTF-8')}")

                    elif action == '6': # CHANGE PASSWORD
                        details = {}
                        details['old_password'] = input('Type your old password: ')
                        details['new_password'] = input('Type your new password: ')

                        data = json.dumps(details).encode('UTF-8')
                        packet = self.__send_secure(PacketType.CHANGE_PASSWORD,data)
                        print(f'Sent CHANGE_PASSWORD packet: {packet}')

                        (packet_type,data) = PacketTCP.parse(self.__recv_secure())

                        if packet_type == PacketType.CHANGE_PASSWORD_FINISHED:
                            print(f"Received CHANGE_PASSWORD_FINISHED, success.")
                        elif packet_type == PacketType.CHANGE_PASSWORD_DENIED:
                            print(f"Received CHANGE_PASSWORD_DENIED, failure: {data.decode('UTF-8')}")
                        elif packet_type == PacketType.DISCONNECT:
                            raise Exception(f"Received DISCONNECT, terminating...")
                        else:
                            print(f"Received {packet_type.name}, {data.decode('UTF-8')}")
                    
                    elif action == '7': # CHANGE USERNAME
                        details = {}
                        details['new_username'] = input('Type your new username: ')

                        data = json.dumps(details).encode('UTF-8')
                        packet = self.__send_secure(PacketType.CHANGE_USERNAME,data)
                        print(f'Sent CHANGE_USERNAME packet: {packet}')

                        (packet_type,data) = PacketTCP.parse(self.__recv_secure())

                        if packet_type == PacketType.CHANGE_USERNAME_FINISHED:
                            print(f"Received CHANGE_USERNAME_FINISHED, success.")
                        elif packet_type == PacketType.CHANGE_USERNAME_DENIED:
                            print(f"Received CHANGE_USERNAME_DENIED, failure: {data.decode('UTF-8')}")
                        elif packet_type == PacketType.DISCONNECT:
                            raise Exception(f"Received DISCONNECT, terminating...")
                        else:
                            print(f"Received {packet_type.name}, {data.decode('UTF-8')}")
                    
                    elif action == '8': # USER LIST
                        packet = self.__send_secure(PacketType.USER_LIST,b'')

                        (packet_type,data) = PacketTCP.parse(self.__recv_secure())

                        if packet_type == PacketType.USER_LIST:
                            users:dict = json.loads(data.decode('UTF-8'))
                            [print(f"username: {key}, {value}") for key, value in users.items()]

                        elif packet_type == PacketType.DISCONNECT:
                            raise Exception(f"Received DISCONNECT, terminating...")
                        else:
                            print(f"Received {packet_type.name}, {data.decode('UTF-8')}")

                    elif action == '9': # CHANGE OTHER USER'S LEVEL
                        details = {}
                        details['target_username'] = input('Type target username: ')
                        details['new_role'] = input('Type its new role (0,1,2): ')

                        data = json.dumps(details).encode('UTF-8')
                        packet = self.__send_secure(PacketType.CHANGE_USER_LEVEL,data)
                        print(f'Sent CHANGE_USER_LEVEL packet: {packet}')

                        (packet_type,data) = PacketTCP.parse(self.__recv_secure())

                        if packet_type == PacketType.CHANGE_USER_LEVEL_FINISHED:
                            print(f"Received CHANGE_USER_LEVEL_FINISHED, success.")
                        elif packet_type == PacketType.CHANGE_USER_LEVEL_DENIED:
                            print(f"Received CHANGE_USER_LEVEL_DENIED, failure.")
                        elif packet_type == PacketType.DISCONNECT:
                            raise Exception(f"Received DISCONNECT, terminating...")
                        else:
                            print(f"Received {packet_type.name}, {data.decode('UTF-8')}")

                    elif action == '11': # LOW TIER REGISTER
                        packet = self.__send_secure(PacketType.LOW_TIER_REGISTER,b'')
                        print(f'Sent LOW_TIER_REGISTER packet: {packet}')

                        (packet_type,data) = PacketTCP.parse(self.__recv_secure())
                        if packet_type == PacketType.LOW_TIER_REGISTER_FINISHED:
                            print(f"Received LOW_TIER_HELLO_FINISHED, success.")
                            # first 128 bytes (keys)
                            lowtier_keys = data[:128]
                            print(f'Lowtier keys: {lowtier_keys}\n')
                            # second 32 bytes (nonce)
                            lowtier_nonce = data[128:160]
                            print(f'lowtier nonce: {lowtier_nonce}\n')
                            # remaining is identifier str
                            lowtier_ident = data[160:].decode('UTF-8')
                            print(f'lowtier identifier: {lowtier_ident}')

                            # send this back to IOT via bluetooth TODO IN COMPANION APP
                            
                        elif packet_type == PacketType.LOW_TIER_REGISTER_DENIED:
                            print(f"Received LOW_TIER_REGISTER_DENIED, failure.")
                        elif packet_type == PacketType.DISCONNECT:
                            raise Exception(f"Received DISCONNECT, terminating...")
                        else:
                            print(f"Received {packet_type.name}, {data.decode('UTF-8')}")

                    elif action == '12': # LOGOUT
                        packet = self.__send_secure(PacketType.USER_LOGOUT,b'')
                        print(f'Sent USER_LOGOUT packet: {packet}')
                        authenticated = False

        except Exception as e:
            print(e)
        finally:
            try: self.socket.close()
            except: pass

    def __not_auth_actions(self) -> str:
        s = None
        while s not in ['1','2']:
            if s in ['exit','q','quit']: return None
            print(user_not_auth_menu_str)
            s  = input('')
        return s

    def __auth_actions(self) -> str:
        s = None
        while s not in ['1','2','3','4','5','6','7','8','9','10','11','12']:
            if s in ['exit','q','quit']: return None
            print(user_auth_menu_str)
            s = input('')
        return s

    def __send_secure(self,packet_type:PacketType,data:bytes) -> bytes:
        """
        secure socket send method

        Parameters:
        - packet_type {PacketType} : type of the packet
        - data {bytes} : data in bytes

        returns sent packet in bytes
        """
        encryptor = self.send_cipher.encryptor()
        padder = PKCS7(128).padder()
        data = padder.update(packet_type.value + data) + padder.finalize()
        data = encryptor.update(data) + encryptor.finalize()
        packet = PacketTCP.form_t(data)
        self.socket.send(packet)
        return packet

    def __recv_secure(self) -> bytes:
        """
        secure socket recieve method
        """
        decryptor = self.recv_cipher.decryptor()
        unpadder = PKCS7(128).unpadder()
        data = PacketTCP.recv_t(self.socket)
        return unpadder.update(decryptor.update(data) + decryptor.finalize()) + unpadder.finalize()