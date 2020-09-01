from packet import PacketTCP, PacketType
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey,RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.padding import PKCS7 
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import socket
from util import handshake
from os import urandom

class HighIoTSimulation:
    def __init__(self,server_ip:str,server_port:int,ca_cert:crypto.X509,iot_cert:crypto.X509,iot_prv:RSAPrivateKey):
        self.socket = socket.socket()
        self.cert_store = crypto.X509Store()
        self.cert_store.add_cert(ca_cert)
        self.server_ip = server_ip
        self.server_port = server_port
        self.ca_cert = ca_cert
        self.iot_cert = iot_cert
        self.iot_prv = iot_prv
        self.recv_cipher = None
        self.send_cipher = None

    def simulate(self):
        try:
            # connects to the server
            self.socket.connect((self.server_ip,self.server_port))
            print(f'Connected to {self.server_ip}:{self.server_port}.')

            # handshake protocol
            master, keys = handshake(socket=self.socket,client_cert=self.iot_cert,client_prv=self.iot_prv,cert_store=self.cert_store)

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
            self.__send_secure(packet_type=PacketType.CLIENT_TYPE,data='high-tier IoT'.encode('UTF-8'))
            print("Sent IoT type packet. Message: 'high-tier IoT'")

            while True:
                    self.socket.settimeout(None)
                    (packet_type,data) = PacketTCP.parse(self.__recv_secure())
                    if packet_type == PacketType.START_COMMUNCATION:
                        print('Server sent START_COMMINICATION, starting communcation action...')
                        while True:
                            # sends encrypted random 32 bytes datas every 5 seconds
                            random_data = urandom(8)
                            encrypted_data = self.__send_secure(packet_type=PacketType.MESSAGE,data=random_data)
                            print(f'\nSending Random data: {random_data}\nEncrypted packet: {encrypted_data}')
                            try:
                                # checks incoming packets
                                self.socket.settimeout(2)
                                (packet_type,data) = PacketTCP.parse(self.__recv_secure())

                                if packet_type == PacketType.END_COMMUNCATION:
                                    print('Server sent END_COMMUNCATION, ending communcation action...')
                                    break
                                elif packet_type == PacketType.DISCONNECT:
                                    print('Server sent DISCONNECT, ending whole IoT simulation...')
                                    raise Exception()

                            except socket.timeout:
                                continue
        except Exception as e:
            print(e)
        finally:
            try:
                self.socket.close()
            except: pass

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