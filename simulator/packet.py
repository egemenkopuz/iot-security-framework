from enum import Enum
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import padding
from os import urandom
import socket

class PacketType(Enum):
    """
    Packet type enums with corresponding byte values
    """
    # HANDSHAKE PACKETS
    CLIENT_HELLO                = b'000'
    SERVER_HELLO                = b'001'
    CLIENT_CERT_REQUEST         = b'002'
    CLIENT_CERT                 = b'003'
    KEY_INFO                    = b'004'
    CLIENT_CERT_VERIFY          = b'005'
    SERVER_FINISHED             = b'006'
    CLIENT_FINISHED             = b'007'
    HANDSHAKE_DENIED            = b'009'

    # LOW TIER HANDSHAKE
    LOW_TIER_HELLO              = b'010'
    LOW_TIER_HELLO_FINISHED     = b'011'
    LOW_TIER_HELLO_DENIED       = b'019'

    # ACTIVE INIT PACKETS
    CLIENT_TYPE                 = b'100'

    # USER PACKETS
    USER_LOGIN                  = b'200'
    USER_LOGIN_FINISHED         = b'201'
    USER_LOGOUT                 = b'208'    # USER AUTH
    USER_LOGIN_DENIED           = b'209'

    USER_REGISTER               = b'210'
    USER_REGISTER_FINISHED      = b'211'
    USER_REGISTER_DENIED        = b'219'

    ACTIVE_DEVICE_LIST          = b'220'    # USER AUTH
    CONNECT_TO_DEVICE           = b'221'    # USER AUTH
    DISCONNECT_FROM_DEVICE      = b'222'    # USER AUTH
    DEVICE_CONNECTION_FINISHED  = b'223'    # USER AUTH
    CHANGE_DEVICE_LEVEL         = b'224'    # ADMIN AUTH
    CHANGE_DEVICE_LEVEL_FINISHED= b'225'    # ADMIN AUTH
    CHANGE_DEVICE_LEVEL_DENIED  = b'226'    # ADMIN AUTH
    DEVICE_CONNECTION_DENIED    = b'229'    # USER AUTH

    CHANGE_PASSWORD             = b'230'    # USER AUTH
    CHANGE_PASSWORD_FINISHED    = b'231'    # USER AUTH
    CHANGE_PASSWORD_DENIED      = b'239'    # USER AUTH

    CHANGE_USERNAME             = b'240'    # USER AUTH
    CHANGE_USERNAME_FINISHED    = b'241'    # USER AUTH
    CHANGE_USERNAME_DENIED      = b'249'    # USER AUTH

    USER_LIST                   = b'250'    # ADMIN AUTH
    CHANGE_USER_LEVEL           = b'251'    # ADMIN AUTH
    CHANGE_USER_LEVEL_FINISHED  = b'252'    # ADMIN AUTH
    CHANGE_USER_LEVEL_DENIED    = b'253'    # ADMIN AUTH
    DELETE_USER                 = b'254'    # ADMIN AUTH
    DELETE_USER_FINISHED        = b'255'    # ADMIN_AUTH
    DELETE_USER_DENIED          = b'256'    # ADMIN AUTH

    LOW_TIER_REGISTER           = b'260'    # ADMIN AUTH
    LOW_TIER_REGISTER_FINISHED  = b'261'    # ADMIN AUTH
    LOW_TIER_REGISTER_DENIED    = b'269'    # ADMIN AUTH

    ADMIN_AUTH_REQUIRED         = b'298'
    USER_AUTH_REQUIRED          = b'299'

    # IOTS
    START_COMMUNCATION          = b'300'    # DEVICE AUTH
    END_COMMUNCATION            = b'399'    # DEVICE AUTH

    # TRANSFER PACKETS
    MESSAGE                     = b'400'    # USER/DEVICE AUTH

    # SERVER DISCONNECTION
    DISCONNECT                  = b'999'


class PacketTCP:
    """
    TCP packet blueprint
    """
    @staticmethod
    def form_lowtier_packet(packet_type:PacketType,aes_key:bytes,iv:bytes,data:bytes) -> bytes:
        """
        Forms a packet for low tier communication
        
        packet formation: [iv|encrypted(type|data)]
        
        - iv : 16 bytes
        - type : 3 byte
        - data : variable

        Arguments:
        - packet_type {PacketType} -- packet type
        - aes_key {bytes} -- AES key
        - iv {bytes} -- initial vector
        - data {bytes} -- data to be sent
        
        Returns:
        - bytes -- full packet
        """
        iv = urandom(16)
        encryptor = Cipher(algorithms.AES(aes_key),modes.CBC(iv),default_backend()).encryptor()
        padder = PKCS7(128).padder()
        data = padder.update(packet_type.value + data) + padder.finalize()
        data = encryptor.update(data) + encryptor.finalize()
        data = iv + data
        return PacketTCP.form_t(data)
    
    @staticmethod
    def parse_lowtier_packet(aes_key:bytes,data:bytes) -> (PacketType, bytes):
        """
        Parses a packet for low tier communication
        """
        iv = data[:16]
        decryptor = Cipher(algorithms.AES(aes_key),modes.CBC(iv),default_backend()).decryptor()
        unpadder = PKCS7(128).unpadder()
        data = decryptor(data) + decryptor.finalize()
        data = unpadder(data) + unpadder.finalize()
        packet_type = PacketType(data[:3])
        return (packet_type,data[3:])
    @staticmethod
    def form(packet_type:PacketType,data:bytes) -> bytes:
        """
        Forms a packet
        
        packet formation: [size|type|data]
        
        - size : 5 bytes
        - type : 3 byte
        - data : variable

        Arguments:
        - packet_type {PacketType} -- packet type
        - data {bytes} -- data to be sent
        
        Returns:
            bytes -- full packet
        """
        size = len(packet_type.value) + len(data)
        #size = str(len(packet_type.value) + len(data)).rjust(5,'0').encode('utf-8')
        packet = bytearray(size.to_bytes(5,byteorder='big',signed=True))
        packet.extend(packet_type.value)
        packet.extend(data)
        return packet

    @staticmethod
    def form_limited(packet_type:bytes,data:bytes,size:int=2048) -> list:
        """
        Forms packet(s) with limited size

        Arguments:
        - packet_type {bytes} -- packet type
        - data {bytes} -- data to be sent
        
        Keyword Arguments:
        - size {int} -- size of the packet(s) (default: {2048})
        
        Returns:
            list -- list of formed packets
        """
        # TODO if necessary
        return []

    @staticmethod
    def receive(socket) -> (PacketType,bytes):
        size:int = int.from_bytes(socket.recv(5),byteorder='big',signed=True)
        payload = socket.recv(size)
        packet_type = PacketType(payload[:3])
        data = payload[3:]
        return (packet_type, data)

    @staticmethod
    def recv_t(socket) -> bytes:
        size:int = int.from_bytes(socket.recv(5),byteorder='big',signed=True)
        return socket.recv(size)

    @staticmethod
    def form_t(data:bytes) -> bytes:
        size = len(data)
        packet = bytearray(size.to_bytes(5,byteorder='big',signed=True))
        packet.extend(data)
        return packet

    @staticmethod
    def get_size(data:bytes) -> int:
        """
        Calculates data's size
        
        Arguments:
        - data {bytes} -- data
        
        Returns:
            int -- size
        """
        return int.from_bytes(data,byteorder='big',signed=True)

    @staticmethod
    def parse(payload:bytes) -> (PacketType, bytes):
        """
        Parses the received packet to its type and data
        
        Arguments:
        - payload {bytes} -- whole packet
        
        Returns:
            (PacketType, bytes) -- type of the data, and only the data
        """
        packet_type = PacketType(payload[:3])
        data = payload[3:]
        return (packet_type, data)