from enum import Enum

from network.packet import PacketTCP, PacketType

from utilities.logger import LogLevel
from utilities.exceptions import HandshakeError
from utilities.thread import FrameworkThread, ThreadInterface, ThreadMessageType, ThreadMessage, Priority
from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey,RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from os import urandom

import enum, socket, hmac, hashlib, inspect, queue, json

class LowtierException(Exception):
    def __init__(self, low_tier_data:bytes):
        self.data = low_tier_data

class ClientType(Enum):
    TYPE_USER_APP = 'user'
    TYPE_LOW_TIER_IOT = 'low-tier IoT'
    TYPE_HIGH_TIER_IOT = 'high-tier IoT'

class ClientMode(Enum):
    INITIALIZATION = 'Initialization'
    HANDSHAKE = 'Handshake'
    ACTIVE = 'Active'
    COMMUNICATING = 'Communicating'
    DENIED = 'Denied'
    ERROR = 'Error'

class Keys:
    """
    key module for master key, derived key generation and possession
    """
    def __init__(self,mk:bytes,cwmk:bytes,swmk:bytes,cwk:bytes,swk:bytes,cwi:bytes,swi:bytes):
        """
        Arguments:
        - mk {bytes} : derived master key
        - cwmk {bytes} : client write mac key
        - swmk {bytes} : server write mac key
        - cwk {bytes} : client write key
        - swk {bytes} : server write key
        - cwi {bytes} : client initial vector
        - swi {bytes} : server initial vector
        """
        self.master_key = mk
        self.client_write_mac_key = cwmk
        self.server_write_mac_key = swmk
        self.client_write_key = cwk
        self.server_write_key = swk
        self.client_write_iv = cwi
        self.server_write_iv = swi

    @staticmethod
    def create_master_key(pre_master_secret:bytes,random1:bytes,random2:bytes) -> bytes:
        """
        Creates 48 bytes long master key derived from pre master secret using two random bytes
        """
        seed = 'master secret'.encode('utf-8') + random1 + random2
        h = hmac.new(key=pre_master_secret,digestmod=hashlib.sha256)
        a0 = seed
        h.update(a0)
        a1 = h.digest()
        h.update(a1)
        a2 = h.digest()
        h.update(a1 + seed)
        p = h.digest()
        h.update(a2 + seed)
        p += h.digest()
        return p[:48]

    @staticmethod
    def create_server_finished(master_key:bytes,pre_master_secret:bytes) -> bytes:
        seed = 'server finished'.encode('UTF-8') + hashlib.sha256(pre_master_secret).digest()
        a0 = seed 
        h = hmac.new(key=master_key, digestmod=hashlib.sha256)
        h.update(a0)
        a1 = h.digest()
        h.update(a1 + seed)
        p1 = h.digest()
        return p1[:12]

    @staticmethod
    def create_client_finished(master_key:bytes,pre_master_secret:bytes) -> bytes:
        seed = 'client finished'.encode('UTF-8') + hashlib.sha256(pre_master_secret).digest()
        a0 = seed
        h = hmac.new(key=master_key, digestmod=hashlib.sha256)
        h.update(a0)
        a1 = h.digest()
        h.update(a1 + seed)
        p1 = h.digest()
        return p1[:12]

    @classmethod
    def derive_keys_from_master(cls,master_key:bytes,random1:bytes,random2:bytes) -> bytes:
        """
        Derives expansion keys from master key and return initialized Keys class
        """
        seed = 'key expansion'.encode('utf-8') + random1 + random2
        a0 = seed
        h = hmac.new(key=master_key,digestmod=hashlib.sha256)
        h.update(a0)
        a1 = h.digest()
        h.update(a1)
        a2 = h.digest()
        h.update(a2)
        a3 = h.digest()
        h.update(a3)
        a4 = h.digest()
        h.update(a1 + seed)
        p = h.digest()
        h.update(a2 + seed)
        p += h.digest()
        h.update(a3 + seed)
        p += h.digest()
        h.update(a4 + seed)
        p += h.digest()
        return cls(master_key,p[:32],p[32:64],p[64:80],p[80:96],p[96:112],p[112:128])

    @staticmethod
    def derive_whole_keys_from_master(master_key:bytes,random1:bytes,random2:bytes) -> bytes:
        """
        Derives expansion keys from master key and return 128 bytes of whole keys
        """
        seed = 'key expansion'.encode('utf-8') + random1 + random2
        a0 = seed
        h = hmac.new(key=master_key,digestmod=hashlib.sha256)
        h.update(a0)
        a1 = h.digest()
        h.update(a1)
        a2 = h.digest()
        h.update(a2)
        a3 = h.digest()
        h.update(a3)
        a4 = h.digest()
        h.update(a1 + seed)
        p = h.digest()
        h.update(a2 + seed)
        p += h.digest()
        h.update(a3 + seed)
        p += h.digest()
        h.update(a4 + seed)
        p += h.digest()
        return p


client_count = -1

class Client(FrameworkThread):
    """
    client thread to handle handshake and further specific actions
    """
    def __init__(self,socket:socket.socket,address:tuple,store:crypto.X509Store, server_cert:crypto.X509, server_prv:crypto.PKey):
        global client_count
        client_count += 1
        super().__init__(f'CLIENT{client_count}', f"{address[0]}:{address[1]})" + ClientMode.INITIALIZATION.value, daemon=False, priority=None)
        self.create_interface()
        self.socket = socket
        self.address = address
        self.store = store
        self.server_cert = server_cert
        self.server_prv = server_prv
        self.client_type = None
        self.client_cert = None
        self.keys = None
        self.send_cipher = None
        self.recv_cipher = None

        self.iot_level = 1

    def run(self):
        try:
            # HANDSAHKE PROTOCOL
            self.description = f"{self.address[0]}:{self.address[1]}) {ClientMode.HANDSHAKE}"
            self.keys = self.__handshake()
        except LowtierException as e:
            # LOW TIER PROTOCOL
            details:dict = json.loads(e.data.decode('UTF-8'))
            enc_lowtier_nonce:bytes = details['enc_nonce'].encode('UTF-8')
            lowtier_iv:bytes = details['iv'].encode('UTF-8')
            lowtier_ident:int = details['identifier']
            # checking
            (l_bool,data) = self._database_interface.check_lowtier_validity(lowtier_ident,lowtier_iv,enc_lowtier_nonce)

            if l_bool:
                # valid device
                self._logger_interface.write_log(f'Client ({self.address[0]}:{self.address[1]}) logged in as lowtier ({lowtier_ident})',LogLevel.INFO,inspect.currentframe())
                self.socket.send(PacketTCP.form_lowtier_packet(PacketType.LOW_TIER_HELLO_FINISHED,data[0],data[1]))
                self.priority = Priority.LEVEL1
                self.client_type = ClientType.TYPE_LOW_TIER_IOT
                self._archive_interface.add_thread(self)
                self.__low_iot_module(lowtier_ident,data[0])
            else:
                # not valid device
                self._logger_interface.write_log(f'Client ({self.address[0]}:{self.address[1]}) has failed to login in as lowtier ({lowtier_ident})',LogLevel.INFO,inspect.currentframe())
                self.socket.send(PacketTCP.form(PacketType.LOW_TIER_HELLO_DENIED,data.encode('UTF-8')))
                self._stop_request.set()
                try:
                # self.__send_secure(packet_type=PacketType.DISCONNECT,data=b'')
                    self.socket.close()
                except: pass
                return

        except HandshakeError as e:
            # HANDSHAKE DENIED
            self.description = f"{self.address[0]}:{self.address[1]}) {ClientMode.DENIED}"
            self._logger_interface.write_log(f'Client ({self.address[0]}:{self.address[1]}) has failed Handshake protocol, {e}',LogLevel.INFO,inspect.currentframe())
            self._stop_request.set()
        except Exception as e:
            # HANDSHAKE ERROR
            self.description = f"{self.address[0]}:{self.address[1]}) {ClientMode.ERROR}"
            self._logger_interface.write_log(f'Client ({self.address[0]}:{self.address[1]}) had an error while connecting, {e}',LogLevel.ERROR,inspect.currentframe())
            self._stop_request.set()

        if self._stop_request.is_set():
            try:
                # sends denial message back to client
                self.socket.send(PacketTCP.form(PacketType.HANDSHAKE_DENIED,b''))
            except: pass
        else:
            # Handshake protocol is done, asking for client type
            self.description = f"{self.address[0]}:{self.address[1]}) {ClientMode.ACTIVE}"
            self.send_cipher = Cipher(algorithms.AES(self.keys.server_write_mac_key),modes.CBC(self.keys.server_write_iv),default_backend())
            self.recv_cipher = Cipher(algorithms.AES(self.keys.client_write_mac_key),modes.CBC(self.keys.client_write_iv),default_backend())
            self._logger_interface.write_log(f'Client ({self.address[0]}:{self.address[1]}) has finished Handshake protocol.',LogLevel.INFO,inspect.currentframe())
            
            try:
                if self.client_type == None:
                    (packet_type,data) = PacketTCP.parse(self.__recv_secure())
                    if packet_type != PacketType.CLIENT_TYPE:
                        raise Exception(f'Client ({self.address[0]}:{self.address[1]}) did not send CLIENT_TYPE packet!')
                    self.client_type = ClientType(data.decode('UTF-8'))
                if self.client_type == ClientType.TYPE_USER_APP:
                    self.priority = Priority.LEVEL2
                    self._archive_interface.add_thread(self)
                    self.__user_module()
                elif self.client_type == ClientType.TYPE_HIGH_TIER_IOT:
                    self.priority = Priority.LEVEL1
                    self._archive_interface.add_thread(self)
                    self.__high_iot_module()
                """elif self.client_type == ClientType.TYPE_LOW_TIER_IOT:
                    self.priority = Priority.LEVEL1
                    self._archive_interface.add_thread(self)
                    self.__low_iot_module()"""
            except Exception as e:
                self._logger_interface.write_log(e,LogLevel.ERROR,inspect.currentframe())
                self._stop_request.set()
            try:
                # self.__send_secure(packet_type=PacketType.DISCONNECT,data=b'')
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
        
    def __handshake(self) -> Keys:
        """
        Handshake protocol
        """
        # --------------------------------------------------------------------------------- #
        # receives CLIENT HELLO (high-tier IoT or Companion App)  - includes client_random                                   #
        # --------------------------------------------------------------------------------- #

        (packet_type,data) = PacketTCP.receive(self.socket)
        
        if packet_type == PacketType.CLIENT_HELLO: 
            client_random = data

        # --------------------------------------------------------------------------------- #
        # receives LOW TIER HELLO (low-tier IoT) - ???                                      #
        # --------------------------------------------------------------------------------- #
        
        elif packet_type == PacketType.LOW_TIER_HELLO:
            raise LowtierException(data)

        else:
            raise HandshakeError(f'({self.address[0]}:{self.address[1]}) : CLIENT_HELLO must be sent first')
    


        # --------------------------------------------------------------------------------- #
        # sends SERVER HELLO - includes server_random and server_cert                       #
        # --------------------------------------------------------------------------------- #

        server_random = urandom(32)
        packet = PacketTCP.form(PacketType.SERVER_HELLO,server_random + crypto.dump_certificate(crypto.FILETYPE_PEM,self.server_cert))
        self.socket.send(packet)

        # --------------------------------------------------------------------------------- #
        # sends CLIENT CERTIFICATE REQUEST                                                  #
        # --------------------------------------------------------------------------------- #

        packet = PacketTCP.form(PacketType.CLIENT_CERT_REQUEST,b'')
        self.socket.send(packet)

        # --------------------------------------------------------------------------------- #
        # recieves CLIENT CERTIFICATE - includes client_cert                                #
        # --------------------------------------------------------------------------------- #

        (packet_type,data) = PacketTCP.receive(self.socket)
        if packet_type != PacketType.CLIENT_CERT:
            raise HandshakeError(f'({self.address[0]}:{self.address[1]}) : CLIENT_CERT was needed but failed')
        else:
            self.client_cert = crypto.load_certificate(crypto.FILETYPE_PEM,data)
            ctx = crypto.X509StoreContext(self.store,self.client_cert)
            try:
                ctx.verify_certificate()
            except Exception as e:
                raise HandshakeError(f'({self.address[0]}:{self.address[1]}) : {e}')

        # --------------------------------------------------------------------------------- #
        # recieves KEY INFO - includes encrypted pre master secret                          #
        # --------------------------------------------------------------------------------- #

        (packet_type,data) = PacketTCP.receive(self.socket)
        if packet_type != PacketType.KEY_INFO:
            raise HandshakeError(f'({self.address[0]}:{self.address[1]}) : KEY_INFO was needed but failed')
        else:
            server_private_key:RSAPrivateKey = self.server_prv.to_cryptography_key()
            try:
                pre_master_secret = server_private_key.decrypt(data,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            except Exception as e:
                raise HandshakeError(f'({self.address[0]}:{self.address[1]}) : {e}')

        # --------------------------------------------------------------------------------- #
        # recieves CLIENT CERTIFICATE VERIFY - includes signed client_cert                  #
        # --------------------------------------------------------------------------------- #

        (packet_type,data) = PacketTCP.receive(self.socket)
        if packet_type != PacketType.CLIENT_CERT_VERIFY:
            raise HandshakeError(f'({self.address[0]}:{self.address[1]}) : CLIENT_CERT_VERIFY was needed but failed')
        else:
            client_public_key:RSAPublicKey= self.client_cert.get_pubkey().to_cryptography_key() 
            try:
                client_public_key.verify(data=crypto.dump_certificate(crypto.FILETYPE_PEM,self.client_cert),signature=data,padding=padding.PKCS1v15(),algorithm=hashes.SHA256())
            except Exception as e:
                raise HandshakeError(f'({self.address[0]}:{self.address[1]}) : {e}')

        # --------------------------------------------------------------------------------- #
        # Master Key Generation using pre-master-secret client_random, server_random        #
        # --------------------------------------------------------------------------------- #

        master_key = Keys.create_master_key(pre_master_secret,client_random,server_random)

        # --------------------------------------------------------------------------------- #
        # sends SERVER FINISHED - includes hmac of pre-master-secret using master key       #
        # --------------------------------------------------------------------------------- #

        data = Keys.create_server_finished(master_key,pre_master_secret)
        packet = PacketTCP.form(PacketType.SERVER_FINISHED,data)
        self.socket.send(packet)

        # --------------------------------------------------------------------------------- #
        # recieves CLIENT FINISHED - includes hmac of pre-master-secret using master key    #
        # --------------------------------------------------------------------------------- #
        
        (packet_type,hash_c) = PacketTCP.receive(self.socket)
        if packet_type != PacketType.CLIENT_FINISHED:
            raise HandshakeError(f'({self.address[0]}:{self.address[1]}) : CLIENT_FINISHED was needed but failed')
        else:
            data = Keys.create_client_finished(master_key,pre_master_secret)
            if not data == hash_c:
                raise HandshakeError(f'({self.address[0]}:{self.address[1]}) : CLIENT_FINISHED comparison failed')
        
        # --------------------------------------------------------------------------------- #
        # Expansion Keys Generation using master key, client_random and server_random       #
        # --------------------------------------------------------------------------------- #

        return Keys.derive_keys_from_master(master_key,client_random,server_random)
    
    def __high_iot_module(self):
        """
        High-tier IoT outer and inner communication manager function
        """
        
        current_thread_subs = {}    # dict to hold interfaces of establsihed intercomm threads
        current_recv_comm = False   # indicates if there is active communication

        try:
            while not self._stop_request.is_set():
                # --------------------------------------------------------------------------------- #
                # INNERCOMMUNICATION BETWEEN THREADS, checks thread messages from channel           #
                # --------------------------------------------------------------------------------- #

                # receivable thread messages: 
                # CONNECTION_BEGIN : indicates start of communication
                # CONNECTION_END : indicates end of communication
                # TRANSFER  : data transfer between threads

                try:
                    thread_message:ThreadMessage = self._channel.get(block=True,timeout=0.05)
                except queue.Empty:
                    thread_message = None
                
                # if there is a new message, change with old one
                if thread_message:
                    current_comm_type = thread_message.message_type
                else:
                    current_comm_type = None
                
                # --------------------------------------------------------------------------------- #
                # OUTERCOMMUNCATION TO IOT, sends other thread's messages to IoT                    #
                # --------------------------------------------------------------------------------- #

                # sendable packet types:
                # START_COMMUNICATION : indicates start of communication
                # END_COMMUNICATION : indicates end of communication
                # MESSAGE : data transfer between sockets


                if current_comm_type == ThreadMessageType.CONNECTION_BEGIN:
                    # add new thread's interface
                    current_thread_subs[thread_message.sender_tid] = thread_message.data
                    if len(current_thread_subs) == 1:
                        # sends packet iot to indicate start of communication
                        self.__send_secure(packet_type=PacketType.START_COMMUNCATION,data=b'')
                        self._logger_interface.write_log(f'Requested client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) to start communication.',LogLevel.INFO,inspect.currentframe())
                        current_recv_comm = True
                    self.description = f"{self.address[0]}:{self.address[1]}) {ClientMode.COMMUNICATING} - {[f'{str(k)} ' for k in current_thread_subs.keys()]}"
                elif current_comm_type == ThreadMessageType.CONNECTION_END:
                    # remove existing thread's interface
                    current_thread_subs.pop(thread_message.sender_tid)
                    self.description = f"{self.address[0]}:{self.address[1]}) {ClientMode.COMMUNICATING} - {[f'{str(k)} ' for k in current_thread_subs.keys()]}"
                elif current_comm_type == ThreadMessageType.TRANSFER:
                    self.__send_secure(packet_type=PacketType.MESSAGE,data=thread_message.data)
                
                
                if len(current_thread_subs) == 0 and current_recv_comm == True:
                    # send packet iot to indicate end of communication
                    self.__send_secure(packet_type=PacketType.END_COMMUNCATION,data=b'')
                    self._logger_interface.write_log(f'Requested client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) to end communication.',LogLevel.INFO,inspect.currentframe())
                    current_recv_comm = False

                # --------------------------------------------------------------------------------- #
                # OUTERCOMMUNICATION FROM IOT, recieves IoT's messages and transfers them           #
                # --------------------------------------------------------------------------------- #

                # receivable packet types: 
                # DISCONNECT : indicates manual closure from the IoT
                # MESSAGE : data transfer between sockets

                # sendable thread messages: 
                # TRANSFER  : data transfer between threads

                try:
                    self.socket.settimeout(0.01)
                    (packet_type,data) = PacketTCP.parse(self.__recv_secure())
                except socket.timeout:
                    continue

                
                if packet_type == PacketType.DISCONNECT:
                    raise Exception(f'Manual Disconnect from the client : ({self.client_type}) - {self.address[0]}:{self.address[1]}')
                elif packet_type == PacketType.MESSAGE and current_recv_comm == True:
                    msg = ThreadMessage(self.ident,ThreadMessageType.TRANSFER,data)
                    # tries to send message to subs
                    for k, v in current_thread_subs.items():
                        # if function returns false, meaning that target thread is no longer available, removes it
                        if not v.send(msg):
                            current_thread_subs.pop(k)

        except Exception as e:
            # send notification to each thread subbed to this iot
            msg = ThreadMessage(self.ident,ThreadMessageType.CONNECTION_END)
            for sub_interface in current_thread_subs.values():
                sub_interface.send(msg)
            raise e

    def __user_module(self):
        """
        User outer and inner communication manager function
        """

        username:str = None
        user_level:int = None

        user_authentication:bool = False            # user login authentication
        admin_authority:bool = False                # indicates admin authority
        target_interface:ThreadInterface = None     # target IoT's interface
        current_recv_comm:bool = False              # indicates if there is active communication

        try:
            while not self._stop_request.is_set():
                # --------------------------------------------------------------------------------- #
                # INNERCOMMUNICATION BETWEEN THREADS, checks thread messages from channel           #
                # --------------------------------------------------------------------------------- #

                # receivable thread messages: 
                # CONNECTION_BEGIN : indicates start of communication
                # CONNECTION_END : indicates end of communication
                # TRANSFER  : data transfer between threads

                try:
                    thread_message:ThreadMessage = self._channel.get(block=True,timeout=0.05)
                except queue.Empty:
                    thread_message = None

                # if there is a new message, change with old one
                if thread_message:
                    current_comm_type = thread_message.message_type
                else:
                    current_comm_type = None

                # --------------------------------------------------------------------------------- #
                # OUTERCOMMUNCATION TO USER, sends other thread's messages to USER                  #
                # --------------------------------------------------------------------------------- #

                if user_authentication == True:
                    if current_comm_type == ThreadMessageType.CONNECTION_END:
                        self.__send_secure(PacketType.DEVICE_CONNECTION_DENIED,b'')
                        current_recv_comm = False
                    elif current_comm_type == ThreadMessageType.TRANSFER:
                        self.__send_secure(PacketType.MESSAGE,thread_message.data)

                # --------------------------------------------------------------------------------- #
                # OUTERCOMMUNICATION FROM USER, recieves User's messages and transfers them         #
                # --------------------------------------------------------------------------------- #

                try:
                    self.socket.settimeout(0.01)
                    (packet_type,data) = PacketTCP.parse(self.__recv_secure())
                except socket.timeout:
                    continue

                # --------------------- USER LOGIN ---------------------
                if packet_type == PacketType.USER_LOGIN:
                    if user_authentication == False:
                        # JSON user login details
                        details:dict = json.loads(data.decode('UTF-8'))

                        t_username = details['username']
                        t_password = details['password']
                        
                        (validity,row) = self._database_interface.check_user_validity(t_username,t_password)

                        if validity == True:
                            # login success
                            username = t_username
                            user_level = row[0][2]
                            user_authentication = True

                            if user_level == 0:
                                admin_authority = True
                                self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) {t_username} with admin authority has succesfully logged in.',LogLevel.INFO,inspect.currentframe())
                            else:
                                self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) {t_username} with role {user_level} has succesfully logged in.',LogLevel.INFO,inspect.currentframe())
                            self.__send_secure(PacketType.USER_LOGIN_FINISHED,str(user_level).encode('UTF-8'))

                        else:
                            self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) tried to log but there is no such username {t_username} in the database.',LogLevel.INFO,inspect.currentframe())
                            self.__send_secure(PacketType.USER_LOGIN_DENIED,'Not valid account details'.encode('UTF-8'))
                    else:
                        self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) tried to log in while logged in.',LogLevel.WARNING,inspect.currentframe())
                        self.__send_secure(PacketType.USER_LOGIN_DENIED,'Already logged in'.encode('UTF-8'))
                
                # --------------------- USER REGISTER  ---------------------
                elif packet_type == PacketType.USER_REGISTER:
                    if user_authentication == False:
                        # JSON user register details
                        details:dict = json.loads(data.decode('UTF-8'))

                        r_username = details['username']
                        r_password = details['password']

                        (validity, r_exception) = self._database_interface.add_user(r_username,2,"guest",r_password,None)

                        if validity == True:
                            # register success
                            self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) {r_username} has succesfully registered.',LogLevel.INFO,inspect.currentframe())
                            self.__send_secure(PacketType.USER_REGISTER_FINISHED,str(2).encode('UTF-8'))
                        else:
                            self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) {r_username} has failed to register, {r_exception}.',LogLevel.ERROR,inspect.currentframe())
                            self.__send_secure(PacketType.USER_REGISTER_DENIED,"Register failed".encode('UTF-8'))
                    else:
                        self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) tried to log in while logged in.',LogLevel.WARNING,inspect.currentframe())
                        self.__send_secure(PacketType.USER_LOGIN_DENIED,'Already logged in'.encode('UTF-8'))

                # --------------------- USER LOGOUT  ---------------------
                elif packet_type == PacketType.USER_LOGOUT:
                    if user_authentication:
                        # RESET
                        if target_interface:
                            if target_interface.is_alive():
                                target_interface.send(ThreadMessage(self.ident,ThreadMessageType.CONNECTION_END))
                        username = None
                        user_level = None
                        user_authentication = False            
                        admin_authority = False                
                        target_interface = None     
                        current_recv_comm = False              

                # --------------------- ACTIVE DEVICE LIST ---------------------
                elif packet_type == PacketType.ACTIVE_DEVICE_LIST:
                    if user_authentication == True:
                        devices = {}
                        for k, v in self._archive_interface.get_level1_threads().items():
                            if user_level <= v.iot_level:
                                devices[k] = f'level: {v.iot_level} name: {v.name}' 
                        self.__send_secure(PacketType.ACTIVE_DEVICE_LIST,json.dumps(devices).encode('UTF-8'))
                    else:
                        self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) tried to action with no proper authority',LogLevel.INFO,inspect.currentframe())
                        self.__send_secure(PacketType.USER_AUTH_REQUIRED,'User authentication is required'.encode('UTF-8'))
                
                # --------------------- CONNECT TO DEVICE ---------------------
                elif packet_type == PacketType.CONNECT_TO_DEVICE:
                    if user_authentication == True:
                        target_device = int(data.decode('UTF-8'))
                        devices = self._archive_interface.get_level1_threads()
                        if target_device in devices.keys():
                            if user_level > devices[target_device].iot_level:
                                self.__send_secure(PacketType.DEVICE_CONNECTION_DENIED,'not allowed for this device'.encode('UTF-8'))
                            else:
                                target_interface = devices[target_device]._interface
                                current_recv_comm = True
                                self.__send_secure(PacketType.DEVICE_CONNECTION_FINISHED,b'')
                                target_interface.send(ThreadMessage(self.ident,ThreadMessageType.CONNECTION_BEGIN,self._interface))
                        else:
                            self.__send_secure(PacketType.DEVICE_CONNECTION_DENIED,'Not valid device detail'.encode('UTF-8'))
                    else:
                        self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) tried to action with no proper authority',LogLevel.INFO,inspect.currentframe())
                        self.__send_secure(PacketType.USER_AUTH_REQUIRED,'User authentication is required'.encode('UTF-8'))

                # --------------------- DISCONNECT FROM DEVICE ---------------------
                elif packet_type == PacketType.DISCONNECT_FROM_DEVICE:
                    if user_authentication == True:
                        if current_recv_comm:
                            target_interface.send(ThreadMessage(self.ident,ThreadMessageType.CONNECTION_END))
                            current_recv_comm = False
                    else:
                        self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) tried to action with no proper authority',LogLevel.INFO,inspect.currentframe())
                        self.__send_secure(PacketType.USER_AUTH_REQUIRED,'User authentication is required'.encode('UTF-8'))
                
                # --------------------- CHANGE USER'S PASSWORD ---------------------
                elif packet_type == PacketType.CHANGE_PASSWORD:
                    if user_authentication:
                        # JSON user change password details
                        details:dict = json.loads(data.decode('UTF-8'))

                        old_password = details['old_password']
                        new_password = details['new_password']

                        (validity, r_exception) = self._database_interface.change_password(username,old_password,new_password)
                        if validity:
                            # change password success
                            self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) {username} has succesfully changed its password',LogLevel.INFO,inspect.currentframe())
                            self.__send_secure(PacketType.CHANGE_PASSWORD_FINISHED,b'')
                        else:
                            self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) {username} has succesfully changed its password',LogLevel.INFO,inspect.currentframe())
                            self.__send_secure(PacketType.CHANGE_PASSWORD_DENIED,str(r_exception).encode('UTF-8'))    
                    else:
                        self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) tried to action with no proper authority',LogLevel.INFO,inspect.currentframe())
                        self.__send_secure(PacketType.USER_AUTH_REQUIRED,'User authentication is required'.encode('UTF-8'))

                # --------------------- CHANGE USER'S USERNAME ---------------------
                elif packet_type == PacketType.CHANGE_USERNAME:
                    if user_authentication:
                        # JSON user change username details
                        details:dict = json.loads(data.decode('UTF-8'))

                        new_username = details['new_username']

                        (validity, r_exception) = self._database_interface.change_username(username,new_username) 
                        if validity:
                            # change username success
                            self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) {username} has succesfully changed its username to {new_username}',LogLevel.INFO,inspect.currentframe())
                            username = new_username
                            self.__send_secure(PacketType.CHANGE_USERNAME_FINISHED,b'')
                        else:
                            self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) {username} has failed to change its password to {new_username}',LogLevel.INFO,inspect.currentframe())
                            self.__send_secure(PacketType.CHANGE_USERNAME_DENIED,r_exception)    
                    else:
                        self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) tried to action with no proper authority',LogLevel.INFO,inspect.currentframe())
                        self.__send_secure(PacketType.USER_AUTH_REQUIRED,'User authentication is required'.encode('UTF-8'))

                # --------------------- CHANGE OTHER USER'S LEVEL ---------------------
                elif packet_type == PacketType.CHANGE_USER_LEVEL:
                    if user_authentication and admin_authority:
                        details:dict = json.loads(data.decode('UTF-8'))

                        target_username = details['target_username']
                        new_role = int(details['new_role'])

                        if target_username == username:
                            # cannot modify itself
                            self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) {username} has succesfully changed its password',LogLevel.INFO,inspect.currentframe())
                            self.__send_secure(PacketType.CHANGE_USER_LEVEL_DENIED,"Cannot modify itself".encode('UTF-8'))
                        else:
                            (validity, r_exception) = self._database_interface.change_role(target_username,new_role) 

                            if validity:
                                # change role success
                                self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) {username} has succesfully changed its password',LogLevel.INFO,inspect.currentframe())
                                self.__send_secure(PacketType.CHANGE_USER_LEVEL_FINISHED,b'')
                            else:
                                self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) {username} has succesfully changed its password',LogLevel.INFO,inspect.currentframe())
                                self.__send_secure(PacketType.CHANGE_USER_LEVEL_DENIED,r_exception)    
                             
                    else:
                        self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) tried to action with no proper authority',LogLevel.INFO,inspect.currentframe())
                        self.__send_secure(PacketType.ADMIN_AUTH_REQUIRED,'Admin authentication is required'.encode('UTF-8'))

                # --------------------- USER LIST ---------------------
                elif packet_type == PacketType.USER_LIST:
                    if user_authentication and admin_authority:
                        details:dict = {}
                        (validity, data) = self._database_interface.get_users()

                        if validity:
                            # success getting list of users
                            for row in data:
                                details[row[1]] = f'role: {row[2]}, name: {row[3]}'

                            data = json.dumps(details)

                            self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) {username} has succesfully changed its password',LogLevel.INFO,inspect.currentframe())
                            self.__send_secure(PacketType.USER_LIST,data.encode('UTF-8'))
                        else:

                            data = json.dumps(details)
                            self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) {username} has failed to get list of users: {data}',LogLevel.INFO,inspect.currentframe())
                            self.__send_secure(PacketType.USER_LIST,data)    
                    else:
                        self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) tried to action with no proper authority',LogLevel.INFO,inspect.currentframe())
                        self.__send_secure(PacketType.ADMIN_AUTH_REQUIRED,'Admin authentication is required'.encode('UTF-8'))
 
                # --------------------- CHANGE DEVICE'S LEVEL ---------------------
                elif packet_type == PacketType.CHANGE_DEVICE_LEVEL:
                    if user_authentication and admin_authority:
                        details:dict = json.loads(data.decode('UTF-8'))

                        target_device = int(details['target_device'])
                        new_device_level = int(details['new_device_level'])

                        devices:dict = self._archive_interface.get_level1_threads()
                        if target_device in devices:
                            devices[target_device].iot_level = new_device_level
                            self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) has changed device ({target_device} to {new_device_level}) level',LogLevel.INFO,inspect.currentframe())
                            self.__send_secure(PacketType.CHANGE_DEVICE_LEVEL_FINISHED,'Success'.encode('UTF-8'))
                        else:
                            self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) has failed to change device level but there was no such given device',LogLevel.INFO,inspect.currentframe())
                            self.__send_secure(PacketType.CHANGE_DEVICE_LEVEL_DENIED,'Denied'.encode('UTF-8'))


                    else:
                        self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) tried to action with no proper authority',LogLevel.INFO,inspect.currentframe())
                        self.__send_secure(PacketType.ADMIN_AUTH_REQUIRED,'Admin authentication is required'.encode('UTF-8'))

                # --------------------- LOW TIER IOT REGISTER ---------------------
                elif packet_type == PacketType.LOW_TIER_REGISTER:
                    if user_authentication and admin_authority:
                        # will create account for the low tier device
                        nonce:bytes = urandom(32)
                        random1:bytes = urandom(32)
                        random2:bytes = urandom(32)
                        lowtier_pre_master_key:bytes = urandom(48)
                        lowtier_master_key:bytes = Keys.create_master_key(lowtier_pre_master_key,random1,random2)
                        lowtier_aes_key:bytes = Keys.derive_whole_keys_from_master(lowtier_master_key,random1,random2)

                        # add to the database
                        (r_bool,lowtier_identifier) = self._database_interface.add_lowtier(lowtier_aes_key,nonce)
                        if r_bool:
                            # register success
                            packet = lowtier_aes_key + nonce + str(lowtier_identifier).encode('UTF-8')
                            self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) has created a low tier account',LogLevel.INFO,inspect.currentframe())
                            self.__send_secure(PacketType.LOW_TIER_REGISTER_FINISHED,packet)
                        else:
                            self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) has failed to create a low tier account',LogLevel.INFO,inspect.currentframe())
                            self.__send_secure(PacketType.LOW_TIER_REGISTER_DENIED,lowtier_identifier)
                    else:
                        self._logger_interface.write_log(f'Client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) tried to action with no proper authority',LogLevel.INFO,inspect.currentframe())
                        self.__send_secure(PacketType.ADMIN_AUTH_REQUIRED,'Admin authentication is required'.encode('UTF-8'))

        except Exception as e:
            # send notification to target iot
            if target_interface:
                if target_interface.is_alive():
                    target_interface.send(ThreadMessage(self.ident,ThreadMessageType.CONNECTION_END))
            raise e

    def __low_iot_module(self,lowtier_identifier:int,aes_key:bytes):
        """
        Low-tier IoT outer and inner communication manager function
        """
        current_thread_subs = {}    # dict to hold interfaces of establsihed intercomm threads
        current_recv_comm = False   # indicates if there is active communication
        try:
            while not self._stop_request.is_set():
                # --------------------------------------------------------------------------------- #
                # INNERCOMMUNICATION BETWEEN THREADS, checks thread messages from channel           #
                # --------------------------------------------------------------------------------- #

                # receivable thread messages: 
                # CONNECTION_BEGIN : indicates start of communication
                # CONNECTION_END : indicates end of communication
                # TRANSFER  : data transfer between threads

                try:
                    thread_message:ThreadMessage = self._channel.get(block=True,timeout=0.05)
                except queue.Empty:
                    thread_message = None
                
                # if there is a new message, change with old one
                if thread_message:
                    current_comm_type = thread_message.message_type
                else:
                    current_comm_type = None

                # --------------------------------------------------------------------------------- #
                # OUTERCOMMUNCATION TO IOT, sends other thread's messages to IoT                    #
                # --------------------------------------------------------------------------------- #

                # sendable packet types:
                # START_COMMUNICATION : indicates start of communication
                # END_COMMUNICATION : indicates end of communication
                # MESSAGE : data transfer between sockets

                if current_comm_type == ThreadMessageType.CONNECTION_BEGIN:
                    # add new thread's interface
                    current_thread_subs[thread_message.sender_tid] = thread_message.data
                    if len(current_thread_subs) == 1:
                        # sends packet iot to indicate start of communication
                        packet = PacketTCP.form_lowtier_packet(PacketType.START_COMMUNCATION,aes_key,b'')
                        self.socket.send(packet)
                        self._logger_interface.write_log(f'Requested client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) to start communication.',LogLevel.INFO,inspect.currentframe())
                        current_recv_comm = True
                    self.description = f"{self.address[0]}:{self.address[1]}) {ClientMode.COMMUNICATING} - {[f'{str(k)} ' for k in current_thread_subs.keys()]}"
                elif current_comm_type == ThreadMessageType.CONNECTION_END:
                    # remove existing thread's interface
                    current_thread_subs.pop(thread_message.sender_tid)
                    self.description = f"{self.address[0]}:{self.address[1]}) {ClientMode.COMMUNICATING} - {[f'{str(k)} ' for k in current_thread_subs.keys()]}"
                elif current_comm_type == ThreadMessageType.TRANSFER:
                    packet = PacketTCP.form_lowtier_packet(PacketType.START_COMMUNCATION,aes_key,thread_message.data)
                    self.socket.send(packet)

                if len(current_thread_subs) == 0 and current_recv_comm == True:
                    # send packet iot to indicate end of communication
                    packet = PacketTCP.form_lowtier_packet(PacketType.END_COMMUNCATION,aes_key,b'')
                    self.socket.send(packet)
                    self._logger_interface.write_log(f'Requested client : ({self.client_type}) - ({self.address[0]}:{self.address[1]}) to end communication.',LogLevel.INFO,inspect.currentframe())
                    current_recv_comm = False

                # --------------------------------------------------------------------------------- #
                # OUTERCOMMUNICATION FROM IOT, recieves IoT's messages and transfers them           #
                # --------------------------------------------------------------------------------- #

                # receivable packet types: 
                # DISCONNECT : indicates manual closure from the IoT
                # MESSAGE : data transfer between sockets

                # sendable thread messages: 
                # TRANSFER  : data transfer between threads

                try:
                    self.socket.settimeout(0.01)
                    data = PacketTCP.recv_t(self.socket)
                    (packet_type,data) = PacketTCP.parse_lowtier_packet(aes_key,data)
                except socket.timeout:
                    continue

                if packet_type == PacketType.DISCONNECT:
                    raise Exception(f'Manual Disconnect from the client : ({self.client_type}) - {self.address[0]}:{self.address[1]}')
                elif packet_type == PacketType.MESSAGE and current_recv_comm == True:
                    msg = ThreadMessage(self.ident,ThreadMessageType.TRANSFER,data)
                    # tries to send message to subs
                    for k, v in current_thread_subs.items():
                        # if function returns false, meaning that target thread is no longer available, removes it
                        if not v.send(msg):
                            current_thread_subs.pop(k)

        except Exception as e:
            # send notification to each thread subbed to this iot
            msg = ThreadMessage(self.ident,ThreadMessageType.CONNECTION_END)
            for sub_interface in current_thread_subs.values():
                sub_interface.send(msg)
            raise e