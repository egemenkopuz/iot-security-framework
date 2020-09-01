from utilities.thread import FrameworkThread, ThreadInterface, Priority
from utilities.logger import LogLevel
from utilities.exceptions import HandshakeError

from OpenSSL import crypto

from network.client import Client

import socket, inspect, sys

class Server(FrameworkThread):
    def __init__(self,settings:dict,cert_file_location:str):
        super().__init__('SERVER', 'server management', daemon=False, priority=Priority.LEVEL0)
        self.ip = settings['IP']
        self.port = settings['PORT']
        self.description = f"Server Management Module ({self.ip}:{self.port})"

        root_cert =  crypto.load_certificate(crypto.FILETYPE_PEM,open(cert_file_location +'ca.cer','r').read())
        self.server_cert = crypto.load_certificate(crypto.FILETYPE_PEM,open(cert_file_location + 'server.cer','r').read())
        self.server_prv = crypto.load_privatekey(crypto.FILETYPE_PEM,open(cert_file_location + 'server.pem','r').read())
        self.cert_store = crypto.X509Store()
        self.cert_store.add_cert(root_cert)
        
    def run(self):
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as ssocket:
                ssocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                ssocket.settimeout(0.2)
                ssocket.bind((self.ip,self.port))
                ssocket.listen(5)

                self._logger_interface.write_log(f'Server ({self.ip}) started listening on port: {self.port}',LogLevel.INFO,inspect.currentframe())

                while not self._stop_request.is_set():
                    try:
                        csocket, address = ssocket.accept()
                        try:
                            self._logger_interface.write_log(f'Client ({address[0]}:{address[1]}) is trying to connect to the system, proceeded to Handshake protocol',LogLevel.INFO,inspect.currentframe())
                            client = Client(csocket,address,self.cert_store,self.server_cert,self.server_prv)
                            client.add_access_to_logger(self._logger_interface)
                            client.add_access_to_archive(self._archive_interface)
                            client.add_access_to_database(self._database_interface)
                            client.create_interface()
                            client.start()
                        except Exception as e: 
                            self._logger_interface.write_log(e,LogLevel.CRITICAL,inspect.currentframe())
                    except socket.timeout:
                        continue
                    except:
                        raise
                   
        except Exception as e:
            self._logger_interface.write_log(e,LogLevel.CRITICAL,inspect.currentframe())
            self._stop_request.set()

    def create_interface(self):
        self._interface = ServerInterface(self)
        return self._interface
        
class ServerInterface(ThreadInterface):
    def __init__(self, thread):
        super().__init__(thread)


