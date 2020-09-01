from packet import PacketTCP, PacketType
from high import HighIoTSimulation
from user import UserSimulation

from OpenSSL import crypto

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey,RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.padding import PKCS7 
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from os import urandom
import socket, hmac, hashlib

# YYYYMMDDhhmmssZ (TIME)

server_ip = '127.0.0.1'
server_port = 7777

ca_cert:crypto.X509 = crypto.load_certificate(crypto.FILETYPE_PEM,open('ca_cert.cer','r').read())
client_cert:crypto.X509 = crypto.load_certificate(crypto.FILETYPE_PEM,open('client.cer','r').read())
client_prv:RSAPrivateKey = crypto.load_privatekey(crypto.FILETYPE_PEM,open('client.pem','r').read()).to_cryptography_key()
cert_store = crypto.X509Store()
cert_store.add_cert(ca_cert)

def main():
    try:
        s = input('[SIMULATION] Select your simulation type (1: low-tier, 2: high-tier, 3: user):')
        while s not in ['1','2','3']:
            if s in ['exit','q','quit']: return
            s = input('[SIMULATION] Select your simulation type (1: low-tier, 2: high-tier, 3: user):')
            
        if s == '1':
            pass
        elif s == '2':
            sim = HighIoTSimulation(server_ip=server_ip,server_port=server_port,ca_cert=ca_cert,iot_cert=client_cert,iot_prv=client_prv)
            sim.simulate()
        elif s == '3':
            sim = UserSimulation(server_ip=server_ip,server_port=server_port,ca_cert=ca_cert,user_cert=client_cert,user_prv=client_prv)
            sim.simulate()
    except Exception as e:
        print(e)

if __name__ == '__main__':
    main()