from packet import PacketTCP, PacketType
from os import urandom
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey,RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.padding import PKCS7 
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import socket, hmac, hashlib

def handshake(socket,client_cert,client_prv,cert_store) -> (bytes,bytes):
    server_cert:crypto.X509 = None
    client_random,server_random,master_key = None,None,None
    try:
        print(f'---------- HANDSHAKE PROTOCOL ----------')
        # CLIENT HELLO
        client_random = urandom(32)
        packet = PacketTCP.form(PacketType.CLIENT_HELLO,client_random)
        socket.send(packet)
        print(f'\n##### CLIENT_HELLO is sent\n##### client random :\n{client_random}',end='\n\n')

        # SERVER HELLO
        (packet_type,data) = PacketTCP.receive(socket)
        if packet_type != PacketType.SERVER_HELLO:
            raise Exception('CLIENT_HELLO must be sent first!')
        else:
            server_random = data[:32]
            server_cert = crypto.load_certificate(crypto.FILETYPE_PEM,data[32:])
            ctx = crypto.X509StoreContext(cert_store,server_cert)
            ctx.verify_certificate()
            print(f'##### SERVER_HELLO is received\n##### server random :\n{server_random}\n##### verified server cert :\n{data[32:]}',end='\n\n')

        # CLIENT CERTIFICATE REQUEST & CLIENT CERTIFICATE
        (packet_type,data) = PacketTCP.receive(socket) 
        if packet_type == PacketType.CLIENT_CERT_REQUEST:
            print(f'##### CLIENT_CERT_REQUEST is received',end='\n\n')
            client_cert_dumped = crypto.dump_certificate(crypto.FILETYPE_PEM,client_cert)
            packet = PacketTCP.form(PacketType.CLIENT_CERT,client_cert_dumped)
            socket.send(packet)
            print(f'##### CLIENT_CERT is sent\n client cert :\n{client_cert_dumped}',end='\n\n')

        # KEY INFO
        server_public_key:RSAPublicKey= server_cert.get_pubkey().to_cryptography_key() 
        pre_master_secret = urandom(48)
        encrypted_pre_master_secret = server_public_key.encrypt(pre_master_secret,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        packet = PacketTCP.form(PacketType.KEY_INFO,encrypted_pre_master_secret)
        socket.send(packet)
        print(f'##### KEY_INFO is sent\n##### pre-master-secret :\n{pre_master_secret}\n##### encrypted pre-master-key :\n{encrypted_pre_master_secret}',end='\n\n')

        # CLIENT CERTIFICATE VERIFY
        signed_client_cert =  client_prv.sign(client_cert_dumped,padding=padding.PKCS1v15(),algorithm=hashes.SHA256())
        packet = PacketTCP.form(PacketType.CLIENT_CERT_VERIFY,signed_client_cert)
        socket.send(packet)
        print(f'##### CLIENT_CERT_VERIFY is sent\n##### signed client cert :\n{signed_client_cert}',end='\n\n')

        # MASTER KEY
        seed = 'master secret'.encode('utf-8') + client_random + server_random
        print(f'##### Master seed for hmac :\n{seed}',end='\n\n')
        a0 = seed
        h = hmac.new(key=pre_master_secret,digestmod=hashlib.sha256)

        h.update(a0)
        a1 = h.digest()
        h.update(a1)
        a2 = h.digest()
        h.update(a1 + seed)

        p = h.digest()
        h.update(a2 + seed)
        p += h.digest()
        master_key = p[:48]
        print(f'##### Master key :\n{master_key}',end='\n\n')

        # CLIENT FINISHED
        seed = 'client finished'.encode('UTF-8') + hashlib.sha256(pre_master_secret).digest()
        a0 = seed 
        h = hmac.new(key=master_key, digestmod=hashlib.sha256)

        h.update(a0)
        a1 = h.digest()
        h.update(a1 + seed)
        p1 = h.digest()
        data = p1[:12]
        packet = PacketTCP.form(PacketType.CLIENT_FINISHED,data)
        socket.send(packet)
        print(f'##### CLIENT_FINISHED is sent\n##### hash :\n{data}',end='\n\n')

        # SERVER FINISHED
        (packet_type,hash_s) = PacketTCP.receive(socket) 
        if packet_type != PacketType.SERVER_FINISHED:
            raise Exception('SERVER_FINISHED was needed but failed!')
        else:
            seed = 'server finished'.encode('UTF-8') + hashlib.sha256(pre_master_secret).digest()
            a0 = seed
            h = hmac.new(key=master_key, digestmod=hashlib.sha256)
            h.update(a0)
            a1 = h.digest()
            h.update(a1 + seed)
            p1 = h.digest()
            data = p1[:12]
            if data == hash_s:
                print(f'##### SERVER_FINISHED is received\n##### hash :\n{data}',end='\n\n')
            else:
                raise Exception('SERVER_FINISHED comparison failed!')

        # EXPANSION KEYS
        seed = 'key expansion'.encode('utf-8') + client_random + server_random
        print(f'##### Expansion seed for hmac :\n{seed}',end='\n\n')
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
        
        client_write_mac_key = p[:32]
        server_write_mac_key = p[32:64]
        client_write_key = p[64:80]
        server_write_key = p[80:96]
        client_write_iv = p[96:112]
        server_write_iv = p[112:128]

        print(f'##### Client write mac key :\n{client_write_mac_key}')
        print(f'##### Server write mac key :\n{server_write_mac_key}')
        print(f'##### Client write key :\n{client_write_key}')
        print(f'##### Server write key :\n{server_write_key}')
        print(f'##### Client write IV :\n{client_write_iv}')
        print(f'##### Server write IV :\n{server_write_iv}')

        print('---------- HANDSHAKE IS DONE ----------')

        return master_key,p
    except Exception as e:
        raise e