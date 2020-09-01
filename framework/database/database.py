from utilities.thread import FrameworkThread, ThreadInterface, Priority
from database.queries import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from hashlib import sha512
from os import urandom

import sqlite3, threading, datetime

class Database(FrameworkThread):
    def __init__(self,settings:dict,database_file_location:str):
        super().__init__('DATABASE', 'database management', daemon=False, priority=Priority.LEVEL0)
        self._connection = None
        self._path = database_file_location
        self._db_mutex = threading.Lock()

    def __connect(self) -> None:
        """
        Connect to the database
        """
        self._connection = sqlite3.connect(self._path,check_same_thread=False)

    def __disconnect(self) -> None:
        """
        Disconnect from the database
        """
        if self.__active(): self._connection.close()

    def __active(self) -> bool:
        """
        Check whether connection is open or not
        """
        if self._connection: return True
        else: return False

    def create_interface(self):
        self._interface = DatabaseInterface(self)
        return self._interface

    def run(self):
        """
        Do routine check-ups on database connection and for the data inside
        """
        self.__connect()
        while not self._stop_request.is_set() and self.__active():
            try:
                # TODO
                # check guests account and their timestamp, if expired delete them
                # checks low-tier iots devices, if expired or not active, delete them
                pass 

            except Exception as e:
                pass
        self.__disconnect()



class DatabaseInterface(ThreadInterface):
    def __init__(self, thread:Database):
        super().__init__(thread)

    def check_table(self,*args) -> list():
        """
        Takes table string(s) as input and checks whether they exist in the database or not
        then returns list of booleans in the size of input to indicate their existence
        """
        result = []
        try:
            cursor = self._thread._connection.cursor()
            for arg in args:
                cursor.execute(CHECK_TABLE,(arg,))
                if len(cursor.fetchall()) == 1:
                    result.append(True)
                else:
                    result.append(False)
        except Exception as e:
            return [False in range(len(args))]
        finally:
            return result

    def add_user(self,username:str,role:int,name:str,password:str,expire_duration:int=None) -> (bool,Exception):
            """
            Adds a defined user to the database
            
            Arguments:
            - username {str} -- unique user identifier
            - role {int} -- 0: admin, 1: privileged, 2: guest
            - name {str} -- user's name
            - password {str} -- user's password
            - expire_duration {int} -- days until expiration (default: {None})
            
            Returns:
            - (bool,exception) -- returns either (True,None) or (False, Exception)
            """
            r_val = (True,None) # return pair variable
            conn_locked = False # indicates whether this thread locked the conn or not
            try:
                password_salt = urandom(32)
                password_hash = sha512(password.encode('utf-8') + password_salt).digest()

                if expire_duration:
                    expire_duration = (datetime.datetime.now() + datetime.timedelta(days=expire_duration)).strftime("%Y-%m-%d %H:%M:%S")

                self._thread._db_mutex.acquire()
                conn_locked = True
                cursor = self._thread._connection.cursor()
                cursor.execute(ADD_USER,(username,role,name,password_hash,password_salt,expire_duration))
                if cursor.rowcount > 0:
                    self._thread._connection.commit()
                else:
                    r_val = (False,"Query was not succesful!")
            except Exception as e:
                r_val = (False, e)
            finally:
                if conn_locked: self._thread._db_mutex.release()
                return r_val

    def add_lowtier(self,keys:bytes,nonce:bytes) -> (bool,Exception):
            """
            Adds a low tier account to the database
            
            Arguments:
            - keys {bytes} -- whole derived keys
            - nonce {bytes} -- random 32 bytes for auth
            
            Returns:
            - (bool,exception) -- returns either (True,None) or (False, Exception)
            """
            r_val = (True,None) # return pair variable
            conn_locked = False # indicates whether this thread locked the conn or not

            try:
                self._thread._db_mutex.acquire()
                conn_locked = True
                cursor = self._thread._connection.cursor()
                cursor.execute(ADD_LOWTIER,(keys,nonce))

                if cursor.rowcount > 0:
                    self._thread._connection.commit()
                    r_val = (True,cursor.lastrowid)
                else:
                    r_val = (False,"Query was not succesful!")

            except Exception as e:
                r_val = (False, e)
            finally:
                if conn_locked: self._thread._db_mutex.release()
                return r_val

    def change_username(self,username:str,new_username:str) -> (bool,Exception):
        """
        Changes user's username

        Arguments:
        - username {str} -- unique user identifier
        - new_username {str} -- new user identifier

        Returns:
        - (bool,exception) -- returns either (True,None) or (False, Exception)
        """
        r_val = (True,None) # return pair variable
        conn_locked = False # indicates whether this thread locked the conn or not

        # check if there is an user with given new username
        try:
            (fethched_bool,_) = self.fetch_user(username)
            if fethched_bool == True:
                self._thread._db_mutex.acquire()
                conn_locked = True
                cursor = self._thread._connection.cursor()
                cursor.execute(UPDATE_USERNAME,(new_username,username))
                if cursor.rowcount > 0:
                    self._thread._connection.commit()
                else:
                    r_val = (False,"Query was not succesful!")
            else:
                raise Exception('There is already an user with the same username.')
        except Exception as e:
            r_val = (False,e)
        finally:
            if conn_locked: self._thread._db_mutex.release()
            return r_val

    def change_password(self,username:str,old_password:str,new_password:str) -> (bool,Exception):
        """
        Changes user's password

        Arguments:
        - username {str} -- unique user identifier
        - old_password {str} -- old password
        - new_password {str} -- new password

        Returns:
        - (bool,exception) -- returns either (True,None) or (False,Exception)
        """
        r_val = (True,None) # return pair variable
        conn_locked = False # indicates whether this thread locked the conn or not

        try:
            (fethched_bool,r_exception) = self.check_user_validity(username,old_password)
            if fethched_bool == True:
                self._thread._db_mutex.acquire()
                conn_locked = True

                new_password_salt = urandom(32)
                new_password_hash = sha512(new_password.encode('utf-8') + new_password_salt).digest()

                cursor = self._thread._connection.cursor()
                cursor.execute(UPDATE_PASSWORD,(new_password_hash,new_password_salt,username))

                if cursor.rowcount > 0:
                    self._thread._connection.commit()
                else:
                    r_val = (False,"Query was not succesful!")
            else:
                raise r_exception
        except Exception as e:
            r_val = (False,e)
        finally:
            if conn_locked: self._thread._db_mutex.release()
            return r_val

    def change_role(self,target_username:str,new_role:int):
        """
        Changes user's role

        Arguments:
        - username {str} -- unique user identifier
        - new role {int} -- new role (0:admin, 1: priv, 2: guest)

        Returns:
        - (bool,exception) -- returns either (True,None) or (False,Exception)
        """
        r_val = (True,None) # return pair variable
        conn_locked = False # indicates whether this thread locked the conn or not

        try:
            (fethched_bool,row) = self.fetch_user(target_username)

            if fethched_bool == True:
                self._thread._db_mutex.acquire()
                conn_locked = True

                cursor = self._thread._connection.cursor()
                cursor.execute(UPDATE_ROLE,(new_role,target_username))

                if cursor.rowcount > 0:
                    self._thread._connection.commit()
                else:
                    r_val = (False,"Query was not succesful!")
            else:
                raise Exception('There is already an user with the same username.')
        except Exception as e:
            r_val = (False,e)
        finally:
            if conn_locked: self._thread._db_mutex.release()
            return r_val

    def remove_user(self,username:str) -> (bool,Exception):
        """
        Removes an user from the database

        Arguments:
        - username {str} -- unique user identifier

         Returns:
        - (bool,exception) -- returns either (True,None) or (False, Exception)
        """
        r_val = (True,None) # return pair variable
        conn_locked = False # indicates whether this thread locked the conn or not
        try:
            self._thread._db_mutex.acquire()
            conn_locked = True
            cursor = self._thread._connection.cursor()
            cursor.execute(REMOVE_USER,(username,))
            if cursor.rowcount > 0:
                self._thread._connection.commit()
            else:
                r_val = (False,"Query was not succesful!")
        except Exception as e:
            r_val = (False,e)
        finally:
            if conn_locked: self._thread._db_mutex.release()
            return r_val

    def fetch_user(self,username:str) -> (bool,Exception):
        """
        Fetch user's data
        
        Arguments:
        - username {str} -- unique user identifier
        
        Returns:
        - (bool,data/Exception) -- returns either (True,Data) or (False, Exception)
        """
        try:
            cursor = self._thread._connection.cursor()
            cursor.execute(FETCH_USER,(username,))
            row = cursor.fetchall()
            return (True, row)
        except Exception as e:
            return (False, e)

    def check_lowtier_validity(self,identifier:int,iv:bytes,enc_nonce:bytes) -> (bool,Exception):
        """
        Compares given lowtier details with the one in the database if there is
        
        Arguments:
        - identifier {int} -- unique lowtier identifier
        - enc_nonce {bytes} -- encrpted nonce
        
        Returns:
        - (bool,data/Exception) -- returns either (True,Data) or (False, Exception)
        """ 
        try:
            cursor = self._thread._connection.cursor()
            cursor.execute(FETCH_LOWTIER,(identifier,))
            row = cursor.fetchall()

            d_keys:bytes = row[0][1] # 32 bytes
            d_nonce:bytes = row[0][2] # 32 bytes

            decryptor = Cipher(algorithms.AES(d_keys),modes.CBC(iv),default_backend()).decryptor()
            decrypted_nonce = decryptor.update(enc_nonce) + decryptor.finalize()

            if decrypted_nonce == d_nonce:
                return (True,[d_keys,d_nonce])
            else:
                return (False,Exception('Failed decryption'))
        except Exception as e:
            return (False,e)

    def get_users(self) -> (bool,Exception):
        """
        Get all users' data

        Returns:
        - (bool,data/Exception) -- returns either (True,Data) or (False, Exception)
        """

        try:
            cursor = self._thread._connection.cursor()
            cursor.execute(FETCH_USERS,())
            rows = cursor.fetchall()
            return (True,rows)
        except Exception as e:
            return (False,e)

    def check_user_validity(self,username:str,password:str) -> (bool,Exception):
        """
        With given user details, checkf if it is valid account by comparing hash of passwords
        """
        try:
            cursor = self._thread._connection.cursor()
            cursor.execute(FETCH_USER,(username,))
            row = cursor.fetchall()

            d_password_hash:bytes = row[0][4]
            d_password_salt:bytes = row[0][5]

            c_password_hash:bytes = sha512(password.encode('utf-8') + d_password_salt).digest()

            if c_password_hash == d_password_hash:
                return (True,row)
            else:
                return (False,Exception('Wrong password'))

        except Exception as e:
            return (False,e)