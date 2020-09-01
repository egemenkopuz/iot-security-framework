from hashlib import sha512
import sys, os, yaml, sqlite3

class Setup():
    """
    Setup Module for the Secure Control Framework
    """
    def __init__(self):
        self._path = sys.path[0]
        self._settings_file_name = self._path + '\settings.yaml'
        self._database_file_name = self._path + '\database.sqlite3'

    def start(self):
        """
        Main setup function of the framework, checks anomalies and decides on 
        first time setup or factory based on user's input
        """
        anomalies, first_time = self.__detect_anomaly()
        anomaly_count = len(anomalies)
        if first_time:
            self.__first_time_setup()
            return
        if anomaly_count > 0:
            if anomaly_count == 1: print('Anomaly is detected!')
            else: print(f'{anomaly_count} Anomalies are detected!')
            [print('- ' + s) for s in anomalies] 
            print('Fatal crashes may occur due to anomaly. Strongly advised to factory reset. Would you like to initiate factory reset? (Y/n)')
            c = input('>> ')
            while True:
                if c.lower() in ['y','yes']:
                    self.__factory_reset()
                    break
                elif c.lower() in ['n','no']:
                    break
                else:
                    c = input('>> ')
                    
    def __detect_anomaly(self) -> (list,bool):
        """
        Detects anomalies in the framework directory 
        """
        anomalies, first_time = [], False
        if not os.path.isfile(self._database_file_name):
            anomalies.append(f'There is no database file with path {self._database_file_name} in the directory.')
            first_time = True
        else:
            # check database tables
            with sqlite3.connect(self._database_file_name) as conn:
                cursor = conn.cursor()
                cursor.execute(CHECK_TABLE,('lowtiers',))
                if len(cursor.fetchall()) != 1:
                    anomalies.append("There is no table named 'lowtiers' in the database")
                cursor.execute(CHECK_TABLE,('devices',))
                if len(cursor.fetchall()) != 1:
                    anomalies.append("There is no table named 'devices' in the database.")
                cursor.execute(CHECK_TABLE,('certificates',))
                if len(cursor.fetchall()) != 1:
                    anomalies.append("There is no table named 'certificates' in the database.")
                cursor.execute(CHECK_TABLE,('users',))
                if len(cursor.fetchall()) != 1:
                    anomalies.append("There is no table named 'users' in the database.")
                else:
                    # check for admin account
                    cursor.execute(GET_ADMIN_USER)
                    s = cursor.fetchall()
                    if len(s) == 0:
                        anomalies.append("There is no admin user in the database.")


        if not os.path.isfile(self._settings_file_name):
            anomalies.append(f'There is no settings file with path {self._settings_file_name} in the directory.')
            first_time = (first_time and True)
        else:
            # check settings attributes
            pass
        return anomalies, first_time

    def __first_time_setup(self) -> None:
        """
        First Time Setup
        """
        print('Secure Control Framework Setup:')
        # database and its tables creation
        with sqlite3.connect(self._database_file_name) as conn:
            cursor = conn.cursor()
            self.__show_progress(0,'Database')
            cursor.executescript(FIRST_TIME_INIT_SCRIPT)
            self.__show_progress(33,'Database')
            admin_salt = os.urandom(32)
            admin_hash = sha512('admin'.encode('UTF-8') + admin_salt).digest()
            self.__show_progress(66,'Database')
            cursor.execute(ADD_ADMIN_USER,(admin_hash,admin_salt))
            conn.commit()
            self.__show_progress(100,'Database\n')
        
        # settings file creation with default values
        with open(self._settings_file_name,'w') as settings_file:
            self.__show_progress(0,'Settings')
            s = yaml.dump(DEFAULT_SETTINGS,settings_file,default_flow_style=False,sort_keys=False)
            self.__show_progress(100,'Settings\n')

    def __factory_reset(self) -> None:
        """
        Factory Reset, removes existing/corrupted files
        and instead creates predefined default files
        """
        if os.path.exists(self._settings_file_name): 
                os.remove(self._settings_file_name)
        if os.path.exists(self._database_file_name):
                os.remove(self._database_file_name)

        self.__show_progress(0,'Factory Reset')
        self.__database()
        self.__show_progress(50,'Factory Reset')
        self.__settings()
        self.__show_progress(100,'Factory Reset is completed\n')

    def __database(self) -> None:
        """
        Creates database, then adds tables and admin account
        """
        # there is no database in the directory so
        # database will be created with predefined queries
        with sqlite3.connect(self._database_file_name) as conn:
            cursor = conn.cursor()
            # creates tables
            cursor.executescript(FIRST_TIME_INIT_SCRIPT)
            # creates admin user
            admin_salt = os.urandom(32)
            admin_hash = sha512('admin'.encode('UTF-8') + admin_salt).digest()
            cursor.execute(ADD_ADMIN_USER,(admin_hash,admin_salt))
            conn.commit()

    def __settings(self) -> None:
        """
        Creates settings yaml file and stores default setting values
        """
        settings_attrs = None
        if not os.path.isfile(self._settings_file_name):
            # there is no settings file in the directory
            with open(self._settings_file_name,'w') as f:
                # creates default settings file
                yaml.dump(DEFAULT_SETTINGS,f,default_flow_style=False,sort_keys=False)
            
    def __show_progress(self,perc:int,title:str="",size:int=40):
        """
        Prints a progress bar with given values
        
        Arguments:
            perc {int} -- from 0 to 100, prints corresponding value in the bar
        
        Keyword Arguments:
            title {str} -- name of the bar to be printed in the end (default: {""})
            size {int} -- size of the bar (default: {40})
        """
        count = (size * perc) // 100 
        if count > size:
            count = size
            output = f"[{'#'*count}{'-'*(size-count)}] 100% {title}\r"
        else: 
            output = f"[{'#'*count}{'-'*(size-count)}] {perc}% {title}\r"
        sys.stdout.write(output)
        sys.stdout.flush()

DEFAULT_SETTINGS = {'IP':'127.0.0.1',
                    'PORT':7777,
                    'LOG_PATH':'./logs/',
                    'MIN_LOG_LEVEL':'DEBUG'}

CHECK_TABLE = """
    SELECT name FROM sqlite_master
    WHERE type = 'table' AND name = ?;"""

FIRST_TIME_INIT_SCRIPT = """
    CREATE TABLE users (
		id				INTEGER PRIMARY KEY AUTOINCREMENT,
		username 		TEXT NOT NULL UNIQUE,
		role 			INTEGER NOT NULL DEFAULT 2,
		name 			TEXT NOT NULL DEFAULT 'guest',
		passwordHash	BLOB NOT NULL,
		passwordSalt	BLOB NOT NULL,
		register_date	REAL NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expire_date		REAL
	);

    CREATE TABLE "certificates" (
        "name"	TEXT NOT NULL CHECK(length(name)>=3),
        "expire_date"	REAL NOT NULL,
        "cert"	BLOB NOT NULL,
        PRIMARY KEY("name")
    );

    CREATE TABLE "devices" (
		"ID"	INTEGER PRIMARY KEY AUTOINCREMENT,
		"type"	TEXT NOT NULL CHECK(type in ('low','high')),
		"description"	INTEGER CHECK(length(description)<=32),
		"cert_name"	TEXT NOT NULL,
		FOREIGN KEY("cert_name") REFERENCES "certificates"("name") ON DELETE CASCADE
	);

    CREATE TABLE "lowtiers" (
	"identifier"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"keys"	BLOB NOT NULL,
	"nonce"	BLOB NOT NULL
    );
    """

GET_ADMIN_USER = """
    SELECT * FROM users
	WHERE role = 0;"""

ADD_ADMIN_USER = """ 
    INSERT INTO users (username,role,name,passwordHash,passwordSalt) VALUES ('admin',0,'administrator',?,?);"""