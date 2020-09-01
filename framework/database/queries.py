from enum import Enum

CHECK_TABLE = """
    SELECT name FROM sqlite_master
    WHERE type = 'table' AND name = ?;"""
CREATE_USERS_TABLE = """
    CREATE TABLE users (
        id				INTEGER PRIMARY KEY AUTOINCREMENT,
        username 		TEXT NOT NULL UNIQUE,
        role 			INTEGER NOT NULL DEFAULT 2,
        name 			TEXT NOT NULL DEFAULT 'guest',
        passwordHash	BLOB NOT NULL,
        passwordSalt	BLOB NOT NULL,
        register_date	REAL NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expire_date		REAL
    );"""
CREATE_CERTIFICATES_TABLE =  """
    CREATE TABLE "devices" (
        "ID"	INTEGER PRIMARY KEY AUTOINCREMENT,
        "type"	TEXT NOT NULL CHECK(type in ('low','high')),
        "description"	INTEGER CHECK(length(description)<=32),
        "cert_name"	TEXT NOT NULL,
        FOREIGN KEY("cert_name") REFERENCES "certificates"("name") ON DELETE CASCADE
    );"""
CREATE_DEVICES_TABLE = """
    CREATE TABLE "devices" (
        "ID"	INTEGER PRIMARY KEY AUTOINCREMENT,
        "type"	TEXT NOT NULL CHECK(type in ('low','high')),
        "description"	INTEGER CHECK(length(description)<=32),
        "cert_name"	TEXT NOT NULL,
        FOREIGN KEY("cert_name") REFERENCES "certificates"("name") ON DELETE CASCADE
    ); """

CREATE_LOWTIERS_TABLE = """
    CREATE TABLE "lowtiers" (
        "identifier"	INTEGER PRIMARY KEY AUTOINCREMENT,
        "keys"	BLOB NOT NULL,
        "nonce"	BLOB NOT NULL
    );"""

ADD_USER = """
    INSERT INTO users (username,role,name,passwordHash,passwordSalt,expire_date) VALUES (?,?,?,?,?,?);"""

ADD_LOWTIER = """
    INSERT INTO lowtiers (keys,nonce) VALUES (?,?);"""

FETCH_USER = """
    SELECT * FROM users
    WHERE username = ?;"""

FETCH_LOWTIER = """
    SELECT * FROM lowtiers
    WHERE identifier = ?;"""

FETCH_USERS = """
    SELECT * from users"""

FETCH_LOWTIERS = """
    SELECT * from lowtiers"""

UPDATE_USERNAME = """
    UPDATE users
    SET username = ?
    WHERE username = ?"""

UPDATE_PASSWORD = """
    UPDATE users
    SET passwordHash = ?,
        passwordSalt = ?
    WHERE username = ?"""

UPDATE_ROLE = """
    UPDATE users
    SET role = ?
    WHERE username = ?"""

REMOVE_USER = """
    DELETE FROM users
    WHERE "username" = ? AND "role" != 1;"""