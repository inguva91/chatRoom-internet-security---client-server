# chatRoom-internet-security---database

import sqlite3
connection = sqlite3.connect("company.db")
cursor = connection.cursor()
$ pip install passlib

from passlib.hash import pbkdf2_sha256
 
hash = pbkdf2_sha256.encrypt("password", rounds=200000, salt_size=16)
 
sql_command = """
CREATE TABLE users ( 
uname VARCHAR(20), 
password VARCHAR(30), );"""
cursor.execute(sql_command)
sql_command = """INSERT INTO users (uname,password)
    VALUES ("William","anjana");"""
sql_command = """INSERT INTO users (uname,password)
    VALUES ("John","karan");"""
sql_command = """INSERT INTO users (uname,password)
    VALUES ("Jim","sudheer");"""
sql_command = """INSERT INTO users (uname,password)
    VALUES ("Max","archana");"""
sql_command = """INSERT INTO users (uname,password)
    VALUES ("Sarah","paarthu");"""
sql_command = """INSERT INTO users (uname,password)
    VALUES ("Nicole","lakshmi");"""
sql_command = """INSERT INTO users (uname,password)
    VALUES ("Randy","Murthy");"""
sql_command = """INSERT INTO users (uname,password)
    VALUES ("Maria","Durga");"""
sql_command = """INSERT INTO users (uname,password)
    VALUES ("Stevens","Sastry");"""
sql_command = """INSERT INTO users (uname,password)
    VALUES ("Karol","Krishna");"""
    
cursor.execute(sql_command)
connection.commit()

connection.close()

THIS CHECKS IF PASSWORDS MATCH

cursor.execute("SELECT * FROM users WHERE username= ? and password= ?",
    (username, pass1))
found = cursor.fetchone()
if found:
    # user exists and password matches
else:
    # user does not exist or password does not match
