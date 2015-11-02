# chatRoom-internet-security---database
import sqlite3
connection = sqlite3.connect("company.db")
cursor = connection.cursor()
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

