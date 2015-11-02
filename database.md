# chatRoom-internet-security---database


from mysql.connector import errorcode

from __future__ import print_function

cnx = mysql.connector.connect(user='scott', password='tiger',
                              host='127.0.0.1',
                              database='employees')
                              cnx.close()
