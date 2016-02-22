import socket
import threading
import os
import httplib
from Queue import Queue
import connection as c

ADDRESS = "/home/jotaro/uni/BA/scripts/socket.sock" # ("1.2.3.4", 8080)
counter = 0
CONNECTIONS = []

try:
    os.remove(ADDRESS)
except:
    pass


if __name__ == '__main__':
    #INIT

    #create an INET, STREAMing socket
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(ADDRESS)
    # make s a server socket
    s.listen(5)

    # start processing connections
    while True:
        client, addr = s.accept()
        print "New connection No. " + str(counter)
        con = c.Connection(client, addr, counter)
        CONNECTIONS.append(con)
        counter += 1



