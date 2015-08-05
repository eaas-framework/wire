import socket
import threading
import os

ADDRESS = "/home/jotaro/uni/BA/scripts/socket.sock" # ("1.2.3.4", 8080)
counter = 0

def readSock(sock, no):
    while True:
        data = sock.recv(4096)
        if len(data) < 1:
            print("socket on " + str(no) + " closed")
            return
        print(no, data,)
        sock.send(data)
try:
    os.remove(ADDRESS)
except:
    pass

#create an INET, STREAMing socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(ADDRESS)
# make s a server socket
s.listen(5)

# start processing connections
while True:
    client, addr = s.accept()
    print("New connection No. " + str(counter))
    threading.Thread(target=readSock, args=(client, counter)).start()
    counter += 1

