from Queue import Queue
import threading
import parsing

def readSock(con):
    """Funciton reading data from socket and adding it to the inp. Queue."""
    while True:
        data = con.sock.recv(4096)
        # TODO: Process and manipulate HTTP data.
        if len(data) < 1 or con.remove:
            print "reading socket on " + str(con.number) + " closed"
            con.deletion()
            return
        con.inputQueue.put(data)

def parseRequests(con):
    """Function processing the data in inp. Queue. 
    HTML request are manipulated."""
    while True:
        if not con.inputQueue.empty():
            data = con.inputQueue.get()
            print(con.number, data)
            data = parsing.httpReqMan(data)
            print(con.number, data)
            con.outputQueue.put(data)
        elif con.remove:
            print "Removing parsing routine for" + str(con.number)
            return

def sendSock(con):
    """Function sending data back to the socket."""
    while True:
        if not con.outputQueue.empty():
            con.sock.send(con.outputQueue.get())
        elif con.remove:
            print "Removing sending routine for " + str(con.number)
            return


class Connection(object):
    """Class holding all information about a l7connection."""  
    CONNECTIONS = []

    def __init__(self, sock, address, counter):
        """Contructor."""
        Connection.CONNECTIONS.append(self)
        self.inputQueue = Queue()
        self.outputQueue = Queue()
        self.remove = False
        self.sock = sock
        self.number = counter
        self.address = address
        self.reader = threading.Thread(target=readSock, args=(self,))
        self.parser = threading.Thread(target=parseRequests, args=(self,))
        self.sender = threading.Thread(target=sendSock, args=(self,))
        self.reader.daemon, self.parser.daemon = True, True
        self.sender.daemon = True
        self.reader.start()
        self.parser.start()
        self.sender.start()

    def deletion(self):
        """Function initializing termination of all associated threads."""
        self.remove = True
        Connection.CONNECTIONS.remove(self)

    
