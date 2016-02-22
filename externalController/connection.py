from Queue import Queue
import threading

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
        if con.inputQueue.not_empty:
            data = con.inputQueue.get()
            print(con.number, data)
            con.outputQueue.put(data)
        if con.remove and con.inputQueue.empty():
            print "Removing parsing routine for" + con.number
            return

def sendSock(con):
    """Function sending data back to the socket."""
    while True:
        print "SendSock"
        if con.outputQueue.not_empty:
            con.sock.send(con.outputQueue.get())
        if con.remove and con.outputQueue.empty():
            print "Removing sending routine for" + con.number
            return
        if con.remove:
            print "Apparently, only remove is set."



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
        print "Conneciton status:"
        print "InputQueue: " + str(self.inputQueue)
        print "OutputQueue: " + str(self.outputQueue)
        self.remove = True
        Connection.CONNECTIONS.remove(self)
    
