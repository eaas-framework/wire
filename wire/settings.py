# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# By Fabian Ullrich <fabian@artefaxen.de>

import os
import select
import ConfigParser
import threading
from Queue import Queue
from collections import defaultdict
from collections import OrderedDict
import datetime
import connection

def init(path):
	# Init datatypes
    global log
    # Dict in format: {port: socket}
    global connectionlist
    connectionlist = dict()
    # Dict in format: {socket: {protocol: sth, port: sthelse}}
    global socketlist
    socketlist = dict(dict())
    # Determining the max amount of bytes to read from a buffer at once.
    global maxpacketsize
    maxpacketsize = 65535
    # Queue for managing multiple packages at once.
    global queue
    queue = Queue()

    global l34srcdstmap
    l34srcdstmap = dict()
    # Read-in config.
    global config
    config = ConfigParser.ConfigParser()
    config.read(path)
    # The filterlist is an array of lists, 0 -> IP rules 1 -> Port rules.
    # List containing all filterered IPs
    global ipfilter
    ipfilter = config.get('Filter', 'ip').splitlines()
    global portfilter
    portfilter = defaultdict(list)
    # Extract ports for each IP
    for ipport in ipfilter:
        if ":" in ipport:
            portfilter[str(ipport[:ipport.index(":")])].append(
                str(ipport[ipport.index(":") + 1:]))
    # Cleaning the ports from the filterlist.
    ipfilter = [x[:x.index(":")] if ":" in x else x for x in ipfilter]
    # Deleting duplicates.
    ipfilter = list(OrderedDict.fromkeys(ipfilter))
    # Mode 0 -> L3/4, Mode 1 -> L7
    global mode
    mode = config.getint('Mode', 'mode')
    # The IP which will be forged in mode 0.
    if mode == 0:
        global newTargetIp
        newTargetIp = config.get('Filter', 'targetip')
    # Get the verbosity for logging.
    global verbosity
    verbosity = config.getint('Log', 'verbosity')
    global logfile
    logfile = open(config.get('Log', 'path'), 'w')
    logfile.write("Logfile created: " + str(datetime.datetime.now()) + "\n")
    logfile.write("Starting in Mode " + str(mode) + "\n")
    logfile.write("Verbosity level set to " + str(verbosity) + "\n")
    # Printing the filterules to logfile:
    if verbosity:
        logfile.write("Active ip-filters:\n")
        for ip in ipfilter:
            logfile.write(str(ip) + "\n")
        logfile.write("Active port-filters:\n")
        for ip in portfilter:
            logfile.write(str(ip) + "\n")
            for port in portfilter[ip]:
                logfile.write(str(port) + "\n")

    # This is the sending queue, which will be processed by the sendingRoutine.
    global sendingQueue
    sendingQueue = Queue()

    global reSendingQueue
    reSendingQueue = Queue()
    # The receivingQueue is filled by the receivingRoutine.
    # It holds the packets which will be managed next.
    global receivingQueue
    receivingQueue = Queue()

    # This list holds all connections, which should get deleted next.
    global deletionList
    deletionList = []

    # Queue holding information of hosts which shall be sent a FIN.
    global finQueue
    finQueue = QueuePeek()
    # The time before a non-acknowledged packet gets retransmitted.
    global retranstime
    retranstime = datetime.timedelta(seconds=2)
    # The time how long a TCP-connection stays open after a FIN
    # was received.
    global finTime
    finTime = datetime.timedelta(seconds=2)
    # Maximum UDP data size for one packet.
    # 512 Bytes is the guaranteed supported size on the WWW. 
    # If you know more about the environment, feel free to change this value.
    global udpsize
    udpsize = 512
   

    # This is the retranmissionQueue lock.
    global lock
    lock = threading.Lock()




class QueuePeek(Queue):
    """A PriorityQueue with the additional peek() option."""

    def peek(self):
        """Returning the element with highest priority without
        popping it."""
        return self.queue[0]

