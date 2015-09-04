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
import sys
import select
import datetime
import socket
import ConfigParser
import priority_dict
import threading
from collections import defaultdict
from Queue import Queue
from struct import pack, unpack
from impacket import ImpactDecoder, ImpactPacket
from collections import OrderedDict


def main(path):
    """The main function of the program.
    Mode 0 means Layer 3/4
    Mode 1 means Layer 7"""
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

    # Set IN/OUT for further operations.
    stdin = os.fdopen(0, 'rb')
    stdout = os.fdopen(1, 'wb')
    alt_stdin = os.fdopen(int(os.getenv("ALTERNATE_STDIN")), 'rb')
    alt_stdout = os.fdopen(int(os.getenv("ALTERNATE_STDOUT")), 'wb')
    # Give Connection the output inforation
    Connection.stdout = stdout
    Connection.alt_stdout = alt_stdout

    # Register inputs in poller for handling the channels.
    global poller
    poller = select.poll()
    poller.register(stdin, select.POLLIN | select.POLLHUP)
    poller.register(alt_stdin, select.POLLIN | select.POLLHUP)
    # give the Connection class access to the poller and the socket information
    Connection.poller = poller
    if mode == 1:
        Connection.sockinfo = (config.get('Socket', 'path'))

    # All calls to inout_map except 0 or 3 give 'special', which means we got
    # socket data.
    global inout_map
    inout_map = {0: alt_stdout, 3: stdout}
    inout_map = defaultdict(lambda: 'special', inout_map)

    # This is the retranmissionQueue lock.
    global lock
    lock = threading.Lock()
    # Start the sending routine.
    t1 = threading.Thread(target=sendingRoutine)
    t1.daemon = True
    t1.start()
    # Start the receiving routine.
    t2 = threading.Thread(target=receivingRoutine, args=(poller,))
    t2.daemon = True
    t2.start()
    # Start of main routine:
    while 1:
        filedescriptor, readdata = receivingQueue.get()
        if mode == 0:
            out = inout_map[filedescriptor]
            if filedescriptor == 0:
                filterpacket, status = tcpipfilter_out(readdata)
            elif filedescriptor == 3:
                filterpacket, status = tcpipfilter_in(readdata)
            else:
                raise ValueError("Unkown filedescriptor for filter.")
            if status:
                out.write(filterpacket)
                out.flush()
            logfile.flush()
        elif mode == 1:
            out = inout_map[filedescriptor]
            if filedescriptor == 0 or filedescriptor == 3:
                ethpacket = decode(readdata)
                if filedescriptor == 0:
                    if l34protocolfilter(ethpacket):
                        if l34filter(ethpacket) == 1:
                            # If we have a match on layer34,
                            # proceed with layer 4 management
                            status, con = l4manage(ethpacket,
                                                   filedescriptor)
                            if status == 2:
                                send(Connection.SOCK, con,
                                     getdata(ethpacket), 0)
                                # con.sock.send(getdata(ethpacket))
                            elif status == 1:
                                send(Connection.TAIL, None,
                                     readdata, 0)
                            # Drop packet
                            else:
                                pass
                        else:
                            # Send data to the other end of the wire.
                            send(Connection.TAIL, None, readdata, 0)
                    else:
                        # Send data to the other end of the wire.
                        send(Connection.TAIL, None, readdata, 0)
                # filedescriptor == 3
                else:
                    if l34protocolfilter(ethpacket):
                        if l34filter(ethpacket, 1):
                            status, con = l4manage(ethpacket,
                                                   filedescriptor)
                            # This is the way back,
                            # here we do not send to sock but need to
                            # make sure the correct seq and ack numbers
                            # are set in the packet we foreward.
                            if status == 2:
                                packet = con.makevalid(ethpacket)
                                packet = encode(packet)
                                send(Connection.HEAD, con, packet)
                            elif status == 1:
                                send(Connection.HEAD, con, packet, 0)
                            # Drop packet
                            else:
                                pass
                        else:
                            # Send data to the machine at the head
                            # of the wire.
                            send(Connection.HEAD, None, readdata, 0)
                    else:
                        # Send data to the machine at the head
                        # of the wire.
                        send(Connection.HEAD, None, readdata, 0)
            else:
                if verbosity:
                    logfile.write("Socketdata processed!\n")
                con = Connection.resolvefd(filedescriptor)
                l7manage(readdata, con)
        else:
            raise ValueError("Unknown mode.")
        logfile.flush()


def tcpretransmit():
    """This logic checks for overdue packets in the retransmission queues.
    If they are remaining in the queue for more than 1 Second,
    retransmit them ONCE. Since we aer using a virtual network nothing should
    get lost. The one time retransmission is some kind of failsafe, and can be
    redisigned for normal TCP retransmission behaviour if needed later."""
    for con in Connection.connectionlist.values():
        lock.acquire()
        hq = con.head.retransqueue
        if hq:
            while (time() - hq[hq.smallest()][0]) > retranstime:
                if verbosity or not verbosity:
                    logfile.write("Head: Retransmission of ACKNr: "
                                     + str(hq.smallest()) + "\n")
                send(Connection.HEAD, con, hq[hq.smallest()][1], 0)
                hq.pop_smallest()
                if not hq:
                    break
        tq = con.tail.retransqueue
        if tq:
            while (time() - tq[tq.smallest()][0]) > retranstime:
                if verbosity or not verbosity:
                    logfile.write("Tail: Retransmission of ACKNr: "
                                     + str(tq.smallest()) + "\n")
                send(Connection.TAIL, con, tq[tq.smallest()][1], 0)
                tq.pop_smallest()
                if not tq:
                    break
        lock.release()


def receivingRoutine(poller):
    """This function will be threaded and will receive packets from the FDs all
    the time. It will do some simple processing:
    If the header tells us, the packet is not interesting, it will get
    forwarded immediately.
    If it is a simple ACK packet without data, it will get processed
    immediately, too. This should make sure we get a healthy TCP-retransmission
    behaviour."""
    global receivingQueue
    global queue
    while True:
        scheduledEvents()
        # If no packets are in the queue get new ones.
        if queue.empty():
            events = poller.poll(200)
        else:
            # Grab data from queue and generate an event.
            queuedata = queue.get()
            events = [(queuedata[1], 1337)]
        for filedescriptor, event in events:
            if event & (select.POLLIN | 1337):
                # Check if event originates from socket or one of the STDs.
                if filedescriptor == 0 or filedescriptor == 3:
                    if event == select.POLLIN:
                        readdata = os.read(filedescriptor, maxpacketsize)
                        # Check if we have one or more packets.
                        packetcountvde(readdata, filedescriptor)
                    # Else its a queue generated event.
                    elif event == 1337:
                        readdata = queuedata[0]
                    elif event == select.POLLNVAL:
                        logfile.write("Invalid POLL! Exiting...\n")
                        os._exit(0)
                    else:
                        logfile.write(str(event))
                        os._exit(0)
                # Socketdata
                else:
                    if verbosity:
                            logfile.write("Socketdata received!\n")
                    # If event is POLLIN get new data from socket.
                    if event == select.POLLIN:
                        con = Connection.fdtocon[filedescriptor]
                        readdata = con.sock.recv(maxpacketsize)
                        # Socketdata will not get pre-filtered.
                        receivingQueue.put((filedescriptor, readdata))
                        continue
                    # Else its a queue generated event.
                    elif event == 1337:
                        raise Exception("Split packets should not occur "
                                        + "on socket entry.")
                # In mode 0, we simply add the readdata to the recvQueue.
                # We do not need to do any pre processing.
                if mode == 0:
                    receivingQueue.put((filedescriptor, readdata))
                # In mode 1 we do some pre-processing.
                else:
                    if prefilter(filedescriptor, readdata):
                        receivingQueue.put((filedescriptor, readdata))
        tcpretransmit()
        logfile.flush()


def sendingRoutine():
    """This function will be threaded and will send all packets in the
    sendqueue. When sending a packets, it gets added to the retransmission
    queue of the corresponding connection."""
    global sendingQueue
    global reSendingQueue
    while True:
        if not reSendingQueue.empty():
            packet = reSendingQueue.get()
            target = "sock"
        else:
            target, con, packet, enqueue, acknr = sendingQueue.get()
        if target == Connection.HEAD or target == Connection.TAIL:
            if target == Connection.HEAD:
                out = Connection.stdout
            else:
                out = Connection.alt_stdout
            if enqueue:
                con.tcpenqueue(target, packet, acknr)
            out.write(packet)
            out.flush()
        # Socket
        else:
            try:
                con.sock.send(packet)
            except socket.error:
                reSendingQueue.put(packet)
        logfile.flush()


def time():
    """Return the actual time."""
    return datetime.datetime.now()


def scheduledEvents():
    """Function managing scheduled events, like deleting connections
    and sending FIN flags."""
    # Delete old connections.
    for con in deletionList:
        Connection.remove(con)
    # Send scheduled FIN
    if not finQueue.empty():
        while (time() - finQueue.peek()[0]) > finTime:
            curtime, con, target = finQueue.get()
            if verbosity or not verbosity:
                logfile.write("Sending FIN: "
                                 + str(con.source) + "\n")
            con.sendfin(target, 0)
            if target == Connection.HEAD:
                con.head.status = Host.STATUS_CLOSE_WAIT
            else:
                con.tail.status = Host.STATUS_CLOSE_WAIT
            if finQueue.empty():
                break


def send(target, con, packet, enqueue=1):
    """Puts packets in the sendingQueue in a proper format."""
    global sendingQueue
    if enqueue:
        if target == Connection.HEAD:
            acknr = con.head.acknr()
        else:
            acknr = con.tail.acknr()
    else:
        acknr = 0
    sendingQueue.put((target, con, packet, enqueue, acknr))


def prefilter(filedescriptor, readdata):
    """Function taking a quick look at incoming packets. All ACK packets will
    get processed immediately. The rest will get queued as usual."""
    if not (filedescriptor == 0 or filedescriptor == 3):
        return 1
    ethpacket = decode(readdata)
    if l34protocolfilter(ethpacket):
        iphead = ethpacket.child()
        tcphead = iphead.child()
        flags = tcphead.get_th_flags()
        if filedescriptor == 0:
            reverse = 0
            source = Connection.HEAD
            target = Connection.TAIL
            con = Connection.resolvesrc(tcphead.get_th_sport())
        # filedescriptor == 3
        else:
            reverse = 1
            source = Connection.TAIL
            target = Connection.HEAD
            con = Connection.resolvesrc(tcphead.get_th_dport())
        # If the connection is unkown yet, enqueue the packet.
        if not con:
            return 1
        # Get the host information.
        if source == Connection.HEAD:
            shost = con.head
        else:
            shost = con.tail

        # TCP SeqNr Control
        seqnrstatus = con.validate(source, tcphead.get_th_seq())
        # If we have a valid seqnr, the packet will get processed.
        if seqnrstatus == 0:
            pass
        # React to keepalive. Do not enqueue.
        elif seqnrstatus == 1:
            if verbosity:
                logfile.write("Ack: " + str(tcphead.get_th_ack()) + "\n")
            if verbosity > 9:
                logfile.write(str(ethpacket) + "\n")
            con.sendack(source, 0, 1)
            return 0
        # Invalid packets do not get analysed at all.
        else:
            return 0

        # If we received data, the expected seqnr need to be counter up.
        datalength = tcphead.child().get_size()
        shost.seqnr(datalength)
        # We only need to take  further action, if we have an ACK packet
        # without data. Everything else gets enqueued as usual.
        if flags == 16 and len(str(tcphead.child())) == 0:
            # We now know we have an ACK for a known connection.
            # Check the host-state now and take according action. The packet
            # will not get enqueued since we process it here.
            if shost.status == Host.STATUS_FIN_WAIT2:
                shost.status = Host.STATUS_CLOSED
                con.ack(source, tcphead.get_th_ack())
                if verbosity:
                    logfile.write("Received last ACK.\n")
                    logfile.write("Seq: "
                                     + str(tcphead.get_th_seq()) + "\n")
                    logfile.write("Ack: "
                                     + str(tcphead.get_th_ack()) + "\n")
                    logfile.write("Connection status:\n")
                    logfile.write("Head: " + str(con.head.status) + "\n")
                    logfile.write("Tail: " + str(con.tail.status) + "\n")
                return 0
            # Host is active.
            else:
                if verbosity:
                    logfile.write("ACK received: \n")
                    logfile.write("Seq: " + str(tcphead.get_th_seq()) + "\n")
                con.ack(source, tcphead.get_th_ack())
                if verbosity > 9:
                    logfile.write(str(ethpacket) + "\n")
                return 0
    return 1


def getdata(ethhead):
    """Function getting the payload (l7 data) from a ImpactPacket.Ethernet
    packet."""
    # logfile.write("getdata: " + str(ethhead.child().child().child()) + '\n')
    return ethhead.child().child().child().get_packet()


def decode(packet):
    """Function decoding a VDE packet to ImpactPacket.Ethernet"""
    # Decode the packet for easy header inspection. The first two bytes get cut
    # they hold the VDE-length information.
    ethhead = ImpactDecoder.EthDecoder().decode(packet[2:])
    return ethhead


def encode(ethhead):
    """Function encoding a ImpacetPacket.Ethernet packet to vde-padded ethernet
    sendable format"""
    return vdepad(cksum(ethhead))


def l34protocolfilter(ethpacket):
    """Funtion returning 1 if packet has TCP content, else 0.
    """
    ethhead = ethpacket
    iphead = ethhead.child()
    # Identify IP packets:
    if iphead.ethertype == ImpactPacket.IP.ethertype:
        tcpudphead = iphead.child()
        # Only check TCP
        if tcpudphead.protocol == ImpactPacket.TCP.protocol:
            return 1
    return 0


def l34filter(ethpacket, reverse=0):
    """Function calculating filterhits on outgoing TCP packets.
    (Layer 7 mode)."""
    ethhead = ethpacket
    iphead = ethhead.child()
    tcpudphead = iphead.child()
    if not reverse:
        packetip = iphead.get_ip_dst()
        port = str(tcpudphead.get_th_dport())
    else:
        packetip = iphead.get_ip_src()
        port = str(tcpudphead.get_th_sport())
    if not packetip in ipfilter:
        if verbosity > 9:
            logfile.write("No IP match. \n")
        return 0
    else:
        # If no port rules apply, all packetip hits are filtered.
        if not portfilter[packetip]:
            if verbosity > 9:
                logfile.write("IP match. \n")
            return 1
        # Test for Port-dest hits on TCP.
        elif port in portfilter[packetip]:
            if verbosity > 9:
                logfile.write("Port match. \n")
            return 1
        else:
            if verbosity > 9:
                logfile.write("Ip match, No Port match. \n")
            return 0


def getconinfo(packet):
    """Function parsing data for opening a new connection. Return values are
    source = (mac, ip, port), dest = (mac, ip, port), seq = sequence number"""
    ethhead = packet
    iphead = ethhead.child()
    tcpudphead = iphead.child()
    sourceip = iphead.get_ip_src()
    dstip = iphead.get_ip_dst()
    sourcemac = ethhead.get_ether_shost()
    dstmac = ethhead.get_ether_dhost()
    dstport = tcpudphead.get_th_dport()
    sourceport = tcpudphead.get_th_sport()
    seq = tcpudphead.get_th_seq()

    return ((sourcemac, sourceip, sourceport), (dstmac, dstip, dstport), seq)


def l4manage(ethhead, filedescriptor):
    """Function checking the TCP information in a packet, retrieving the
    corresponding tcp connection and taking care of tcp commands.
    filedescriptor is needed to determine the direction of the data.
    Return values: 0-> Drop packet. 1-> Send data to stdout/alt_stdout,
    2-> Send data to sockpreet. Second value is a decoded ethheader with all
    layers as children. Third value is the connection for the packet.
    """
    if verbosity:
        logfile.write("\n")
    iphead = ethhead.child()
    # Unpack to layer 7. WARNING: If there are more or less than 3 layers
    # above the data this will crash!
    tcphead = iphead.child()
    flags = tcphead.get_th_flags()
    if filedescriptor == 0:
        reverse = 0
        source = Connection.HEAD
        target = Connection.TAIL
        # Get the corresponding connection, if there exists none yet, create it
        con = Connection.resolvesrc(tcphead.get_th_sport())
        # Check for seq- consistency
        # if (tcphead.get_th_seq != )
    # filedescriptor == 3
    else:
        reverse = 1
        source = Connection.TAIL
        target = Connection.HEAD
        con = Connection.resolvesrc(tcphead.get_th_dport())
    if not con:
        if verbosity:
            logfile.write("New Connection! SPort: " +
                             str(tcphead.get_th_sport()) + "\n")
            logfile.write("Flags: " + str(tcphead.get_th_flags()) + "\n")
        con = Connection(ethhead, reverse)
        # Check if we have a sane connection creation. If this is the first
        # packet of the connection it MUST be a SYN packet.
        if not tcphead.get_SYN():
            # Send RST command.
            send(source, None, vdepad(cksum(con.reset(source))), 0)
            logfile.write("Bad connection, removing!\n")
            deletionList.append(con)
            return 0, con
        # If it is a SYN, give connection the information and forward to fd.
        con.syn(source, tcphead.get_th_seq(), tcphead.get_th_win())
        con.sendSYN(target, ethhead)
        if verbosity > 9:
            logfile.write(str(ethhead) + "\n")
        # Acknowledge the packet.
        # con.sendack(source, 1)
        return 0, con

    # Now where we have a connection, get the host information.
    if source == Connection.HEAD:
        shost = con.head
    else:
        shost = con.tail

    # If SYN and ACK are set, we are at step 2 of the 3 way handshake.
    # Give connection the information and forward to fd.
    if tcphead.get_SYN() and tcphead.get_ACK():
        if verbosity:
            logfile.write("SYNACK found! \n")
            logfile.write("Seq: " + str(tcphead.get_th_seq()) + "\n")
            logfile.write("Ack: " + str(tcphead.get_th_ack()) + "\n")
        con.syn(source, tcphead.get_th_seq(), tcphead.get_th_win())
        con.ack(source, tcphead.get_th_ack())
        # Acknowledge the packet.
        con.sendack(source, 0)
        con.sendSYN(target, ethhead)
        if verbosity > 9:
            logfile.write(str(ethhead) + "\n")
        # Ignore if data is sent with the packet.
        return 0, con

    # Check for commands and take the according action.
    # If there is data sent with the packet, forward it to the socket.
    # TODO: __str__ of headers is very expensive.
    datalen = len(str(tcphead.child()))
    if datalen > 0:
        data = tcphead.child()
    else:
        data = None

    # If FIN and ACK are set, tell the connection to init the finish procedure.
    if tcphead.get_FIN() and tcphead.get_ACK():
        if not data:
            if verbosity:
                logfile.write("FIN/ACK received!\n")
                logfile.write("Seq: " + str(tcphead.get_th_seq()) + "\n")
                logfile.write("Ack: " + str(tcphead.get_th_ack()) + "\n")
            con.ack(source, tcphead.get_th_ack())
            con.fin(source)
        # If data exists in the FIN/ACK package, process it before closing.
        elif data and target == Connection.HEAD:
            tcphead.reset_FIN()
            new_packet = con.makevalid(ethhead)
            new_packet = cksum(new_packet)
            new_packet = encode(new_packet)
            send(target, con, new_packet)
            con.fin(source, datalen)
        elif data and target == Connection.TAIL:
            send(Connection.SOCK, con, getdata(ethhead), 0)
            con.fin(source, datalen)
        else:
            raise ValueError("Faulty FIN procedure.")
        return 0, con

    # If we get a RST/ACK or RST packet,
    # drop the connection and tell the other end.
    elif flags == 20 or flags == 4:
        if verbosity:
            logfile.write("RST Flag set!")
            logfile.write("Seq: " + str(tcphead.get_th_seq()) + "\n")
            if flags == 20:
                logfile.write("Ack: " + str(tcphead.get_th_ack()) + "\n")
        # Send RST command.
        send(target, None, vdepad(cksum(con.reset(target))), 0)
        # Remove connection.
        # Connection.remove(con)
        return 0, con

    # If ACK flag is set from an active host, give the connection
    # the information.
    elif flags == 16 or flags == 24:
        if verbosity:
            logfile.write("ACK received: \n")
            logfile.write("Seq: " + str(tcphead.get_th_seq()) + "\n")
        con.ack(source, tcphead.get_th_ack())
        if verbosity > 9:
            logfile.write(str(ethhead) + "\n")
        # ACKs without data will not get acknowledged!
        if not data:
            return 0, con
    # Check for FIN flag, if set, tell the connection.
    elif tcphead.get_FIN():
        con.fin(source)
        if verbosity:
            logfile.write("Connection closed with FIN. SPort: "
                             + str(con.source[2]) + "\n")
    if data:
        if verbosity:
            logfile.write("Data packet received! \n")
            logfile.write("SeqNr: " + str(tcphead.get_th_seq()) + "\n")
            logfile.write("AckNr: " + str(tcphead.get_th_ack()) + "\n")
            if verbosity > 9:
                logfile.write("Packet is:\n"
                                 + vdepad(cksum(ethhead)) + "\n")
        # If data is given, we always need to send an ACK.
        # TODO: get_packet is very expensive
        con.sendack(source, len(data.get_packet()))
        return 2, con
    # If there is no data, do not forward to socket.
    # Acknowledge the control data.
    if verbosity:
        logfile.write("Other control received. \n")
        logfile.write("Flags:" + str(tcphead.get_th_flags()) + '\n')
    con.sendack(source, 1)
    return 0, con


def l7manage(data, con):
    """Function repacking the payload data received from the socket and sending
    it to the TAIL of the connection.
    con is the connection for which we are repacking the data.
    """
    datalength = len(str(data))
    loglength = datalength
    # If the datalength is not bigger than the given MSS
    if not datalength > con.head.mss:
        if verbosity:
            logfile.write("Writing " + str(datalength)
                             + " Bytes to TAIL.\n")
        packet = datapacket(con, data)
        if verbosity == 3:
            logfile.write("Resulting packet:\n" + str(packet) + "\n")
        send(Connection.TAIL, con, packet)
    # The datalength is bigger than the MSS, we need to send multiple packets.
    else:
        if verbosity or not verbosity:
            logfile.write("Multiple packets will be sent. Datalength is: "
                             + str(datalength) + " Bytes to TAIL.\n")
        while datalength > con.head.mss:
            if verbosity:
                logfile.write("Writing a part: " + str(con.head.mss)
                                 + " Bytes to TAIL.\n")
            packet = datapacket(con, data[:con.head.mss])
            data = data[con.head.mss:]
            if verbosity > 9:
                logfile.write("Resulting packet:\n" + str(packet) + "\n")
            send(Connection.TAIL, con, packet)
            datalength -= con.head.mss
        if verbosity:
            logfile.write("Writing last part: " + str(datalength)
                             + " Bytes to TAIL.\n")
            logfile.write(str(loglength) + " Bytes written in total.\n")
        packet = datapacket(con, data)
        if verbosity > 9:
            logfile.write("Resulting packet:\n" + str(packet) + "\n")
        send(Connection.TAIL, con, packet)


def datapacket(con, data):
    """Function returning a datapacket for the given connection with data as
    payload with target con.tail."""
    datalength = len(str(data))
    data = ImpactPacket.Data(data)
    tcp = ImpactPacket.TCP()
    tcp.set_th_dport(con.tail.port)
    tcp.set_th_sport(con.head.port)
    # Set ack to the expected value.
    tcp.set_th_ack(con.tail.expectedAcknr(0))
    # Increment expected seqnr (tail) by number of sent bytes.
    tcp.set_th_seq(con.tail.expectedSeqnr(datalength))
    if verbosity > 1:
        logfile.write("SeqNr: " + str(tcp.get_th_seq()) + "\n")
    tcp.set_ACK()
    tcp.contains(data)
    con.tail.acknr(datalength)
    ethhead = con.packet(Connection.TAIL, tcp)
    packet = vdepad(cksum(ethhead))
    return packet


def cksum(packet):
    """Function setting the cksum for a given decoded packet and returning it.
    """
    ethhead = packet
    iphead = ethhead.child()
    tcpudphead = iphead.child()
    if isinstance(tcpudphead, ImpactPacket.TCP):
        tcpudphead.set_th_sum(0)
        tcpudphead.auto_checksum = 1
    elif isinstance(tcpudphead, ImpactPacket.UDP):
        tcpudphead.set_uh_sum(0)
        tcpudphead.auto_checksum = 1
    iphead.auto_checksum = 1
    ethhead.auto_checksum = 1
    return ethhead.get_packet()


def tcpipfilter_out(packet):
    """Function for filtering outgoing (FD 0 -> 4) traffic with immediate
    IP-destination manipulation."""
    # Store the original packet, for the case where no match occurs
    orgpacket = packet
    # Cut the VDE internal length information
    packet = packet[2:]
    # Decode the packet for easy header inspection.
    decpacket = ImpactDecoder.EthDecoder().decode(packet)
    content = decpacket.child()

    # Identify IP packets:
    if content.ethertype == ImpactPacket.IP.ethertype:
        if verbosity > 9:
            logfile.write("IP packet on TCPIPFILTER_OUT. \n")
        child = content.child()
        dstip = content.get_ip_dst()
        if isinstance(child, ImpactPacket.TCP):
            srcp = child.get_th_sport()
            streamtype = 0
        elif isinstance(child, ImpactPacket.UDP):
            srcp = child.get_uh_sport()
            streamtype = 1
        elif isinstance(child, ImpactPacket.ICMP):
            streamtype = 2
            srcp = content.get_ip_src()
        # Test for IP-dest hits.
        if not dstip in ipfilter:
            if verbosity > 9:
                logfile.write("No filterhit. IP-dest is:" + dstip + "\n")
            return orgpacket, 1
        else:
            # If no port rules apply, all ip hits are filtered.
            if not portfilter[dstip]:
                content.set_ip_dst(newTargetIp)
                if streamtype == 0:
                    child.set_th_sum(0)
                    child.auto_checksum = 1
                elif streamtype == 1:
                    child.set_uh_sum(0)
                    child.auto_checksum = 1
                elif streamtype == 2:
                    pass
                else:
                    return orgpacket, 1
            # Test for Port-dest hits on TCP.
            elif streamtype == 0:
                if str(child.get_th_dport()) in portfilter[dstip]:
                    content.set_ip_dst(newTargetIp)
                    child.set_th_sum(0)
                    child.auto_checksum = 1
                    if verbosity:
                        logfile.write("Hit on port: " + str(child.get_th_dport()) +'\n')
                # Port not filtered -> drop
                else:
                    if verbosity:
                        logfile.write("Port not in filterlist, dropping...")
                    return orgpacket, 0

            # Test for Port-dest hits on UDP.
            elif streamtype == 1:
                if str(child.get_uh_dport()) in portfilter[dstip]:
                    content.set_ip_dst(newTargetIp)
                    child.set_uh_sum(0)
                    child.auto_checksum = 1
                # Port not filtered -> drop
                else:
                    return orgpacket, 0
            # Drop ICMP, since it has no port target.
            elif streamtype == 2:
                return orgpacket, 0
            else:
                return orgpacket, 1
        content.auto_checksum = 1
        packet = decpacket.get_packet()
        packet = vdepad(packet)
        l34srcdstmap[srcp] = dstip
        return packet, 1

    # Identify ARP packets:
    elif content.ethertype == ImpactPacket.ARP.ethertype:
        if verbosity > 9:
            logfile.write("ARP on TCPIPFILTER_OUT. \n")
        targetip = str(content.as_pro(content.get_ar_tpa()))
        # Test for IP-dest hits.
        if not targetip in ipfilter:            
            return orgpacket, 1
        else:
            if verbosity:
                logfile.write("Filtered ARP request. Redirecting...\n")
            content.set_ar_tpa(map(int, newTargetIp.split('.')))
            packet = decpacket.get_packet()
            packet = vdepad(packet)
            return packet, 1

    # This case should not happen to often, there are not many packets
    # which are neither ARP nor IP.
    else:
        return orgpacket, 1


def tcpipfilter_in(packet):
    """Function filtering incoming traffic (FD: 3 -> 1) with immediate IP-src
    manipulation."""
    # Store the original packet, for the case where no match occurs
    orgpacket = packet
    # Cut the VDE internal length information
    packet = packet[2:]
    # Decode the packet for easy header inspection.
    decpacket = ImpactDecoder.EthDecoder().decode(packet)
    content = decpacket.child()

    # Identify IP packets:
    if content.ethertype == ImpactPacket.IP.ethertype:
        child = content.child()
        # Test for IP-dest hits.
        if not content.get_ip_src() == newTargetIp:
            return orgpacket, 1
        else:
            if isinstance(child, ImpactPacket.TCP):
                content.set_ip_src(l34srcdstmap[child.get_th_dport()])
                child.set_th_sum(0)
                child.auto_checksum = 1
            elif isinstance(child, ImpactPacket.UDP):
                content.set_ip_src(l34srcdstmap[child.get_uh_dport()])
                child.set_uh_sum(0)
                child.auto_checksum = 1                        
        content.auto_checksum = 1
        packet = decpacket.get_packet()
        packet = vdepad(packet)
        return packet, 1
    # Identify ARP packets:
    elif content.ethertype == ImpactPacket.ARP.ethertype:
        sourceip = str(content.as_pro(content.get_ar_spa()))
        # Test for IP-dest hits.
        if not sourceip == newTargetIp or content.get_ar_op() != 2:
            return orgpacket, 1
        else:
            if verbosity:
                logfile.write("ARP packet from targetip fetched. ARP poisoning..\n")
            for filterip in ipfilter:
                content.set_ar_spa(map(int, filterip.split(".")))
                packet = decpacket.get_packet()
                packet = vdepad(packet)
                Connection.stdout.write(packet)
                Connection.stdout.flush()
            return orgpacket, 1
    # This case should not happen to often, there are not many packets
    # which are neither ARP nor IP.
    else:
        return orgpacket, 1


def vdepad(packet):
    """Funtion computing the right vde padding and adding it to the packet.
    Return value is the packet with leading vde length information."""
    lengthb = pack('H', len(packet))
    lengthb = lengthb[1] + lengthb[0]
    packet = '%s%s' % (lengthb, packet)

    return packet


def packetcountvde(readdata, fd):
    """Function to determine the number of packets in a bunch of readdata from
    the VDE-plugs and manage any packets that exceed the first packet."""
    if (unpack("H", '%s%s' % (readdata[1], readdata[0]))[0]
       == len(readdata[2:])):

        return
    else:
        # Cut the first packet, it will be transmitted regulary.
        readdata = readdata[2 + unpack("H", '%s%s' %
                                       (readdata[1], readdata[0]))[0]:]
        # Add all remaining packets to the queue
        while readdata:
            # Exactly one packet left in the buffer.
            if (unpack("H", '%s%s' % (readdata[1], readdata[0]))[0]
               == len(readdata[2:])):
                queue.put((readdata, fd))
                return
            # More than one packet left in the buffer.
            elif (unpack("H", '%s%s' % (readdata[1], readdata[0]))[0]
                  < len(readdata[2:])):
                queue.put((readdata[:2 + unpack("H", '%s%s' %
                          (readdata[1], readdata[0]))[0]], fd))
                readdata = readdata[2 + unpack("H", '%s%s' %
                                               (readdata[1], readdata[0]))[0]:]
            # Less than one packet left, this seems to be a split packet.
            # Gets dropped ATM, should be okay. If we reach this state, there
            # are some more serious problems than split packets on the buffer.
            else:
                logfile.write("Split packet! Dropping...\n")
                return



class Connection():
    """Each object is a connection with a socket, ip, port and protocol
    information. If it is a TCPConnection, we build a complete TCP stack.
    Everything reveived on std_in will get acked immediately, processed and
    afterwards sent to alt_stdout. The other way round it works the same.
    """
    connectionlist = dict()
    sockinfo = tuple()
    poller = None
    fdtocon = dict()
    TAIL = "tail"
    HEAD = "head"
    SOCK = "sock"
    stdout = None
    alt_stdout = None

    def __init__(self, packet, reverse=0):
        """packet is the packet from which the connection should be built.
        the reverse flag indicates, if the direction is head->tail(0) or
        tail->head(1)"""
        if not reverse:
            source, dest, seqhead = getconinfo(packet)
            seqtail = 0
        else:
            dest, source, seqtail = getconinfo(packet)
            seqhead = 0
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(Connection.sockinfo)
        sock.setblocking(0)
        self.sock = sock
        sock.fileno()
        self.head = Host(source, seqhead, seqtail)
        self.tail = Host(dest, seqtail, seqhead)
        self.source = source
        if verbosity:
            logfile.write("Seqtail: " + str(seqtail)
                             + " Seqhead: " + str(seqhead) + '\n')
            logfile.write("Source: " + str(source) + " Target: "
                          + str(dest) + "\n")
        Connection.poller.register(sock, select.POLLIN | select.POLLHUP)
        Connection.connectionlist[source[2]] = self
        Connection.fdtocon[sock.fileno()] = self

    @staticmethod
    def resolvesrc(source):
        """Function returning the corresponding connection for a source.
        If there is not existing one yet, return None.
        """
        if source in Connection.connectionlist:
            return Connection.connectionlist[source]
        else:
            return None

    @staticmethod
    def resolvefd(filedescriptor):
        """Function returning the correcponding connection to a filedescriptor.
        """
        return Connection.fdtocon[filedescriptor]

    @staticmethod
    def remove(con):
        """Function removing a connection with taking care of the socket and
        poller removal actions."""
        Connection.poller.unregister(con.sock.fileno())
        Connection.fdtocon.pop(con.sock.fileno())
        con.sock.close()
        logfile.write("Closing connection with source "
                         + str(con.source[2]) + "\n")
        deletionList.remove(con)
        Connection.connectionlist.pop(con.source[2])

    def tcpenqueue(self, target, packet, acknr):
        """Method adding the given packet to the retransmission queue of target.
        The ACKnr which will delete the entry is the one which is valid at
        calltime of the method."""
        if target == Connection.HEAD:
            lock.acquire()
            self.head.retransqueue[acknr] = (time(), packet)
            if verbosity:
                logfile.write("Put " + str(acknr)
                                 + " into queue head \n")
                if verbosity > 1:
                    logfile.write("Time: " +
                                     str(self.head.retransqueue
                                         [acknr][0]) + "\n")
                    if verbosity > 9:
                        logfile.write("Packet:\n" + str(packet) + "\n")
            lock.release()
        else:
            lock.acquire()
            self.tail.retransqueue[acknr] = (time(), packet)
            if verbosity:
                logfile.write("Put " + str(acknr)
                                 + " into queue tail \n")
                if verbosity == 2:
                    logfile.write("Time: " +
                                     str(self.tail.retransqueue
                                         [acknr][0]) + "\n")
                    if verbosity > 9:
                        logfile.write("Packet:\n" + str(packet) + "\n")
            lock.release()

    def reset(self, target):
        """Function returning a TCP-RST packet to target.
        """
        tcp = ImpactPacket.TCP()
        if target == Connection.HEAD:
            thost = self.head
            shost = self.tail
        # target == Connection.TAIL
        else:
            thost = self.tail
            shost = self.head
        tcp.set_th_dport(thost.port)
        tcp.set_th_sport(shost.port)
        tcp.set_th_seq(thost.expectedSeqnr())
        tcp.set_th_ack(thost.expectedAcknr())
        tcp.set_RST()
        tcp.set_ACK()
        if verbosity:
            logfile.write("RST packet sent!\n")
            logfile.write("SeqNr: " + str(tcp.get_th_seq()) + "\n")
            logfile.write("AckNr: " + str(tcp.get_th_ack()) + "\n")
        return self.packet(target, tcp)

    def ack(self, source, acknr):
        """Method telling the interal TCP stack, a packet was acknowledged.
        This will remove it from the retransmission queue.
        """
        # Sinc w
        if source == Connection.HEAD:
            host = self.head
        else:
            host = self.tail
        lock.acquire()
        if acknr in host.retransqueue:
            # Every older packet get's ACKed with this one.
            it = host.retransqueue.sorted_iter()
            itemACK = it.next()
            counter = 1
            while itemACK != acknr:
                itemACK = it.next()
                counter += 1
            if verbosity:
                logfile.write("Removing ACK " + str(acknr)
                                     + " and all older from queue. \n")
                logfile.write("A total of " + str(counter)
                              + " are ACKed.\n")

        else:
            if verbosity or not verbosity:
                logfile.write("ACK for unknown packet. ACKNr:"
                                 + str(acknr) + "\n")
        lock.release()

    def syn(self, source, seq, winsize):
        """Method managing received SYN by setting the seqnr for the connection
        """
        if source == Connection.HEAD:
            self.head.seq = seq + 1
            self.head.expectACK = seq + 1
            self.tail.expectSEQ = seq + 1
            self.tail.ack = seq + 1
            self.head.winsize = winsize
            if verbosity == 2:
                logfile.write("winsize head: " + str(winsize) + '\n')
        # source == Connection.TAIL
        else:
            self.tail.seq = seq + 1
            self.tail.expectACK = seq + 1
            self.head.expectSEQ = seq + 1
            self.head.ack = seq + 1
            self.tail.winsize = winsize
            if verbosity == 2:
                logfile.write("winsize tail: " + str(winsize) + '\n')

    def fin(self, source, datalen=0):
        """Method managing received FIN by closing the connection in one
        direction."""
        if source == Connection.HEAD:
            shost = self.head
            thost = self.tail
            target = Connection.TAIL
        else:
            shost = self.tail
            thost = self.head
            target = Connection.HEAD
        # If the sender had status open so far, he was the initiator of FIN.
        if shost.status == Host.STATUS_OPEN:
            self.sendfin(source, 1, datalen)
            shost.status = Host.STATUS_FIN_WAIT2
            # If the other host is open, schedule a finish procedure.
            # When data was included in the package, double the waiting time.
            if thost.status == Host.STATUS_OPEN:
                global finQueue
                if datalen == 0:
                    finQueue.put([time(), self, target])
                else:
                    finQueue.put([time() + finTime, self, target])
        # If the sender was in status CLOSE_WAIT, we initiated the FIN before.
        # He is sending an answer. We simply need to acknowledge it.
        if shost.status == Host.STATUS_CLOSE_WAIT:
            if verbosity:
                logfile.write("Sending last ACK.\n")
            self.sendack(source, 1)
            shost.status = Host.STATUS_CLOSED
            # If both hosts are in status closed, schedule the connection for
            # deletion.
            global deletionList
            if shost.status == thost.status == Host.STATUS_CLOSED:
                deletionList.append(self)
            if verbosity:
                logfile.write("Connection status:\n")
                logfile.write("Head: " + str(self.head.status) + "\n")
                logfile.write("Tail: " + str(self.tail.status) + "\n")

    def sendfin(self, target, answer, datalen=0):
        """Method sending a FIN/ACK to target. If answer is set, this should
        be the answer to a received FIN/ACK. Else this is the initiation of
        the connection closing mechanism."""
        tcp = ImpactPacket.TCP()
        if target == Connection.HEAD:
            thost = self.head
            shost = self.tail
            out = Connection.stdout
        else:
            thost = self.tail
            shost = self.head
            out = Connection.alt_stdout

        tcp.set_th_dport(thost.port)
        tcp.set_th_sport(shost.port)
        tcp.set_th_seq(thost.expectedSeqnr(1))
        if answer:
            tcp.set_th_ack(thost.expectedAcknr(datalen + 1))
            # Increment seqnr.
            thost.seqnr(1)
        else:
            tcp.set_th_ack(thost.expectedAcknr(0))
        tcp.set_th_win(shost.winsize)

        tcp.set_FIN()
        tcp.set_ACK()
        if verbosity:
            logfile.write("FIN/ACK packet sent!\n")
            logfile.write("SeqNr: " + str(tcp.get_th_seq()) + "\n")
            logfile.write("AckNr: " + str(tcp.get_th_ack()) + "\n")
        # Acknr changed, even if there was no data.
        packet = self.packet(target, tcp)
        packet = encode(packet)
        thost.acknr(1)
        send(target, self, packet)

    def sendack(self, target, bytecount, keepalive=0):
        """Function sending an acknowledgement to target. bytes is the number
        of bytes which get acknowledged."""
        tcp = ImpactPacket.TCP()
        if target == Connection.HEAD:
            thost = self.head
            shost = self.tail
            out = Connection.stdout
        else:
            thost = self.tail
            shost = self.head
            out = Connection.alt_stdout

        tcp.set_th_dport(thost.port)
        tcp.set_th_sport(shost.port)
        tcp.set_th_ack(thost.expectedAcknr(bytecount))
        # ACK does not increment seq-nr.
        tcp.set_th_seq(thost.expectedSeqnr(0))
        tcp.set_th_win(thost.winsize)

        tcp.set_ACK()

        packet = self.packet(target, tcp)
        if verbosity:
            logfile.write("ACK sent to " + target + ".\n")
            logfile.write("Seqnr.: " + str(tcp.get_th_seq()) + "\n")
            logfile.write("ACKNr.: " + str(tcp.get_th_ack()) + "\n")
            if verbosity > 9:
                logfile.write(str(packet) + "\n")
        packet = vdepad(cksum(packet))
        send(target, self, packet, 0)


    def sendSYN(self, target, ethhead):
        """Method sending a given SYN packet to target. The SYN packet will be
        changed to not support TCPOPT_TIMESTAMP.
        """
        iphead = ethhead.child()
        tcphead = iphead.child()
        if target == Connection.TAIL:
            out = Connection.alt_stdout
            host = self.head
        # target == Connection.HEAD
        else:
            out = Connection.stdout
            host = self.tail
        nop = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_NOP)
        # If there is a Maximum Segment Size (MSS) give, we need to set it as 
        # the upper threshold for the packet size.
        for option in tcphead.get_options():
            if option.get_kind() == ImpactPacket.TCPOption.TCPOPT_MAXSEG:
                host.mss = option.get_mss()
        # We need to check the availiable options and only delete the 
        # TCP_TIMESTAMP option.
        i = 0
        for option in tcphead.get_options():
            if option.get_kind() == ImpactPacket.TCPOption.TCPOPT_TIMESTAMP:
                # Bad practice, but seems like the only possible way.
                tcphead._TCP__option_list[i] = nop
                break
            i += 1
        # Recalculate the ipheader length
        iphead.set_ip_len(0)
        packet = encode(ethhead)
        send(target, self, packet)

    def packet(self, target, tcppacket):
        """Function forging a packet for connection con. Only L1-3 get created.
        """
        ethhead = ImpactPacket.Ethernet()
        iphead = ImpactPacket.IP()
        if target == Connection.HEAD:
            # Set MACs:
            ethhead.set_ether_shost(self.tail.mac)
            ethhead.set_ether_dhost(self.head.mac)
            # Set IPs
            iphead.set_ip_src(self.tail.ipaddr)
            iphead.set_ip_dst(self.head.ipaddr)
        # target == Connection.TAIL
        else:
            # Set MACs:
            ethhead.set_ether_dhost(self.tail.mac)
            ethhead.set_ether_shost(self.head.mac)
            # Set IPs
            iphead.set_ip_dst(self.tail.ipaddr)
            iphead.set_ip_src(self.head.ipaddr)

        iphead.contains(tcppacket)
        ethhead.contains(iphead)
        return ethhead

    def validate(self, source, seqnr):
        """Method validating received packet. If seqnr is the right (expexted)
        one return 0, if seqnr is the expexted seqnr - 1 return 1 (keepalive)
        else return 2, packet will get dropped since its invalid."""
        if source == Connection.HEAD:
            host = self.head
        else:
            host = self.tail
        if host.seqnr(0) == seqnr:
            return 0
        elif host.seqnr(0) - 1 == seqnr:
            if verbosity:
                logfile.write("Keepalive fetched.\n")
                logfile.write("SeqNr: " + str(seqnr) + "\n")
            return 1
        # If we expect seqnr = 0, this is a new connection.
        # The number is always valid then.
        elif host.seqnr(0) == 0:
            return 0
        else:
            logfile.write("Invalid SEQNR! Dropping...\n")
            logfile.write("Expected: " + str(host.seqnr())
                             + " Got: " + str(seqnr) + "\n")
            return 2

    def makevalid(self, ethhead, target=HEAD):
        """Method making a packet to 'target' a valid TCP packet next in row.
        """
        iphead = ethhead.child()
        tcphead = iphead.child()
        data = tcphead.child()
        if target == Connection.HEAD:
            # Set MACs:
            ethhead.set_ether_shost(self.tail.mac)
            ethhead.set_ether_dhost(self.head.mac)
            # Set IPs
            iphead.set_ip_src(self.tail.ipaddr)
            iphead.set_ip_dst(self.head.ipaddr)
            tcphead.set_th_ack(self.head.expectedAcknr(0))
            tcphead.set_th_seq(self.head.expectedSeqnr(data.get_size()))
            if verbosity:
                logfile.write("Seq: " + str(tcphead.get_th_seq()) + "\n")
            self.head.acknr(data.get_size())
        # target == Connection.TAIL
        else:
            raise NotImplementedError("Makevalid may only be used with HEAD.")
        return ethhead


class Host():

    STATUS_OPEN = 1
    STATUS_CLOSE_WAIT = 2
    STATUS_FIN_WAIT2 = 3
    STATUS_CLOSED = 0

    def __init__(self, information, seq, expSeq):
        self.mac = information[0]
        self.ipaddr = information[1]
        self.port = information[2]
        self.seq = seq
        self.ack = seq
        self.expectACK = seq
        self.expectSEQ = expSeq
        self.retransqueue = priority_dict.priority_dict()
        self.winsize = 0
        self.status = 1
        # This is the default value if there is no specific MSS given.
        self.mss = 512

    # Note: All seqnr operations are modulo 2**32, because the numberspace
    # for sequence numbers is exactly that big and there is a real danger
    # of wrapping here.

    def seqnr(self, bytenr=0):
        """Method returning the actual seqnr of this host.
        Bytenr says how many bytes got sent with the packet, so the number
        can be set to the right amount."""
        self.seq = (self.seq + bytenr) % pow(2, 32)
        return self.seq - bytenr

    def acknr(self, bytenr=0):
        """Method returning the actual seqnr of this host.
        Bytenr says how many bytes were sent last."""
        self.ack = (self.ack + bytenr) % pow(2, 32)
        return self.ack - bytenr

    def expectedSeqnr(self, bytenr=0):
        """Method returning the next expected sequence-number of the host.
        It will we incremented afterwards by the given bytenr."""
        self.expectSEQ = (self.expectSEQ + bytenr) % pow(2, 32)
        return (self.expectSEQ - bytenr) % pow(2, 32)

    def expectedAcknr(self, bytenr=0):
        """Method returning the right expectedAcknr for this side
        of the connection. Bytenr is the amount of received data."""
        self.expectACK = (bytenr + self.expectACK) % pow(2, 32)
        return self.expectACK


class QueuePeek(Queue):
    """A PriorityQueue with the additional peek() option."""

    def peek(self):
        """Returning the element with highest priority without
        popping it."""
        return self.queue[0]


if __name__ == '__main__':
     main(sys.argv[1])
