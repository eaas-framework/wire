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
import socket
import threading
from struct import unpack
from impacket import ImpactDecoder, ImpactPacket
from collections import defaultdict

# package Wire.py
from protocol import *
from host import *
from connection import *
import settings as s
from functions import *



def main(path):
    """The main function of the program.
    Mode 0 means Layer 3/4
    Mode 1 means Layer 7"""
    
    s.init(path)

    # Set IN/OUT for further operations.
    stdin = os.fdopen(0, 'rb')
    stdout = os.fdopen(1, 'wb')
    alt_stdin = os.fdopen(int(os.getenv("ALTERNATE_STDIN")), 'rb')
    alt_stdout = os.fdopen(int(os.getenv("ALTERNATE_STDOUT")), 'wb')
    # Give TCPConnection the output information
    TCPConnection.stdout = stdout
    TCPConnection.alt_stdout = alt_stdout
     # All calls to inout_map except 0 or 3 give 'special', which means we got
    # socket data.
    #global inout_map
    inout_map = {0: alt_stdout, 3: stdout}
    inout_map = defaultdict(lambda: 'special', inout_map)
    # Register inputs in poller for handling the channels.
    global poller
    poller = select.poll()
    poller.register(stdin, select.POLLIN | select.POLLHUP)
    poller.register(alt_stdin, select.POLLIN | select.POLLHUP)
    # give the TCPConnection class access to the poller and the socket info
    Connection.poller = poller
    if s.mode == 1:
        Connection.sockinfo = (s.config.get('Socket', 'path'))
    
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
        filedescriptor, readdata = s.receivingQueue.get()
        if s.mode == 0:
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
            s.logfile.flush()
        elif s.mode == 1:
            out = inout_map[filedescriptor]
            if filedescriptor == 0 or filedescriptor == 3:
                ethpacket = decode(readdata)
                ptype = l34protocolfilter(ethpacket)
                if (filedescriptor == 0) and (ptype != Protocol.Other):
                    # Test for filterhits.
                    if l34filter(ethpacket, ptype):
                        # If we have a match on layer34,
                        # proceed with layer 4 management
                        status, con = l4manage(ethpacket,
                                               filedescriptor, ptype)
                        # Send l7 data to external controler via socket.
                        if status == 2:
                            send(Connection.SOCK, con,
                                 getdata(ethpacket), 0)
                            # con.sock.send(getdata(ethpacket))
                        # # Forward data to target.
                        # elif status == 1:
                        #     send(Connection.TAIL, None,
                        #          readdata, 0)
                        # Drop packet
                        else:
                            pass
                    # No filterhit occured.
                    else:
                        # Send data to the other end of the wire.
                        send(Connection.TAIL, None, readdata, 0)
                # ptype == Protocol.Other
                elif (filedescriptor == 0) and (ptype == Protocol.Other):
                    # Send data to the other end of the wire.
                    send(Connection.TAIL, None, readdata, 0)
                # filedescriptor == 3
                elif (filedescriptor == 3) and (ptype == Protocol.TCP):
                    # Test for filterhits.
                    if l34filter(ethpacket, ptype, 1):
                        # Only TCP management is needed here, UDP is not 
                        # monitored on the inward way.
                        status, con = l4TCPmanage(ethpacket,
                                               filedescriptor)
                        # This is the way back,
                        # here we do not send to sock but need to
                        # make sure the correct seq and ack numbers
                        # are set in the packet we foreward.
                        if status == 2:
                            packet = con.makevalid(ethpacket)
                            packet = encode(packet)
                            send(Connection.HEAD, con, packet)
                        # elif status == 1:
                        #     send(Connection.HEAD, con, packet, 0)
                        # Drop packet
                        else:
                            pass
                    # No filterhit occured.
                    else:
                        # Send data to the machine at the head
                        # of the wire.
                        send(Connection.HEAD, None, readdata, 0)
                # filedescriptor == 3 and 
                # ptype == (Protocol.UDP or Protocol.Other)
                # UDP normally should not be faulty on the answers.
                # TODO: maybe UDP causes problems on the inward direction
                else:
                    # Send data to the machine at the head
                    # of the wire.
                    send(Connection.HEAD, None, readdata, 0)
            # Socket data.
            else:
                if s.verbosity:
                    s.logfile.write("Socketdata processed!\n")
                con = Connection.resolvefd(filedescriptor)
                l7manage(readdata, con)
        else:
            raise ValueError("Unknown mode.")
        s.logfile.flush()


def l4manage(ethpacket, filedescriptor, ptype):
    """Managing genereal layer 4 data by invoking the corresponding functions.
    """
    if ptype == Protocol.TCP:
        return l4TCPmanage(ethpacket, filedescriptor)
    elif ptype == Protocol.UDP:
        return l4UDPmanage(ethpacket, filedescriptor)
    # if ptype == Protocol.Other    
    else:
        raise ValueError("Other protocols should get filtered out before.")


def l4UDPmanage(ethhead, filedescriptor):
    """Function managing UDP packets, by resolving the corresponding socket
    connection."""
    iphead = ethhead.child()
    udphead = iphead.child()
    if not filedescriptor == 0:
        raise ValueError("Inward direction not yet implemented.")
    else:
        con = Connection.resolvesrc(udphead.get_uh_sport(), Protocol.UDP)
        if not con:
            if s.verbosity:
                s.logfile.write("New UDPConnection! SPort: " +
                                 str(udphead.get_uh_sport()) + "\n")
            con = UDPConnection(ethhead)
        return 2, con



def l4TCPmanage(ethhead, filedescriptor):
    """Function checking the TCP information in a packet, retrieving the
    corresponding tcp connection and taking care of tcp commands.
    filedescriptor is needed to determine the direction of the data.
    Return values: 0-> Drop packet. 1-> Send data to stdout/alt_stdout,
    2-> Send data to sockpreet. Second value is a decoded ethheader with all
    layers as children. Third value is the connection for the packet.
    """
    if s.verbosity:
        s.logfile.write("\n")
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
        con = Connection.resolvesrc(tcphead.get_th_sport(), Protocol.TCP)
        # Check for seq- consistency
        # if (tcphead.get_th_seq != )
    # filedescriptor == 3
    else:
        reverse = 1
        source = Connection.TAIL
        target = Connection.HEAD
        con = Connection.resolvesrc(tcphead.get_th_dport(), Protocol.TCP)
    if not con:
        if s.verbosity:
            s.logfile.write("New TCPConnection! SPort: " +
                             str(tcphead.get_th_sport()) + "\n")
            s.logfile.write("Flags: " + str(tcphead.get_th_flags()) + "\n")
        con = TCPConnection(ethhead, reverse)
        # Check if we have a sane connection creation. If this is the first
        # packet of the connection it MUST be a SYN packet.
        if not tcphead.get_SYN():
            # Send RST command.
            send(source, None, vdepad(cksum(con.reset(source))), 0)
            s.logfile.write("Bad connection, removing!\n")
            s.deletionList.append(con)
            return 0, con
        # If it is a SYN, give connection the information and forward to fd.
        con.syn(source, tcphead.get_th_seq(), tcphead.get_th_win())
        con.sendSYN(target, ethhead)
        if s.verbosity > 9:
            s.logfile.write(str(ethhead) + "\n")
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
        if s.verbosity:
            s.logfile.write("SYNACK found! \n")
            s.logfile.write("Seq: " + str(tcphead.get_th_seq()) + "\n")
            s.logfile.write("Ack: " + str(tcphead.get_th_ack()) + "\n")
        con.syn(source, tcphead.get_th_seq(), tcphead.get_th_win())
        con.ack(source, tcphead.get_th_ack())
        # Acknowledge the packet.
        con.sendack(source, 0)
        con.sendSYN(target, ethhead)
        if s.verbosity > 9:
            s.logfile.write(str(ethhead) + "\n")
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
            if s.verbosity:
                s.logfile.write("FIN/ACK received!\n")
                s.logfile.write("Seq: " + str(tcphead.get_th_seq()) + "\n")
                s.logfile.write("Ack: " + str(tcphead.get_th_ack()) + "\n")
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
        if s.verbosity:
            s.logfile.write("RST Flag set!")
            s.logfile.write("Seq: " + str(tcphead.get_th_seq()) + "\n")
            if flags == 20:
                s.logfile.write("Ack: " + str(tcphead.get_th_ack()) + "\n")
        # Send RST command.
        send(target, None, vdepad(cksum(con.reset(target))), 0)
        # Remove connection.
        # TCPConnection.remove(con)
        return 0, con

    # If ACK flag is set from an active host, give the connection
    # the information.
    elif flags == 16 or flags == 24:
        if s.verbosity:
            s.logfile.write("ACK received: \n")
            s.logfile.write("Seq: " + str(tcphead.get_th_seq()) + "\n")
        con.ack(source, tcphead.get_th_ack())
        if s.verbosity > 9:
            s.logfile.write(str(ethhead) + "\n")
        # ACKs without data will not get acknowledged!
        if not data:
            return 0, con
    # Check for FIN flag, if set, tell the connection.
    elif tcphead.get_FIN():
        con.fin(source)
        if s.verbosity:
            s.logfile.write("TCPConnection closed with FIN. SPort: "
                             + str(con.source[2]) + "\n")
    if data:
        if s.verbosity:
            s.logfile.write("Data packet received! \n")
            s.logfile.write("SeqNr: " + str(tcphead.get_th_seq()) + "\n")
            s.logfile.write("AckNr: " + str(tcphead.get_th_ack()) + "\n")
            if s.verbosity > 9:
                s.logfile.write("Packet is:\n"
                                 + vdepad(cksum(ethhead)) + "\n")
        # If data is given, we always need to send an ACK.
        # TODO: get_packet is very expensive
        con.sendack(source, len(data.get_packet()))
        return 2, con
    # If there is no data, do not forward to socket.
    # Acknowledge the control data.
    if s.verbosity:
        s.logfile.write("Other control received. \n")
        s.logfile.write("Flags:" + str(tcphead.get_th_flags()) + '\n')
    con.sendack(source, 1)
    return 0, con


def tcpretransmit():
    """This logic checks for overdue packets in the retransmission queues.
    If they are remaining in the queue for more than 1 Second,
    retransmit them ONCE. Since we aer using a virtual network nothing should
    get lost. The one time retransmission is some kind of failsafe, and can be
    redisigned for normal TCP retransmission behaviour if needed later."""
    for con in TCPConnection.connectionlist.values():
        s.lock.acquire()
        hq = con.head.retransqueue
        if hq:
            while (time() - hq[hq.smallest()][0]) > s.retranstime:
                if s.verbosity or not s.verbosity:
                    s.logfile.write("Head: Retransmission of ACKNr: "
                                     + str(hq.smallest()) + "\n")
                send(Connection.HEAD, con, hq[hq.smallest()][1], 0)
                hq.pop_smallest()
                if not hq:
                    break
        tq = con.tail.retransqueue
        if tq:
            while (time() - tq[tq.smallest()][0]) > s.retranstime:
                if s.verbosity or not s.verbosity:
                    s.logfile.write("Tail: Retransmission of ACKNr: "
                                     + str(tq.smallest()) + "\n")
                send(Connection.TAIL, con, tq[tq.smallest()][1], 0)
                tq.pop_smallest()
                if not tq:
                    break
        s.lock.release()


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
        if s.queue.empty():
            events = poller.poll(200)
        else:
            # Grab data from queue and generate an event.
            queuedata = s.queue.get()
            events = [(queuedata[1], 1337)]
        for filedescriptor, event in events:
            if event & (select.POLLIN | 1337):
                # Check if event originates from socket or one of the STDs.
                if filedescriptor == 0 or filedescriptor == 3:
                    if event == select.POLLIN:
                        readdata = os.read(filedescriptor, s.maxpacketsize)
                        # Check if we have one or more packets.
                        packetcountvde(readdata, filedescriptor)
                    # Else its a queue generated event.
                    elif event == 1337:
                        readdata = queuedata[0]
                    elif event == select.POLLNVAL:
                        s.logfile.write("Invalid POLL! Exiting...\n")
                        os._exit(0)
                    else:
                        s.logfile.write(str(event))
                        os._exit(0)
                # Socketdata
                else:
                    if s.verbosity:
                        s.logfile.write("Socketdata received!\n")
                    # If event is POLLIN get new data from socket.
                    if event == select.POLLIN:
                        con = Connection.fdtocon[filedescriptor]
                        readdata = con.sock.recv(s.maxpacketsize)
                        # Socketdata will not get pre-filtered.
                        s.receivingQueue.put((filedescriptor, readdata))
                        continue
                    # Else its a queue generated event.
                    elif event == 1337:
                        raise Exception("Split packets should not occur "
                                        + "on socket entry.")
                # In mode 0, we simply add the readdata to the recvQueue.
                # We do not need to do any pre processing.
                if s.mode == 0:
                    s.receivingQueue.put((filedescriptor, readdata))
                # In mode 1 we do some pre-processing.
                else:
                    if prefilter(filedescriptor, readdata):
                        s.receivingQueue.put((filedescriptor, readdata))
        tcpretransmit()
        s.logfile.flush()


def sendingRoutine():
    """This function will be threaded and will send all packets in the
    sends.queue. When sending a packets, it gets added to the retransmission
    queue of the corresponding connection."""
    global sendingQueue
    global reSendingQueue
    while True:
        if not s.reSendingQueue.empty():
            packet = s.reSendingQueue.get()
            target = "sock"
        else:
            target, con, packet, enqueue, acknr = s.sendingQueue.get()
        if target == Connection.HEAD or target == Connection.TAIL:
            if target == Connection.HEAD:
                out = TCPConnection.stdout
            else:
                out = TCPConnection.alt_stdout
            if enqueue:
                con.tcpenqueue(target, packet, acknr)
            out.write(packet)
            out.flush()
        # Socket
        else:
            try:
                s.logfile.write("Writing " + str(len(packet)) +
                                " Bytes to socket. \n")
                con.sock.send(packet)
            except socket.error:
                s.reSendingQueue.put(packet)
        s.logfile.flush()


def scheduledEvents():
    """Function managing scheduled events, like deleting connections
    and sending FIN flags."""
    # Delete old connections.
    for con in s.deletionList:
        TCPConnection.remove(con)
    # Send scheduled FIN
    if not s.finQueue.empty():
        while (time() - s.finQueue.peek()[0]) > s.finTime:
            curtime, con, target = s.finQueue.get()
            if s.verbosity or not s.verbosity:
                s.logfile.write("Sending FIN: "
                                 + str(con.source) + "\n")
            con.sendfin(target, 0)
            if target == Connection.HEAD:
                con.head.status = TCPHost.STATUS_CLOSE_WAIT
            else:
                con.tail.status = TCPHost.STATUS_CLOSE_WAIT
            if s.finQueue.empty():
                break


def prefilter(filedescriptor, readdata):
    """Function taking a quick look at incoming packets. All ACK packets will
    get processed immediately. The rest will get queued as usual."""
    # Socketdata never is premanaged.
    if not (filedescriptor == 0 or filedescriptor == 3):
        return 1
    ethpacket = decode(readdata)
    # Obtain the protocol type.
    ptype = l34protocolfilter(ethpacket)
    if ptype == Protocol.TCP:
        return preTCP(ethpacket, filedescriptor)
    elif ptype == Protocol.UDP:
        return preUDP(ethpacket, filedescriptor)
    # ptype == Protocol.Other
    else:
        return 1

def preUDP(ethpacket, filedescriptor):
    # no operations needed atm.
    return 1

def preTCP(ethpacket, filedescriptor):
    iphead = ethpacket.child()
    tcphead = iphead.child()
    flags = tcphead.get_th_flags()
    if filedescriptor == 0:
        reverse = 0
        source = Connection.HEAD
        target = Connection.TAIL
        con = Connection.resolvesrc(tcphead.get_th_sport(), Protocol.TCP)
    # filedescriptor == 3
    else:
        reverse = 1
        source = Connection.TAIL
        target = Connection.HEAD
        con = Connection.resolvesrc(tcphead.get_th_dport(), Protocol.TCP)
    # If the connection is unkown yet, enqueue the packet and stop pre-mngmt.
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
    # React to keepalive. Do not ens.queue.
    elif seqnrstatus == 1:
        if s.verbosity:
            s.logfile.write("Ack: " + str(tcphead.get_th_ack()) + "\n")
        if s.verbosity > 9:
            s.logfile.write(str(ethpacket) + "\n")
        con.sendack(source, 0, 1)
        return 0
    # Invalid packets do not get analysed at all.
    else:
        return 0

    # If we received data, the expected seqnr needs to be counter up.
    datalength = tcphead.child().get_size()
    shost.seqnr(datalength)
    # We only need to take  further action, if we have an ACK packet
    # without data. Everything else gets enqueued as usual.
    if flags == 16 and len(str(tcphead.child())) == 0:
        # We now know we have an ACK for a known connection.
        # Check the host-state now and take according action. The packet
        # will not get enqueued since we process it here.
        if shost.status == TCPHost.STATUS_FIN_WAIT2:
            shost.status = TCPHost.STATUS_CLOSED
            con.ack(source, tcphead.get_th_ack())
            if s.verbosity:
                s.logfile.write("Received last ACK.\n")
                s.logfile.write("Seq: "
                                 + str(tcphead.get_th_seq()) + "\n")
                s.logfile.write("Ack: "
                                 + str(tcphead.get_th_ack()) + "\n")
                s.logfile.write("TCPConnection status:\n")
                s.logfile.write("Head: " + str(con.head.status) + "\n")
                s.logfile.write("Tail: " + str(con.tail.status) + "\n")
            return 0
        # TCPHost is active.
        else:
            if s.verbosity:
                s.logfile.write("ACK received: \n")
                s.logfile.write("Seq: " + str(tcphead.get_th_seq()) + "\n")
            con.ack(source, tcphead.get_th_ack())
            if s.verbosity > 9:
                s.logfile.write(str(ethpacket) + "\n")
            return 0
    return 1




def l34filter(ethpacket, ptype, reverse=0):
    """Function calculating filterhits on outgoing packets.
    (Layer 7 mode)."""
    ethhead = ethpacket
    iphead = ethhead.child()
    tcpudphead = iphead.child()
    if not reverse:
        packetip = iphead.get_ip_dst()
        if ptype == Protocol.TCP:
            port = str(tcpudphead.get_th_dport())
        elif ptype == Protocol.UDP:
            port = str(tcpudphead.get_uh_dport())
        # ptype == Protocol.Other
        else:
            raise ValueError("l34filter should never" +
                              " get passed non-TCP/UDP data.")
    else:
        packetip = iphead.get_ip_src()
        if ptype == Protocol.TCP:
            port = str(tcpudphead.get_th_sport())
        elif ptype == Protocol.UDP:
            port = str(tcpudphead.get_uh_sport())
        # ptype == Protocol.Other
        else:
            raise ValueError("l34filter should never" +
                              " get passed non-TCP/UDP data.")
        
    if not packetip in s.ipfilter:
        if s.verbosity > 9:
            s.logfile.write("No IP match. \n")
        return 0
    else:
        # If no port rules apply, all packetip hits are filtered.
        if not s.portfilter[packetip]:
            if s.verbosity > 9:
                s.logfile.write("IP match. \n")
            return 1
        # Test for Port-dest hits on TCP.
        elif port in s.portfilter[packetip]:
            if s.verbosity > 9:
                s.logfile.write("Port match. \n")
            return 1
        else:
            if s.verbosity > 9:
                s.logfile.write("Ip match, No Port match. \n")
            return 0


def l7manage(data, con):
    """Function repacking the payload data received from the socket and sending
    it to the TAIL of the connection.
    con is the connection for which we are repacking the data.
    """
    if s.verbosity > 9:
        s.logfile.write(str(len(data)) + " Bytes from socket. \n")
    if con.type == Protocol.TCP:
        l7TCPmanage(data, con)        
    elif con.type == Protocol.UDP:
        l7UDPmanage(data, con)
    #con.type == Protocol.Other
    else:
        raise ValueError("No socket possible for Protocol.Other.")

def l7UDPmanage(data, con):
    """Managing the UDP part of l7manage."""
    datalength = len(str(data))
    loglength = datalength
    # If the datalenth does not exceed the max UDP length.
    if not datalength > s.udpsize:
        if s.verbosity:
            s.logfile.write("Writing " + str(datalength)
                             + " Bytes to TAIL.\n")
        packet = udppacket(con, data)
        if s.verbosity == 3:
            s.logfile.write("Resulting packet:\n" + str(packet) + "\n")
        send(Connection.TAIL, con, packet, 0)
    # Too much data for one packet, splitting required.
    else:
        if s.verbosity or not s.verbosity:
            s.logfile.write("Multiple packets will be sent. Datalength is: "
                             + str(datalength) + " Bytes to TAIL.\n")
        while datalength > s.udpsize:
            if s.verbosity:
                s.logfile.write("Writing a part: " + str(s.udpsize)
                                 + " Bytes to TAIL.\n")
            packet = udppacket(con, data[:s.udpsize])
            data = data[s.udpsize:]
            if s.verbosity > 9:
                s.logfile.write("Resulting packet:\n" + str(packet) + "\n")
            send(Connection.TAIL, con, packet, 0)
            datalength -= s.udpsize
        if s.verbosity:
            s.logfile.write("Writing last part: " + str(datalength)
                             + " Bytes to TAIL.\n")
            s.logfile.write(str(loglength) + " Bytes written in total.\n")
        packet = udppacket(con, data)
        if s.verbosity > 9:
            s.logfile.write("Resulting packet:\n" + str(packet) + "\n")
        send(Connection.TAIL, con, packet, 0)


def l7TCPmanage(data, con):
    """Managing the TCP part of l7manage."""
    datalength = len(str(data))
    loglength = datalength
    # If the datalength is not bigger than the given MSS
    if not datalength > con.head.mss:
        if s.verbosity:
            s.logfile.write("Writing " + str(datalength)
                             + " Bytes to TAIL.\n")
        packet = tcppacket(con, data)
        if s.verbosity == 3:
            s.logfile.write("Resulting packet:\n" + str(packet) + "\n")
        send(Connection.TAIL, con, packet)
    # The datalength is bigger than the MSS, we need to send multiple packets.
    else:
        if s.verbosity or not s.verbosity:
            s.logfile.write("Multiple packets will be sent. Datalength is: "
                             + str(datalength) + " Bytes to TAIL.\n")
        while datalength > con.head.mss:
            if s.verbosity:
                s.logfile.write("Writing a part: " + str(con.head.mss)
                                 + " Bytes to TAIL.\n")
            packet = tcppacket(con, data[:con.head.mss])
            data = data[con.head.mss:]
            if s.verbosity > 9:
                s.logfile.write("Resulting packet:\n" + str(packet) + "\n")
            send(Connection.TAIL, con, packet)
            datalength -= con.head.mss
        if s.verbosity:
            s.logfile.write("Writing last part: " + str(datalength)
                             + " Bytes to TAIL.\n")
            s.logfile.write(str(loglength) + " Bytes written in total.\n")
        packet = tcppacket(con, data)
        if s.verbosity > 9:
            s.logfile.write("Resulting packet:\n" + str(packet) + "\n")
        send(Connection.TAIL, con, packet)

def tcppacket(con, data):
    """Function returning a tcppacket for the given connection with data as
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
    if s.verbosity > 1:
        s.logfile.write("SeqNr: " + str(tcp.get_th_seq()) + "\n")
    tcp.set_ACK()
    tcp.contains(data)
    con.tail.acknr(datalength)
    ethhead = con.packet(Connection.TAIL, tcp)
    packet = vdepad(cksum(ethhead))
    return packet


def udppacket(con, data):
    """Function returning a udppacket for the given connection with data as
    payload with target con.tail."""
    data = ImpactPacket.Data(data)
    udp = ImpactPacket.UDP()
    udp.set_uh_dport(con.tail.port)
    udp.set_uh_sport(con.head.port)
    udp.contains(data)
    ethhead = con.packet(Connection.TAIL, udp)
    packet = vdepad(cksum(ethhead))
    return packet


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
        if s.verbosity > 9:
            s.logfile.write("IP packet on TCPIPFILTER_OUT. \n")
        child = content.child()
        dstip = content.get_ip_dst()
        if isinstance(child, ImpactPacket.TCP):
            srcp = child.get_th_sport()
            streamtype = 0
            if s.verbosity > 9:
                s.logfile.write("Streamtype:" + str(streamtype) + " \n")
        elif isinstance(child, ImpactPacket.UDP):
            srcp = child.get_uh_sport()
            streamtype = 1
            if s.verbosity > 9:
                s.logfile.write("Streamtype:" + str(streamtype) + " \n")
        elif isinstance(child, ImpactPacket.ICMP):
            streamtype = 2
            if s.verbosity > 9:
                s.logfile.write("Streamtype:" + str(streamtype) + " \n")
            srcp = content.get_ip_src()
        # Test for IP-dest hits.
        if not dstip in s.ipfilter:
            if s.verbosity > 9:
                s.logfile.write("No filterhit. IP-dest is:" + dstip + "\n")
            return orgpacket, 1
        else:
            # If no port rules apply, all ip hits are filtered.
            if not s.portfilter[dstip]:
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
                if str(child.get_th_dport()) in s.portfilter[dstip]:
                    content.set_ip_dst(newTargetIp)
                    child.set_th_sum(0)
                    child.auto_checksum = 1
                    if s.verbosity:
                        s.logfile.write("Hit on port: " + 
                                      str(child.get_th_dport()) +'\n')
                # Port not filtered -> drop
                else:
                    if s.verbosity:
                        s.logfile.write("Port not in filterlist, dropping...")
                    return orgpacket, 0

            # Test for Port-dest hits on UDP.
            elif streamtype == 1:
                if str(child.get_uh_dport()) in s.portfilter[dstip]:
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
        if s.verbosity > 9:
            s.logfile.write("ARP on TCPIPFILTER_OUT. \n")
        targetip = str(content.as_pro(content.get_ar_tpa()))
        # Test for IP-dest hits.
        if not targetip in s.ipfilter:            
            return orgpacket, 1
        else:
            if s.verbosity:
                s.logfile.write("Filtered ARP request. Redirecting...\n")
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
            if s.verbosity:
                s.logfile.write("ARP packet from targetip fetched." + 
                                " ARP poisoning..\n")
            for filterip in s.ipfilter:
                content.set_ar_spa(map(int, filterip.split(".")))
                packet = decpacket.get_packet()
                packet = vdepad(packet)
                TCPConnection.stdout.write(packet)
                TCPConnection.stdout.flush()
            return orgpacket, 1
    # This case should not happen to often, there are not many packets
    # which are neither ARP nor IP.
    else:
        return orgpacket, 1



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
                s.queue.put((readdata, fd))
                return
            # More than one packet left in the buffer.
            elif (unpack("H", '%s%s' % (readdata[1], readdata[0]))[0]
                  < len(readdata[2:])):
                s.queue.put((readdata[:2 + unpack("H", '%s%s' %
                          (readdata[1], readdata[0]))[0]], fd))
                readdata = readdata[2 + unpack("H", '%s%s' %
                                               (readdata[1], readdata[0]))[0]:]
            # Less than one packet left, this seems to be a split packet.
            # Gets dropped ATM, should be okay. If we reach this state, there
            # are some more serious problems than split packets on the buffer.
            else:
                s.logfile.write("Split packet! Dropping...\n")
                return


if __name__ == '__main__':
     main(sys.argv[1])
