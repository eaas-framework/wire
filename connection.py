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

import socket
import select
import threading
from impacket import ImpactDecoder, ImpactPacket
from host import *
from protocol import *
import settings as s
from functions import *

def getconinfo(packet):
    """Function parsing data for opening a new connection. Return values are
    source = (mac, ip, port), dest = (mac, ip, port), seq = sequence number 
    (if any)"""
    ethhead = packet
    iphead = ethhead.child()
    tcpudphead = iphead.child()
    sourceip = iphead.get_ip_src()
    dstip = iphead.get_ip_dst()
    sourcemac = ethhead.get_ether_shost()
    dstmac = ethhead.get_ether_dhost()
    ptype = l34protocolfilter(ethhead)
    if ptype == Protocol.TCP:
        dstport = tcpudphead.get_th_dport()
        sourceport = tcpudphead.get_th_sport()
        seq = tcpudphead.get_th_seq()
    elif ptype == Protocol.UDP:
        dstport = tcpudphead.get_uh_dport
        sourceport = tcpudphead.get_uh_sport()
        seq = None
    # ptype == Protocol.Other
    else:
        raise ValueError("No non-TCP/UDP packets should be passed to this fct.")

    return ((sourcemac, sourceip, sourceport), (dstmac, dstip, dstport), seq)

class Connection(object):
    """Class for general connection functions."""

    fdtocon = dict()
    sockinfo = tuple()
    poller = None
    TAIL = "tail"
    HEAD = "head"
    SOCK = "sock"

    def __init__(self, source, dest):
        self.head = source
        self.tail = dest

    @staticmethod
    def resolvefd(filedescriptor):
        """Function returning the corresponding connection to a filedescriptor.
        """
        return Connection.fdtocon[filedescriptor]

    @staticmethod
    def resolvesrc(source, ptype):
        """Function returning the corresponding connection for a source.
        If there is not existing one yet, return None.
        """
        if ptype == Protocol.TCP:
            if source in TCPConnection.connectionlist:
                return TCPConnection.connectionlist[source]
            else:
                return None
        elif ptype == Protocol.UDP:
            if source in UDPConnection.connectionlist:
                return UDPConnection.connectionlist[source]

    @staticmethod
    def newSocket():
        """Function returning a new socket, which is registered on the poller
        already."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(Connection.sockinfo)
        sock.setblocking(0)
        Connection.poller.register(sock, select.POLLIN | select.POLLHUP)
        return sock

    @staticmethod
    def remove(con):
        """Function removing a connection with taking care of the socket and
        poller removal actions."""
        Connection.poller.unregister(con.sock.fileno())
        Connection.fdtocon.pop(con.sock.fileno())
        con.sock.close()
        s.logfile.write("Closing TCP-connection with source "
                         + str(con.source[2]) + "\n")
        s.deletionList.remove(con)
        TCPConnection.connectionlist.pop(con.source[2])

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
        # target == TCPConnection.TAIL
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



class UDPConnection(Connection):
    """Each object is a connection with socket, ip and port. Holds all
    information to send and reinject data to and from a socket.
    BEWARE: UDP-connections can only be invoked by the filtered host atm."""

    connectionlist = dict()

    def __init__(self, packet):
        """Packet is the packet, where the connection should be built from."""
        source, dest, seq = getconinfo(packet)
        self.sock = Connection.newSocket()
        self.type = Protocol.UDP
        super(UDPConnection, self).__init__(UDPHost(source), UDPHost(dest))
        UDPConnection.connectionlist[source[2]] = self
        Connection.fdtocon[self.sock.fileno()] = self

    


class TCPConnection(Connection):
    """Each object is a connection with a socket, ip and port.
    Everything reveived on std_in will get acked immediately, processed and
    afterwards sent to alt_stdout. The other way round it works the same.
    """
    connectionlist = dict()
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
        self.sock = Connection.newSocket()
        self.type = Protocol.TCP
        #sock.fileno()
        super(TCPConnection, self).__init__(TCPHost(source, seqhead, seqtail), 
                                            TCPHost(dest, seqtail, seqhead))
        self.source = source
        if s.verbosity:
            s.logfile.write("Seqtail: " + str(seqtail)
                             + " Seqhead: " + str(seqhead) + '\n')
            s.logfile.write("Source: " + str(source) + " Target: "
                          + str(dest) + "\n")        
        TCPConnection.connectionlist[source[2]] = self
        Connection.fdtocon[self.sock.fileno()] = self    

    def tcpenqueue(self, target, packet, acknr):
        """Method adding the given packet to the retransmission queue of target.
        The ACKnr which will delete the entry is the one which is valid at
        calltime of the method."""
        if target == Connection.HEAD:
            s.lock.acquire()
            self.head.retransqueue[acknr] = (time(), packet)
            if s.verbosity:
                s.logfile.write("Put " + str(acknr)
                                 + " into queue head \n")
                if s.verbosity > 1:
                    s.logfile.write("Time: " +
                                     str(self.head.retransqueue
                                         [acknr][0]) + "\n")
                    if s.verbosity > 9:
                        s.logfile.write("Packet:\n" + str(packet) + "\n")
            s.lock.release()
        else:
            s.lock.acquire()
            self.tail.retransqueue[acknr] = (time(), packet)
            if s.verbosity:
                s.logfile.write("Put " + str(acknr)
                                 + " into queue tail \n")
                if s.verbosity == 2:
                    s.logfile.write("Time: " +
                                     str(self.tail.retransqueue
                                         [acknr][0]) + "\n")
                    if s.verbosity > 9:
                        s.logfile.write("Packet:\n" + str(packet) + "\n")
            s.lock.release()

    def reset(self, target):
        """Function returning a TCP-RST packet to target.
        """
        tcp = ImpactPacket.TCP()
        if target == Connection.HEAD:
            thost = self.head
            shost = self.tail
        # target == TCPConnection.TAIL
        else:
            thost = self.tail
            shost = self.head
        tcp.set_th_dport(thost.port)
        tcp.set_th_sport(shost.port)
        tcp.set_th_seq(thost.expectedSeqnr())
        tcp.set_th_ack(thost.expectedAcknr())
        tcp.set_RST()
        tcp.set_ACK()
        if s.verbosity:
            s.logfile.write("RST packet sent!\n")
            s.logfile.write("SeqNr: " + str(tcp.get_th_seq()) + "\n")
            s.logfile.write("AckNr: " + str(tcp.get_th_ack()) + "\n")
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
        s.lock.acquire()
        if acknr in host.retransqueue:
            # Every older packet get's ACKed with this one.
            it = host.retransqueue.sorted_iter()
            itemACK = it.next()
            counter = 1
            while itemACK != acknr:
                itemACK = it.next()
                counter += 1
            if s.verbosity:
                s.logfile.write("Removing ACK " + str(acknr)
                                     + " and all older from queue. \n")
                s.logfile.write("A total of " + str(counter)
                              + " are ACKed.\n")

        else:
            if s.verbosity or not s.verbosity:
                s.logfile.write("ACK for unknown packet. ACKNr:"
                                 + str(acknr) + "\n")
        s.lock.release()

    def syn(self, source, seq, winsize):
        """Method managing received SYN by setting the seqnr for the connection
        """
        if source == Connection.HEAD:
            self.head.seq = seq + 1
            self.head.expectACK = seq + 1
            self.tail.expectSEQ = seq + 1
            self.tail.ack = seq + 1
            self.head.winsize = winsize
            if s.verbosity == 2:
                s.logfile.write("winsize head: " + str(winsize) + '\n')
        # source == TCPConnection.TAIL
        else:
            self.tail.seq = seq + 1
            self.tail.expectACK = seq + 1
            self.head.expectSEQ = seq + 1
            self.head.ack = seq + 1
            self.tail.winsize = winsize
            if s.verbosity == 2:
                s.logfile.write("winsize tail: " + str(winsize) + '\n')

    def fin(self, source, datalen=0):
        """Method managing received FIN by closing the connection in one
        direction."""
        if source == Connection.HEAD:
            shost = self.head
            thost = self.tail
            target = TCPConnection.TAIL
        else:
            shost = self.tail
            thost = self.head
            target = Connection.HEAD
        # If the sender had status open so far, he was the initiator of FIN.
        if shost.status == TCPHost.STATUS_OPEN:
            self.sendfin(source, 1, datalen)
            shost.status = TCPHost.STATUS_FIN_WAIT2
            # If the other host is open, schedule a finish procedure.
            # When data was included in the package, double the waiting time.
            if thost.status == TCPHost.STATUS_OPEN:
                global finQueue
                if datalen == 0:
                    s.finQueue.put([time(), self, target])
                else:
                    s.finQueue.put([time() + s.finTime, self, target])
        # If the sender was in status CLOSE_WAIT, we initiated the FIN before.
        # He is sending an answer. We simply need to acknowledge it.
        if shost.status == TCPHost.STATUS_CLOSE_WAIT:
            if s.verbosity:
                s.logfile.write("Sending last ACK.\n")
            self.sendack(source, 1)
            shost.status = TCPHost.STATUS_CLOSED
            # If both hosts are in status closed, schedule the connection for
            # deletion.
            global deletionList
            if shost.status == thost.status == TCPHost.STATUS_CLOSED:
                s.deletionList.append(self)
            if s.verbosity:
                s.logfile.write("TCPConnection status:\n")
                s.logfile.write("Head: " + str(self.head.status) + "\n")
                s.logfile.write("Tail: " + str(self.tail.status) + "\n")

    def sendfin(self, target, answer, datalen=0):
        """Method sending a FIN/ACK to target. If answer is set, this should
        be the answer to a received FIN/ACK. Else this is the initiation of
        the connection closing mechanism."""
        tcp = ImpactPacket.TCP()
        if target == Connection.HEAD:
            thost = self.head
            shost = self.tail
            out = TCPConnection.stdout
        else:
            thost = self.tail
            shost = self.head
            out = TCPConnection.alt_stdout

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
        if s.verbosity:
            s.logfile.write("FIN/ACK packet sent!\n")
            s.logfile.write("SeqNr: " + str(tcp.get_th_seq()) + "\n")
            s.logfile.write("AckNr: " + str(tcp.get_th_ack()) + "\n")
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
            out = TCPConnection.stdout
        else:
            thost = self.tail
            shost = self.head
            out = TCPConnection.alt_stdout

        tcp.set_th_dport(thost.port)
        tcp.set_th_sport(shost.port)
        tcp.set_th_ack(thost.expectedAcknr(bytecount))
        # ACK does not increment seq-nr.
        tcp.set_th_seq(thost.expectedSeqnr(0))
        tcp.set_th_win(thost.winsize)

        tcp.set_ACK()

        packet = self.packet(target, tcp)
        if s.verbosity:
            s.logfile.write("ACK sent to " + target + ".\n")
            s.logfile.write("Seqnr.: " + str(tcp.get_th_seq()) + "\n")
            s.logfile.write("ACKNr.: " + str(tcp.get_th_ack()) + "\n")
            if s.verbosity > 9:
                s.logfile.write(str(packet) + "\n")
        packet = vdepad(cksum(packet))
        send(target, self, packet, 0)


    def sendSYN(self, target, ethhead):
        """Method sending a given SYN packet to target. The SYN packet will be
        changed to not support TCPOPT_TIMESTAMP.
        """
        iphead = ethhead.child()
        tcphead = iphead.child()
        if target == TCPConnection.TAIL:
            out = TCPConnection.alt_stdout
            host = self.head
        # target == Connection.HEAD
        else:
            out = TCPConnection.stdout
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
            if s.verbosity:
                s.logfile.write("Keepalive fetched.\n")
                s.logfile.write("SeqNr: " + str(seqnr) + "\n")
            return 1
        # If we expect seqnr = 0, this is a new connection.
        # The number is always valid then.
        elif host.seqnr(0) == 0:
            return 0
        else:
            s.logfile.write("Invalid SEQNR! Dropping...\n")
            s.logfile.write("Expected: " + str(host.seqnr())
                             + " Got: " + str(seqnr) + "\n")
            return 2

    def makevalid(self, ethhead, target=Connection.HEAD):
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
            if s.verbosity:
                s.logfile.write("Seq: " + str(tcphead.get_th_seq()) + "\n")
            self.head.acknr(data.get_size())
        # target == TCPConnection.TAIL
        else:
            raise NotImplementedError("Makevalid may only be used with HEAD.")
        return ethhead