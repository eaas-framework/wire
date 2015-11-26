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

from impacket import ImpactDecoder, ImpactPacket
from struct import pack
import settings as s
import connection
import datetime

def getdata(ethhead):
    """Function getting the payload (l7 data) from a ImpactPacket.Ethernet
    packet."""
    # s.logfile.write("getdata: " + str(ethhead.child().child().child()) + '\n')
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

def vdepad(packet):
    """Funtion computing the right vde padding and adding it to the packet.
    Return value is the packet with leading vde length information."""
    lengthb = pack('H', len(packet))
    lengthb = lengthb[1] + lengthb[0]
    packet = '%s%s' % (lengthb, packet)

    return packet

def send(target, con, packet, enqueue=1):
    """Puts packets in the sendingQueue in a proper format."""
    global sendingQueue
    if enqueue:
        if target == connection.Connection.HEAD:
            acknr = con.head.acknr()
        else:
            acknr = con.tail.acknr()
    else:
        acknr = 0
    s.sendingQueue.put((target, con, packet, enqueue, acknr))

def time():
    """Return the actual time."""
    return datetime.datetime.now()


