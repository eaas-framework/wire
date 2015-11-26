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

import priority_dict


class Host(object):
    """Basic Host class, holding layer 2/3 information. This should only be used
    to inherit from."""

    def __init__(self, information):
        self.mac = information[0]
        self.ipaddr = information[1]
        self.port = information[2]


class UDPHost(Host):
    """UDP-Host type."""
    def __init__(self, information):
        super(UDPHost, self).__init__(information)


class TCPHost(Host):
    """TCP-Host type, keeping track of ACK and SEQ nos."""

    STATUS_OPEN = 1
    STATUS_CLOSE_WAIT = 2
    STATUS_FIN_WAIT2 = 3
    STATUS_CLOSED = 0

    def __init__(self, information, seq, expSeq):
        super(TCPHost, self).__init__(information)
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
