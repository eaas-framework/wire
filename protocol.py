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


# Structure for protocol types. More to come eventually.

from impacket import ImpactDecoder, ImpactPacket

def l34protocolfilter(ethpacket):
    """Funtion returning the packets protocol type (see class Protocol).
    """
    ethhead = ethpacket
    iphead = ethhead.child()
    # Identify IP packets:
    if iphead.ethertype == ImpactPacket.IP.ethertype:
        tcpudphead = iphead.child()
        # Only check TCP
        if tcpudphead.protocol == ImpactPacket.TCP.protocol:
            return Protocol.TCP
        elif tcpudphead.protocol == ImpactPacket.UDP.protocol:
            return Protocol.UDP
    return Protocol.Other 

class Protocol():
    Other = 0
    TCP = 1
    UDP = 2

