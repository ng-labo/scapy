# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

import socket
import struct

from scapy.config import conf
from scapy.data import IP_PROTOS
from scapy.error import warning, Scapy_Exception
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    FlagsField,
    IPField,
    IntField,
    LongField,
    MACField,
    PacketListField,
    SecondsIntField,
    ShortEnumField,
    ShortField,
    StrField,
    StrFixedLenField,
    StrLenField,
    ThreeBytesField,
    UTCTimeField,
    XByteField,
    XShortField,
)
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.plist import PacketList
from scapy.sessions import IPSession, DefaultSession

from scapy.layers.inet import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IP6Field

class SflowCounter2001(Packet):
    name = "SFLCOUNTERS_ADAPTORS"
    fields_desc = [ IntField("num_adp", 0),
                    IntField("ifindex", 0),
                    IntField("numMacs", 0),
                    MACField("MACs", None),
                      ]

class SflowCounter1005(Packet):
    name = "SFLCOUNTERS_PORTNAME"
    fields_desc = [ IntField("strLen", 0),
                    StrFixedLenField("ifName", "", length_from=lambda pkt:pkt.strLen)  ]

class SflowCounterList(Packet):
    name = "Sflow Counter List"
    fields_desc = [ IntField("tag", 0),
                    IntField("length", 0),
                    ConditionalField(PacketListField("info", None,  SflowCounter1005), lambda pkt:pkt.tag==1005),
                    ConditionalField(PacketListField("info", None,  SflowCounter2001), lambda pkt:pkt.tag==2001)
                  ]

class SflowCounter(Packet):
    name = "Sflow Counter"
    fields_desc = [ IntField("length", 0),
                    IntField("generated", 0),
                    IntField("samplerId", 0),
                    FieldLenField("numElements", None, fmt='I', count_of="counters"),
                    PacketListField("counters", None, SflowCounterList, count_from=lambda pkt:pkt.numElements) 
                  ]

class SflowFlow(Packet):
    name = "Sflow Flow"
    fields_desc = [ IntField("length", 0),
                   IntField("generated", 0),
                   IntField("samplerId", 0),
                   IntField("meanSkipCount", 0),
                   IntField("samplePool", 0),
                   IntField("dropEvents", 0),
                   IntField("inputPort", 0),
                   IntField("outputPort", 0),
                   IntField("numElements", 0),
                   IntField("elementType", 0),
                   IntField("fieldLen", 0),
                   IntField("headerProtocol", 0),
                   IntField("sampledPacketSize", 0),
                   IntField("strippedBytes", 0),
                   #IntField("headerLen", 0),
                   FieldLenField("headerLen", None, fmt='I', length_of="ether"),
                   PacketListField("ether", None, Ether, length_from=lambda pkt:pkt.headerLen) 
                  ]

class SflowSample(Packet):
    name = "Sflow Sample"
    fields_desc = [IntField("type", 1),
                   #ConditionalField(SflowFlow, lambda pkt:pkt.type==1) ]
                   ConditionalField(PacketListField("flow", None,  SflowFlow), lambda pkt:pkt.type==1),
                   ConditionalField(PacketListField("counter", None,  SflowCounter), lambda pkt:pkt.type==2) ]

class SflowPacket(Packet):
    name = "Sflow Packet"
    fields_desc = [IntField("datagramVersion", 5),
                   IntField("addressType", 1),
                   IPField("agent", "0.0.0.0"),
                   IntField("agentSubId", 0),
                   IntField("sequenceNo", 0),
                   IntField("sysUpTime", 0),
                   FieldLenField("inPacket", None, fmt="I", count_of="sample"),
                   PacketListField("sample", None, SflowSample, count_from=lambda pkt:pkt.inPacket)
                  ]


for port in [6343,]:  # Standard SFlow ports
    bind_bottom_up(UDP, SflowPacket, dport=port)
    bind_bottom_up(UDP, SflowPacket, sport=port)
bind_layers(UDP, SflowPacket, dport=6343, sport=6343)

###########################################
# Sflow Version 5
###########################################
