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
    #BitEnumField,
    #BitField,
    #ByteEnumField,
    #ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    #FlagsField,
    IPField,
    IntField,
    IntEnumField,
    #LongField,
    MACField,
    MultipleTypeField,
    PacketField,
    PacketListField,
    #SecondsIntField,
    #ShortEnumField,
    #ShortField,
    StrField,
    StrFixedLenField,
    #StrLenField,
    #ThreeBytesField,
    #UTCTimeField,
    #XByteField,
    #XShortField,
)
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.plist import PacketList
from scapy.sessions import IPSession, DefaultSession

from scapy.layers.inet import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IP6Field

###########################################
# Sflow Version 5
###########################################

class SflowCounter1(Packet):
    name = "SFLCOUNTERS_GENERIC"
    fields_desc = [ IntField("ifIndex", 0),
                    IntField("networkType", 0),
                    IntField("ifSpeed", 0),
                    IntField("ifDirection", 0),
                    IntField("ifStatus", 0),
                    IntField("ifInOctets", 0),
                    IntField("ifInUcastPkts", 0),
                    IntField("ifInMulticastPkts", 0),
                    IntField("ifInBroadcastPkts", 0),
                    IntField("ifInDiscards", 0),
                    IntField("ifInErrors", 0),
                    IntField("ifInUnknownProtos", 0),
                    IntField("ifOutOctets", 0),
                    IntField("ifOutUcastPkts", 0),
                    IntField("ifOutMulticastPkts", 0),
                    IntField("ifOutBroadcastPkts", 0),
                    IntField("ifOutDiscards", 0),
                    IntField("ifOutErrors", 0),
                    IntField("ifPromiscuousMode", 0),
                  ]
    def extract_padding(self, p):
        return "", p


class SflowCounter2(Packet):
    name = "SFLCOUNTERS_ETHERNET"
    fields_desc = [ IntField("dot3StatsAlignmentErrors", 0),
                    IntField("dot3StatsFCSErrors", 0),
                    IntField("dot3StatsSingleCollisionFrames", 0),
                    IntField("dot3StatsMultipleCollisionFrames", 0),
                    IntField("dot3StatsSQETestErrors", 0),
                    IntField("dot3StatsDeferredTransmissions", 0),
                    IntField("dot3StatsLateCollisions", 0),
                    IntField("dot3StatsExcessiveCollisions", 0),
                    IntField("dot3StatsInternalMacTransmitErrors", 0),
                    IntField("dot3StatsCarrierSenseErrors", 0),
                    IntField("dot3StatsFrameTooLongs", 0),
                    IntField("dot3StatsInternalMacReceiveErrors", 0),
                    IntField("dot3StatsSymbolErrors", 0), ]
    def extract_padding(self, p):
        return "", p


class SflowCounter1005(Packet):
    name = "SFLCOUNTERS_PORTNAME"
    fields_desc = [ IntField("strLen", 0),
                    StrFixedLenField("ifName", "", length_from=lambda pkt:pkt.strLen) ]
    def extract_padding(self, p):
        return "", p


class SflowCounter2001(Packet):
    name = "SFLCOUNTERS_ADAPTORS"
    fields_desc = [ IntField("num_adp", 0),
                    IntField("ifindex", 0),
                    IntField("numMacs", 0),
                    MACField("MACs", None),
                      ]
    def extract_padding(self, p):
        return "", p


class SflowCounterList(Packet):
    name = "Counter List"
    fields_desc = [ IntField("tag", 0),
                    IntField("length", 0),
                    ConditionalField(PacketListField("tag1", None,  SflowCounter1), lambda pkt:pkt.tag==1),
                    ConditionalField(PacketListField("tag2", None,  SflowCounter2), lambda pkt:pkt.tag==2),
                    ConditionalField(PacketListField("tag1005", None,  SflowCounter1005), lambda pkt:pkt.tag==1005),
                    ConditionalField(PacketListField("tag2001", None,  SflowCounter2001), lambda pkt:pkt.tag==2001)
                  ]
    def extract_padding(self, p):
        return "", p

class SflowCounter(Packet):
    name = "Counter"
    fields_desc = [ IntField("length", 0),
                    IntField("generated", 0),
                    IntField("samplerId", 0),
                    FieldLenField("numElements", None, fmt='I', count_of="counters"),
                    PacketListField("counters", None, SflowCounterList, count_from=lambda pkt:pkt.numElements) 
                  ]
    def extract_padding(self, p):
        return "", p


class SflowFlowExswitch(Packet):
    # SFLFLOW_EX_SWITCH    = 1001
    name = "SFL_EXSWITCH"
    fields_desc = [ IntField("inVlan", 0),
                    IntField("inPriority", 0),
                    IntField("outVlan", 0),
                    IntField("outPriority", 0),
                  ]
    def extract_padding(self, p):
        return "", p


class SflowFlowExrouter(Packet):
    # SFLFLOW_EX_ROUTER    = 1002
    name = "SFL_EXROUTER"
    fields_desc = [ IntEnumField("addrType", 1, {1:"v4", 2:"v6"}),
                    MultipleTypeField(
                      [ (IPField("nextHop", "0.0.0.0"), lambda pkt:pkt.addrType==1),
                        (IP6Field("nextHop", "::"), lambda pkt:pkt.addrType==2),], StrField("nextHop", "") ),
                    IntField("srcMask", 0),
                    IntField("dstMask", 0),
                  ]
    def extract_padding(self, p):
        return "", p


class DstAsPath(Packet):
    name = "DstAsPath"
    fields_desc = [ IntEnumField("type", 1, {1:"SET", 2:"SEQUENCE"}),
                    IntField("seglen", 0),
                    StrFixedLenField("dstAsPath", "", length_from=lambda pkt:pkt.seglen*4),
                  ]
    def extract_padding(self, p):
        return "", p


class SflowFlowExgateway(Packet):
    # SFLFLOW_EX_GATEWAY   = 1003
    name = "SFL_EXGATEWAY"
    fields_desc = [ IntEnumField("addrType", 1, {1:"v4", 2:"v6"}),
                    MultipleTypeField(
                      [(IPField("bgp_nextHop", "0.0.0.0"), lambda pkt:pkt.addrType==1),
                       (IP6Field("bgp_nextHop", "::"), lambda pkt:pkt.addrType==2),], StrField("bgp_nextHop", "")),
                    IntField("myAS", 0),
                    IntField("srcAS", 0),
                    IntField("srcPeerAS", 0),
                    IntField("segments", 0),
                    PacketListField("dstAsPath", None, DstAsPath, count_from=lambda pkt:pkt.segments),
                    IntField("communitiesLen", 0),
                    StrFixedLenField("communities", "", length_from=lambda pkt:pkt.communitiesLen*4),
                    IntField("bgp_localPref", 0),
                  ]
    def extract_padding(self, p):
        return "", p


class SflowFlowEthernet(Packet):
    name = "SFL_ETHERNET"
    fields_desc = [ IntField("ethLen", 0),
                    MACField("eth_src", None),
                    MACField("eth_dst", None),
                    IntField("eth_type", 0)
                  ]
    def extract_padding(self, p):
        return "", p


class SflowFlowHeader(Packet):
    name = "SFL_HEADER"
    fields_desc = [ IntField("headerProtocol", 0),
                    IntField("sampledPacketSize", 0),
                    IntField("strippedBytes", 0),
                    FieldLenField("headerLen", None, fmt='I', length_of="ether"),
                    PacketListField("ether", None, Ether, length_from=lambda pkt:pkt.headerLen) 
                  ]
    def extract_padding(self, p):
        return "", p

class SflowFlowElement(Packet):
    name = "FlowElement"
    fields_desc = [ IntField("elementType", 0),
                    FieldLenField("fieldLen", None, fmt='I', length_of="flowHeader"),
                    ConditionalField(
                        PacketListField("flowHeader", None, SflowFlowHeader, length_from=lambda pkt:pkt.fieldLen), lambda pkt:pkt.elementType==1),
                    ConditionalField(
                        PacketListField("flowEthernet", None, SflowFlowEthernet, length_from=lambda pkt:pkt.fieldLen), lambda pkt:pkt.elementType==2),
                    ConditionalField(
                        PacketListField("flowExSwitch", None, SflowFlowExswitch, length_from=lambda pkt:pkt.fieldLen), lambda pkt:pkt.elementType==1001),
                    ConditionalField(
                        PacketListField("flowExRouter", None, SflowFlowExrouter, length_from=lambda pkt:pkt.fieldLen), lambda pkt:pkt.elementType==1002),
                    ConditionalField(
                        PacketListField("flowExGateway", None, SflowFlowExgateway, length_from=lambda pkt:pkt.fieldLen), lambda pkt:pkt.elementType==1003),
                    ConditionalField(
                        StrFixedLenField("flowDummy", "", length_from=lambda pkt:pkt.fieldLen), lambda pkt:pkt.elementType not in (1, 2, 1001, 1002, 1003)),
                  ]
    def extract_padding(self, p):
        return "", p

class SflowFlow(Packet):
    name = "Flow"
    fields_desc = [ FieldLenField("length", None, fmt='I', length_of="flowElement"),
                    IntField("generated", 0),
                    IntField("samplerId", 0),
                    IntField("meanSkipCount", 0),
                    IntField("samplePool", 0),
                    IntField("dropEvents", 0),
                    IntField("inputPort", 0),
                    IntField("outputPort", 0),
                    FieldLenField("numElements", None, fmt='I', count_of="flowElement"),
                    PacketListField("flowElement", None, SflowFlowElement, count_from=lambda pkt:pkt.numElements),
                  ]
    def extract_padding(self, p):
        return "", p

class SflowSample(Packet):
    name = "Sflow Sample"
    fields_desc = [ IntEnumField("type", 1, {1:"flowsample", 2:"counter-sample", 3:"flow-sample-ex"}),
                    ConditionalField(
                        PacketField("flow", None, SflowFlow), lambda pkt:pkt.type==1),
                    ConditionalField(
                        PacketField("counter", None, SflowCounter), lambda pkt:pkt.type==2),
                  ]
    def extract_padding(self, p):
        return "", p

class SflowPacket(Packet):
    name = "Sflow Packet"
    fields_desc = [ IntField("datagramVersion", 5),
                    IntField("addressType", 1),
                    IPField("agent", "0.0.0.0"),
                    IntField("agentSubId", 0),
                    IntField("sequenceNo", 0),
                    IntField("sysUpTime", 0),
                    FieldLenField("inPacket", None, fmt="I", count_of="flowSample"),
                    PacketListField("flowSample", None, SflowSample, count_from=lambda pkt:pkt.inPacket)
                  ]


for port in [6343, 6348]:  # Standard SFlow ports
    bind_bottom_up(UDP, SflowPacket, dport=port)
    bind_bottom_up(UDP, SflowPacket, sport=port)
bind_layers(UDP, SflowPacket, dport=6348, sport=6348)

