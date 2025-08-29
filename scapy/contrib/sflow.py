# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
 sflow

 some specifications of sflow(verrion5) is implemented.

 - version : 5
 - header_protocol : ETHERNET-ISO88023
 - flow element types : flow-header
                        extented switch
                        extented router
                        extented gateway
 - counter tags :

 pkts = sniff(offline=open('captured-slow.pcap', 'rb'))

 sFlowRcvrPort default value is 6343, SflowDatagram is binded to udp in 6343 port


 SflowDatagram
   flow-sample
   flow-counter

"""

from scapy.fields import (
    ConditionalField,
    FieldLenField,
    FieldListField,
    IPField,
    IntField,
    IntEnumField,
    LongField,
    MultipleTypeField,
    PacketField,
    PacketLenField,
    PacketListField,
    StrField,
    StrFixedLenField,
)
from scapy.packet import Packet, bind_layers

from scapy.layers.inet import UDP, Ether, IP
from scapy.layers.inet6 import IP6Field


class SflowCounter1(Packet):
    name = "SFLCOUNTERS_GENERIC"
    fields_desc = [IntField("ifIndex", 0),
                   IntField("networkType", 0),
                   LongField("ifSpeed", 0),
                   IntField("ifDirection", 0),
                   IntField("ifStatus", 0),
                   LongField("ifInOctets", 0),
                   IntField("ifInUcastPkts", 0),
                   IntField("ifInMulticastPkts", 0),
                   IntField("ifInBroadcastPkts", 0),
                   IntField("ifInDiscards", 0),
                   IntField("ifInErrors", 0),
                   IntField("ifInUnknownProtos", 0),
                   LongField("ifOutOctets", 0),
                   IntField("ifOutUcastPkts", 0),
                   IntField("ifOutMulticastPkts", 0),
                   IntField("ifOutBroadcastPkts", 0),
                   IntField("ifOutDiscards", 0),
                   IntField("ifOutErrors", 0),
                   IntField("ifPromiscuousMode", 0), ]

    def extract_padding(self, p):
        return "", p


class SflowCounter2(Packet):
    name = "SFLCOUNTERS_ETHERNET"
    fields_desc = [IntField("dot3StatsAlignmentErrors", 0),
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
    fields_desc = [IntField("strLen", 0),
                   StrFixedLenField("ifName", "",
                                    length_from=lambda pkt: pkt.strLen), ]

    def extract_padding(self, p):
        return "", p


class SflowCounter2000(Packet):
    name = "SFLCOUNTERS_HOST_HID"
    fields_desc = [IntField("hostlen", 0),
                   StrFixedLenField("hostname", "", length=8),
                   LongField("uuid1", 0),
                   LongField("uuid2", 0),
                   IntField("machine_type", 0),
                   IntField("os_name", 0),
                   IntField("orlen", 0),
                   StrFixedLenField("os_release", "",
                                    length_from=lambda pkt: pkt.orlen), ]

    def extract_padding(self, p):
        return "", p


class SflowMACs(Packet):
    name = "SFLCOUNTERS_MACS"
    fields_desc = [IntField("ifindex", 0),
                   IntField("numMacs", 0),
                   StrFixedLenField("MAC", "",
                                    length_from=lambda pkt: pkt.numMacs * 8), ]

    def extract_padding(self, p):
        return "", p


class SflowCounter2001(Packet):
    name = "SFLCOUNTERS_ADAPTORS"
    fields_desc = [IntField("num_adp", 0),
                   PacketListField("Macs", None, SflowMACs,
                                   count_from=lambda pkt: pkt.num_adp), ]

    def extract_padding(self, p):
        return "", p


class SflowCounter2003(Packet):
    name = "SFLCOUNTERS_HOST_CPU"
    fields_desc = [IntField("cpu_load_one", 0),
                   IntField("cpu_load_five", 0),
                   IntField("cpu_load_fifteen", 0),
                   IntField("cpu_proc_run", 0),
                   IntField("cpu_proc_total", 0),
                   IntField("cpu_num", 0),
                   IntField("cpu_speed", 0),
                   IntField("cpu_uptime", 0),
                   IntField("cpu_user", 0),
                   IntField("cpu_nice", 0),
                   IntField("cpu_system", 0),
                   IntField("cpu_idle", 0),
                   IntField("cpu_wio", 0),
                   IntField("cpuintr", 0),
                   IntField("cpu_sintr", 0),
                   IntField("cpuinterrupts", 0),
                   IntField("cpu_contexts", 0),
                   IntField("cpu_steal", 0),
                   IntField("cpu_guest", 0),
                   IntField("cpu_guest_nice", 0), ]

    def extract_padding(self, p):
        return "", p


class SflowCounter2004(Packet):
    name = "SFLCOUNTERS_HOST_MEM"
    fields_desc = [LongField("mem_total", 0),
                   LongField("mem_free", 0),
                   LongField("mem_shared", 0),
                   LongField("mem_buffers", 0),
                   LongField("mem_cached", 0),
                   LongField("swap_total", 0),
                   LongField("swap_free", 0),
                   IntField("page_in", 0),
                   IntField("page_out", 0),
                   IntField("swap_in", 0),
                   IntField("swap_out", 0), ]

    def extract_padding(self, p):
        return "", p


class SflowCounter2005(Packet):
    name = "SFLCOUNTERS_HOST_DSK"
    fields_desc = [LongField("disk_total", 0),
                   LongField("disk_free", 0),
                   IntField("disk_partition_max_used", 0),
                   IntField("disk_reads", 0),
                   LongField("disk_bytes_read", 0),
                   IntField("disk_read_time", 0),
                   IntField("disk_writes", 0),
                   LongField("disk_bytes_written", 0),
                   IntField("disk_write_time", 0), ]

    def extract_padding(self, p):
        return "", p


class SflowCounter2006(Packet):
    name = "SFLCOUNTERS_HOST_NIO"
    fields_desc = [LongField("nio_bytes_in", 0),
                   IntField("nio_pkts_in", 0),
                   IntField("nio_errs_in", 0),
                   IntField("nio_drops_in", 0),
                   LongField("nio_bytes_out", 0),
                   IntField("nio_pkts_out", 0),
                   IntField("nio_errs_out", 0),
                   IntField("nio_drops_out", 0), ]

    def extract_padding(self, p):
        return "", p


class SflowCounter2007(Packet):
    name = "SFLCOUNTERS_HOST_IP"
    fields_desc = [IntField("ipForwarding", 0),
                   IntField("ipDefaultTTL", 0),
                   IntField("ipInReceives", 0),
                   IntField("ipInHdrErrors", 0),
                   IntField("ipInAddrErrors", 0),
                   IntField("ipForwDatagrams", 0),
                   IntField("ipInUnknownProtos", 0),
                   IntField("ipInDiscards", 0),
                   IntField("ipInDelivers", 0),
                   IntField("ipOutRequests", 0),
                   IntField("ipOutDiscards", 0),
                   IntField("ipOutNoRoutes", 0),
                   IntField("ipReasmTimeout", 0),
                   IntField("ipReasmReqds", 0),
                   IntField("ipReasmOKs", 0),
                   IntField("ipReasmFails", 0),
                   IntField("ipFragOKs", 0),
                   IntField("ipFragFails", 0),
                   IntField("ipFragCreates", 0), ]

    def extract_padding(self, p):
        return "", p


class SflowCounter2008(Packet):
    name = "SFLCOUNTERS_HOST_ICMP"
    fields_desc = [IntField("icmpInMsgs", 0),
                   IntField("icmpInErrors", 0),
                   IntField("icmpInDestUnreachs", 0),
                   IntField("icmpInTimeExcds", 0),
                   IntField("icmpInParamProbs", 0),
                   IntField("icmpInSrcQuenchs", 0),
                   IntField("icmpInRedirects", 0),
                   IntField("icmpInEchos", 0),
                   IntField("icmpInEchoReps", 0),
                   IntField("icmpInTimestamps", 0),
                   IntField("icmpInAddrMasks", 0),
                   IntField("icmpInAddrMaskReps", 0),
                   IntField("icmpOutMsgs", 0),
                   IntField("icmpOutErrors", 0),
                   IntField("icmpOutDestUnreachs", 0),
                   IntField("icmpOutTimeExcds", 0),
                   IntField("icmpOutParamProbs", 0),
                   IntField("icmpOutSrcQuenchs", 0),
                   IntField("icmpOutRedirects", 0),
                   IntField("icmpOutEchos", 0),
                   IntField("icmpOutEchoReps", 0),
                   IntField("icmpOutTimestamps", 0),
                   IntField("icmpOutTimestampReps", 0),
                   IntField("icmpOutAddrMasks", 0),
                   IntField("icmpOutAddrMaskReps", 0), ]

    def extract_padding(self, p):
        return "", p


class SflowCounter2009(Packet):
    name = "SFLCOUNTERS_HOST_TCP"
    fields_desc = [IntField("tcpRtoAlgorithm", 0),
                   IntField("tcpRtoMin", 0),
                   IntField("tcpRtoMax", 0),
                   IntField("tcpMaxConn", 0),
                   IntField("tcpActiveOpens", 0),
                   IntField("tcpPassiveOpens", 0),
                   IntField("tcpAttemptFails", 0),
                   IntField("tcpEstabResets", 0),
                   IntField("tcpCurrEstab", 0),
                   IntField("tcpInSegs", 0),
                   IntField("tcpOutSegs", 0),
                   IntField("tcpRetransSegs", 0),
                   IntField("tcpInErrs", 0),
                   IntField("tcpOutRst", 0),
                   IntField("tcpInCsumErrors", 0), ]

    def extract_padding(self, p):
        return "", p


class SflowCounter2010(Packet):
    name = "SFLCOUNTERS_HOST_UDP"
    fields_desc = [IntField("udpInDatagrams", 0),
                   IntField("udpNoPorts", 0),
                   IntField("udpInErrors", 0),
                   IntField("udpOutDatagrams", 0),
                   IntField("udpRcvbufErrors", 0),
                   IntField("udpSndbufErrors", 0),
                   IntField("udpInCsumErrors", 0), ]

    def extract_padding(self, p):
        return "", p


class SflowCounterList(Packet):
    name = "Counter Item"
    fields_desc = [IntField("tag", 0),
                   IntField("length", 0),
                   ConditionalField(
                       PacketField("tag1", None, SflowCounter1),
                       lambda pkt: pkt.tag == 1),
                   ConditionalField(
                       PacketField("tag2", None, SflowCounter2),
                       lambda pkt: pkt.tag == 2),
                   ConditionalField(
                       PacketField("tag1005", None, SflowCounter1005),
                       lambda pkt: pkt.tag == 1005),
                   ConditionalField(
                       PacketField("tag2000", None, SflowCounter2000),
                       lambda pkt: pkt.tag == 2000),
                   ConditionalField(
                       PacketField("tag2001", None, SflowCounter2001),
                       lambda pkt: pkt.tag == 2001),
                   ConditionalField(
                       PacketField("tag2003", None, SflowCounter2003),
                       lambda pkt: pkt.tag == 2003),
                   ConditionalField(
                       PacketField("tag2004", None, SflowCounter2004),
                       lambda pkt: pkt.tag == 2004),
                   ConditionalField(
                       PacketField("tag2005", None, SflowCounter2005),
                       lambda pkt: pkt.tag == 2005),
                   ConditionalField(
                       PacketField("tag2006", None, SflowCounter2006),
                       lambda pkt: pkt.tag == 2006),
                   ConditionalField(
                       PacketField("tag2007", None, SflowCounter2007),
                       lambda pkt: pkt.tag == 2007),
                   ConditionalField(
                       PacketField("tag2008", None, SflowCounter2008),
                       lambda pkt: pkt.tag == 2008),
                   ConditionalField(
                       PacketField("tag2009", None, SflowCounter2009),
                       lambda pkt: pkt.tag == 2009),
                   ConditionalField(
                       PacketField("tag2010", None, SflowCounter2010),
                       lambda pkt: pkt.tag == 2010), ]

    def extract_padding(self, p):
        return "", p


class SflowCounter(Packet):
    name = "Counter Header"
    fields_desc = [IntField("length", 0),
                   IntField("generated", 0),
                   IntField("samplerId", 0),
                   FieldLenField("numElements", None,
                                 fmt='I', count_of="counters"),
                   PacketListField("counters", None,
                                   SflowCounterList,
                                   count_from=lambda pkt: pkt.numElements), ]

    def extract_padding(self, p):
        return "", p


class SflowFlowExswitch(Packet):
    # SFLFLOW_EX_SWITCH    = 1001
    name = "SFL_EXSWITCH"
    fields_desc = [IntField("inVlan", 0),
                   IntField("inPriority", 0),
                   IntField("outVlan", 0),
                   IntField("outPriority", 0), ]

    def extract_padding(self, p):
        return "", p


class SflowFlowExrouter(Packet):
    # SFLFLOW_EX_ROUTER    = 1002
    name = "SFL_EXROUTER"
    _ipv4 = (IPField("nextHop", "0.0.0.0"), lambda pkt: pkt.addrType == 1)
    _ipv6 = (IP6Field("nextHop", "::"), lambda pkt: pkt.addrType == 2)
    fields_desc = [IntEnumField("addrType", 1, {1: "v4", 2: "v6"}),
                   MultipleTypeField([_ipv4, _ipv6], StrField("nextHop", "")),
                   IntField("srcMask", 0),
                   IntField("dstMask", 0), ]

    def extract_padding(self, p):
        return "", p


class DstAsPath(Packet):
    name = "DstAsPath"
    fields_desc = [IntEnumField("type", 1, {1: "SET", 2: "SEQUENCE"}),
                   IntField("asLen", 0),
                   FieldListField("dstAsPath", [],
                                  IntField("", 0),
                                  count_from=lambda pkt: pkt.asLen), ]

    def extract_padding(self, p):
        return "", p


class SflowFlowExgateway(Packet):
    # SFLFLOW_EX_GATEWAY   = 1003
    name = "SFL_EXGATEWAY"
    _ipv4 = (IPField("bgp_nextHop", "0.0.0.0"), lambda pkt: pkt.addrType == 1)
    _ipv6 = (IP6Field("bgp_nextHop", "::"), lambda pkt: pkt.addrType == 2)
    fields_desc = [IntEnumField("addrType", 1, {1: "v4", 2: "v6"}),
                   MultipleTypeField([_ipv4, _ipv6],
                                     StrField("bgp_nextHop", "")),
                   IntField("myAS", 0),
                   IntField("srcAS", 0),
                   IntField("srcPeerAS", 0),
                   IntField("asLen", 0),
                   PacketListField("dstAsPath", None,
                                   DstAsPath,
                                   count_from=lambda pkt: pkt.asLen),
                   IntField("communitiesLen", 0),
                   FieldListField("communities", [],
                                  IntField("", 0),
                                  count_from=lambda pkt: pkt.communitiesLen),
                   IntField("bgp_localPref", 0), ]

    def extract_padding(self, p):
        return "", p


class SflowFlowHeader(Packet):
    name = "SFL_HEADER"
    """
    XXX SFLHEADER_ETHERNET_ISO8023 only
        parsing would break in other headerProtocol
    """
    fields_desc = [IntField("headerProtocol", 0),
                   IntField("sampledPacketSize", 0),
                   IntField("strippedBytes", 0),
                   #FieldLenField("headerLen", None, fmt='I', length_of="ether"),
                   #PacketLenField("ether", None, Ether,
                   #     length_from=lambda pkt: pkt.headerLen), ]
                   FieldLenField("headerLen",
                                 None, fmt='I',
                                 length_of="header"),
                   StrFixedLenField("header", None,
                                    length_from=lambda pkt: int((pkt.headerLen+3)/4)*4),]

    """ replace in last 2 items if hope to decode this sample header
    FieldLenField("headerLen", None, fmt='I', length_of="ether"),
    PacketLenField("ether", None, Ether,
                    length_from=lambda pkt: pkt.headerLen)
    """

    def extract_padding(self, p):
        return "", p


class SflowElement(Packet):
    name = "Element"
    # implemented element-types
    fields_desc = [IntField("elementType", 0),
                   FieldLenField("fieldLen", None, fmt='I'),
                   ConditionalField(
                       PacketLenField("flowHeader", None,
                                       SflowFlowHeader,
                                       length_from=lambda pkt: pkt.fieldLen),
                       lambda pkt: pkt.elementType == 1),
                   ConditionalField(
                       PacketLenField("flowExSwitch", None,
                                       SflowFlowExswitch,
                                       length_from=lambda pkt: pkt.fieldLen),
                       lambda pkt: pkt.elementType == 1001),
                   ConditionalField(
                       PacketLenField("flowExRouter", None,
                                       SflowFlowExrouter,
                                       length_from=lambda pkt: pkt.fieldLen),
                       lambda pkt: pkt.elementType == 1002),
                   ConditionalField(
                       PacketLenField("flowExGateway", None,
                                       SflowFlowExgateway,
                                       length_from=lambda pkt: pkt.fieldLen),
                       lambda pkt: pkt.elementType == 1003),
                   # not yet implemented types
                   ConditionalField(
                       StrFixedLenField("flowRecord", "",
                                        length_from=lambda pkt: pkt.fieldLen),
                       lambda pkt: pkt.elementType not in (1, 1001, 1002, 1003)),]

    def extract_padding(self, p):
        return "", p


class SflowFlow(Packet):
    name = "Flow"
    fields_desc = [FieldLenField("length", None, fmt='I',
                                 length_of="element"),
                   IntField("generated", 0),
                   IntField("samplerId", 0),
                   IntField("meanSkipCount", 0),
                   IntField("samplePool", 0),
                   IntField("dropEvents", 0),
                   IntField("inputPort", 0),
                   IntField("outputPort", 0),
                   FieldLenField("numElements", None, fmt='I',
                                 count_of="element"),
                   PacketListField("element", None,
                                   SflowElement,
                                   count_from=lambda pkt: pkt.numElements), ]

    def extract_padding(self, p):
        return "", p


class SflowSample(Packet):
    name = "Sflow Sample"
    fields_desc = [IntEnumField("type", 1, {1: "flow", 2: "counter"}),
                   ConditionalField(
                       PacketField("flow", None, SflowFlow),
                       lambda pkt: pkt.type == 1),
                   ConditionalField(
                       PacketField("counter", None, SflowCounter),
                       lambda pkt: pkt.type == 2), ]

    def extract_padding(self, p):
        return "", p

    def mysummary(self):
        # type: () -> str
        return self.sprintf("type %type%")


class SflowDatagram(Packet):
    name = "Sflow Datagram"
    fields_desc = [IntField("datagramVersion", 5),
                   IntField("addressType", 1),
                   IPField("agent", "0.0.0.0"),
                   IntField("agentSubId", 0),
                   IntField("sequenceNo", 0),
                   IntField("sysUpTime", 0),
                   FieldLenField("inPacket", None,
                                 fmt="I", count_of="sflowSample"),
                   PacketListField("sflowSample", None,
                                   SflowSample,
                                   count_from=lambda pkt: pkt.inPacket), ]
    """
    def answers(self, other):
        # type: (Packet) -> int
        if isinstance(other, Ether):
            if self.type == other.type:
                return self.payload.answers(other.payload)
        return 0
    """

    def mysummary(self):
        # type: () -> str
        return self.sprintf("sflow %agent%(%inPacket%):")


bind_layers(UDP, SflowDatagram, dport=6343)
#bind_layers(SflowDatagram, SflowSample)

# end of file
