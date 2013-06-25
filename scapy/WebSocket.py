#!/usr/bin/env python 

# scapy.contrib.description = WebSocket
# scapy.contrib.status = loads

"""
WebSocket Protocol (RFC6455)

Copyright 2012-2013, Mike Shema <mike@deadliestwebattacks.com>
Referenced in http://deadliestwebattacks.com/2013/03/08/rsa-us-2013-asec-f41-slides/

This program is published under the GPLv2 license.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
"""

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP

# RFC6455 section 5.2
_ws_opcode_names = {
    0 : "continuation_frame",
    1 : "text_frame",
    2 : "binary_frame",
    3 : "reserved_non_control3",
    4 : "reserved_non_control4",
    5 : "reserved_non_control5",
    6 : "reserved_non_control6",
    7 : "reserved_non_control7",
    8 : "connection_close",
    9 : "ping",
  0xa : "pong",
  0xb : "reserved_controlB",
  0xc : "reserved_controlC",
  0xd : "reserved_controlD",
  0xe : "reserved_controlE",
  0xf : "reserved_controlF"
}

class WebSocket(Packet):
  name = "WebSocket"
  fields_desc = [ FlagsField("flags", 0, 4, ["RSV3", "RSV2", "RSV1", "FIN"]),
                  BitEnumField("opcode", 0, 4, _ws_opcode_names),
                  BitField("mask_flag", 0, 1),
                  BitField("length", 0, 7),
                  ConditionalField(BitField("length16", None, 16), lambda pkt:pkt.length == 126),
                  ConditionalField(BitField("length64", None, 64), lambda pkt:pkt.length == 127),
                  ConditionalField(XIntField("mask", 0), lambda pkt:pkt.mask_flag == 1),
                  StrLenField("frame_data", None,
                              length_from=lambda pkt:(pkt.length64 if pkt.length64 else
                                                      pkt.length16 if pkt.length16 else
                                                      pkt.length))
                ]

  def guess_payload_class(self, payload):
    if isinstance(self.underlayer, TCP):
      return WebSocket
    else:
      return Packet.guess_payload_class(self, payload)

  def post_dissection(self, pkt):
    if(pkt.mask_flag == 1 and pkt.frame_data is not None):
      demask = array.array('I', [pkt.mask >> 24 & 0xff, pkt.mask >> 16 & 0xff, pkt.mask >> 8 & 0xff, pkt.mask & 0xff])
      unmasked = ''
      for i, c in enumerate(pkt.frame_data):
        unmasked += chr(ord(c) ^ (demask[i % 4]))

      pkt.frame_data = unmasked
      return pkt
    else:
      pass

bind_layers(TCP, WebSocket, dport=80)
