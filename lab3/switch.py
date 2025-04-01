# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, ether_types, arp


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        # self.logger.info("Init has been called")
        self.mac_to_port = {}
        self.arp_table = {
            "10.0.0.1": ("10:00:00:00:00:01", 1, 1),  # H1 on s1 port 1
            "10.0.0.2": ("10:00:00:00:00:02", 2, 1),  # H2 on s2 port 1
            "10.0.0.3": ("10:00:00:00:00:03", 3, 1),  # H3 on s3 port 1
            "10.0.0.4": ("10:00:00:00:00:04", 4, 1),  # H4 on s4 port 1
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        # self.logger.info("Switch features handler has been called")
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # self.logger.info("Add flow has been called")

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, instructions=inst
            )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        arp_pkt = pkt.get_protocol(arp.arp)

        dst = eth.dst
        src = eth.src

        if arp_pkt:
            self.logger.info("==== Proxy ARP Request ====")
            self.logger.info("ARP: who has %s? Tell %s", arp_pkt.dst_ip, arp_pkt.src_ip)

            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip in self.arp_table:
                # Get target MAC and respond
                target_mac, target_dpid, target_port = self.arp_table[arp_pkt.dst_ip]

                # Build ARP reply
                arp_reply = packet.Packet()
                arp_reply.add_protocol(
                    ethernet.ethernet(
                        ethertype=eth.ethertype, src=target_mac, dst=eth.src
                    )
                )
                arp_reply.add_protocol(
                    arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=target_mac,
                        src_ip=arp_pkt.dst_ip,
                        dst_mac=eth.src,
                        dst_ip=arp_pkt.src_ip,
                    )
                )
                arp_reply.serialize()

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=arp_reply.data,
                )
                datapath.send_msg(out)
                self.logger.info("Sent ARP reply to %s (%s)", arp_pkt.src_ip, eth.src)
            return

        if ip_pkt:
            self.logger.info("IPv4 src: %s -> dst: %s", ip_pkt.src, ip_pkt.dst)

        if tcp_pkt:
            self.logger.info(
                "TCP src_port: %s -> dst_port: %s", tcp_pkt.src_port, tcp_pkt.dst_port
            )
            self.logger.info("TCP flags: 0x%02x", tcp_pkt.bits)

        if udp_pkt:
            self.logger.info(
                "UDP src_port: %s -> dst_port: %s", udp_pkt.src_port, udp_pkt.dst_port
            )

        if icmp_pkt:
            self.logger.info("ICMP type: %s, code: %s", icmp_pkt.type, icmp_pkt.code)

    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def _packet_in_handler(self, ev):
    #     self.logger.info("Packet in handler has been called")
    #     # If you hit this you might want to increase
    #     # the "miss_send_length" of your switch
    #     if ev.msg.msg_len < ev.msg.total_len:
    #         self.logger.debug(
    #             "packet truncated: only %s of %s bytes",
    #             ev.msg.msg_len,
    #             ev.msg.total_len,
    #         )
    #     msg = ev.msg
    #     datapath = msg.datapath
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
    #     in_port = msg.match["in_port"]
    #
    #     pkt = packet.Packet(msg.data)
    #     eth = pkt.get_protocols(ethernet.ethernet)[0]
    #
    #     if eth.ethertype == ether_types.ETH_TYPE_LLDP:
    #         # ignore lldp packet
    #         return
    #     dst = eth.dst
    #     src = eth.src
    #
    #     dpid = format(datapath.id, "d").zfill(16)
    #     self.mac_to_port.setdefault(dpid, {})
    #
    #     self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
    #
    #     # learn a mac address to avoid FLOOD next time.
    #     self.mac_to_port[dpid][src] = in_port
    #
    #     if dst in self.mac_to_port[dpid]:
    #         out_port = self.mac_to_port[dpid][dst]
    #     else:
    #         out_port = ofproto.OFPP_FLOOD
    #
    #     actions = [parser.OFPActionOutput(out_port)]
    #
    #     # install a flow to avoid packet_in next time
    #     if out_port != ofproto.OFPP_FLOOD:
    #         match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
    #         # verify if we have a valid buffer_id, if yes avoid to send both
    #         # flow_mod & packet_out
    #         if msg.buffer_id != ofproto.OFP_NO_BUFFER:
    #             self.add_flow(datapath, 1, match, actions, msg.buffer_id)
    #             return
    #         else:
    #             self.add_flow(datapath, 1, match, actions)
    #     data = None
    #     if msg.buffer_id == ofproto.OFP_NO_BUFFER:
    #         data = msg.data
    #
    #     out = parser.OFPPacketOut(
    #         datapath=datapath,
    #         buffer_id=msg.buffer_id,
    #         in_port=in_port,
    #         actions=actions,
    #         data=data,
    #     )
    #     datapath.send_msg(out)
