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
import networkx as nx


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {
            "10.0.0.1": ("10:00:00:00:00:01", 1, 1),  # H1 on s1 port 1
            "10.0.0.2": ("10:00:00:00:00:02", 2, 1),  # H2 on s2 port 1
            "10.0.0.3": ("10:00:00:00:00:03", 3, 1),  # H3 on s3 port 1
            "10.0.0.4": ("10:00:00:00:00:04", 4, 1),  # H4 on s4 port 1
        }
        # Clockwise neighbor port per switch
        # dpid: port that goes clockwise
        self.clockwise_port = {
            1: 2,  # s1 → s2
            2: 2,  # s2 → s3
            3: 2,  # s3 → s4
            4: 2,  # s4 → s1
        }
        self.graph = nx.Graph()
        self.graph.add_edges_from(
            [
                (1, 2),  # s1-s2
                (2, 3),  # s2-s3
                (3, 4),  # s3-s4
                (4, 1),  # s4-s1
            ]
        )
        # (dpid, neighbor_dpid) → out_port
        self.port_map = {
            (1, 2): 2,
            (1, 4): 3,
            (2, 1): 3,
            (2, 3): 2,
            (3, 2): 3,
            (3, 4): 2,
            (4, 3): 3,
            (4, 1): 2,
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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

    def _path_direction(self, path):
        # Lower total "dpid" difference → more clockwise
        return sum((b - a) % 4 for a, b in zip(path[:-1], path[1:]))

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

        # Handle ARP with static mapping
        if arp_pkt:
            self.logger.info("==== Proxy ARP Request ====")
            self.logger.info("ARP: who has %s? Tell %s", arp_pkt.dst_ip, arp_pkt.src_ip)

            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip in self.arp_table:
                target_mac, target_dpid, target_port = self.arp_table[arp_pkt.dst_ip]

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

        # Handle IP packets
        if ip_pkt is None:
            return

        self.logger.info("==== IP Packet-In ====")
        self.logger.info("Datapath: %s, in_port: %s", dpid, in_port)
        self.logger.info("IP src: %s -> dst: %s", ip_pkt.src, ip_pkt.dst)

        # Drop UDP from H1 and H4
        if udp_pkt and ip_pkt.src in ["10.0.0.1", "10.0.0.4"]:
            match = parser.OFPMatch(
                in_port=in_port, eth_type=0x0800, ip_proto=17, ipv4_src=ip_pkt.src
            )
            self.logger.info("H1 can't send UDP to H4, packet dropped", ip_pkt.dst)
            self.add_flow(datapath, 100, match, [])  # drop rule
            return

        dst_mac, dst_dpid, dst_port = self.arp_table.get(ip_pkt.dst, (None, None, None))
        if dst_mac is None:
            self.logger.info("Unknown destination IP: %s", ip_pkt.dst)
            return

        # If at destination switch, send to host
        if dpid == dst_dpid:
            out_port = dst_port
        else:
            all_paths = list(
                nx.all_shortest_paths(self.graph, source=dpid, target=dst_dpid)
            )
            if len(all_paths) > 1:
                if icmp_pkt or tcp_pkt:
                    self.logger.info("Multiple paths found, CLOCKWISE is chosen")
                    chosen_path = min(all_paths, key=self._path_direction)  # clockwise
                elif udp_pkt:
                    self.logger.info(
                        "Multiple paths found, counter-clockwise is chosen"
                    )
                    chosen_path = max(
                        all_paths, key=self._path_direction
                    )  # counter-clockwise
                else:
                    chosen_path = all_paths[0]
            else:
                chosen_path = all_paths[0]

            next_hop = chosen_path[chosen_path.index(dpid) + 1]
            out_port = self.port_map.get((dpid, next_hop))

        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(
            in_port=in_port,
            eth_src=eth.src,
            eth_dst=eth.dst,
            eth_type=0x0800,
            ipv4_src=ip_pkt.src,
            ipv4_dst=ip_pkt.dst,
        )
        self.add_flow(datapath, 10, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data,
        )
        datapath.send_msg(out)
