# firewall_controller.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from firewall_rules import FIREWALL_RULES
import datetime
import os

# Build absolute path to log file so it always writes to the right place
# regardless of which directory ryu-manager is run from
LOG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'logs', 'blocked_packets.log'
)

def write_log(msg):
    """
    Write directly to file with immediate flush.
    We avoid Python's logging module because it can silently
    fail inside Ryu's event loop.
    """
    with open(LOG_PATH, 'a') as f:
        f.write(msg + '\n')
        f.flush()


class SDNFirewall(app_manager.RyuApp):
    """
    SDN Firewall Controller.

    Combines two behaviours:
    1. Learning Switch  — learns MAC→port mappings, installs forwarding rules
    2. Firewall         — checks each IP packet against rules, drops if matched
    """

    # Tell Ryu we want OpenFlow version 1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)

        # MAC learning table: {datapath_id: {mac_address: port_number}}
        # Example: {1: {'00:00:00:00:00:01': 1, '00:00:00:00:00:02': 2}}
        self.mac_to_port = {}

        # Write startup marker to log so we know controller launched correctly
        write_log(f"=== Firewall Controller Started at {datetime.datetime.now()} ===")
        self.logger.info("SDN Firewall Controller started. Log: %s", LOG_PATH)

    # =========================================================================
    # EVENT 1: Switch connects to controller (CONFIG_DISPATCHER phase)
    # This fires once when the switch first connects.
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Install the TABLE-MISS flow entry.

        Without this, unmatched packets are silently dropped by the switch.
        With this, unmatched packets are sent to the controller (packet_in).
        Priority 0 = lowest possible, so it only matches when nothing else does.
        """
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        # Match ALL packets (empty match = wildcard everything)
        match = parser.OFPMatch()

        # Action: send to controller, don't buffer the packet
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]

        # Install with priority=0 (table-miss)
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("Table-miss flow entry installed on switch %s", datapath.id)

    # =========================================================================
    # HELPER: Install a forwarding flow rule
    # =========================================================================
    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0, hard_timeout=0):
        """
        Send an OFPFlowMod message to install a flow rule on the switch.

        idle_timeout: rule deleted if no matching packet for N seconds (0=never)
        hard_timeout: rule deleted after N seconds regardless (0=never)
        """
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        # APPLY_ACTIONS means execute actions immediately (not via action set)
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions
        )]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    # =========================================================================
    # HELPER: Install a DROP flow rule
    # =========================================================================
    def add_drop_flow(self, datapath, priority, match):
        """
        Install a flow rule that drops matching packets.

        The trick: an empty action list [] means DROP.
        We set idle_timeout=60 so the rule expires after 60s of inactivity,
        keeping the flow table clean.
        """
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, []   # Empty = DROP
        )]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,      # priority=100 overrides forwarding rules (priority=10)
            match=match,
            instructions=inst,
            idle_timeout=60,        # Auto-expire after 60s of no matching traffic
            hard_timeout=0
        )
        datapath.send_msg(mod)

    # =========================================================================
    # HELPER: Check packet against firewall rules
    # =========================================================================
    def is_blocked(self, src_ip, dst_ip, proto, dst_port):
        """
        Walk through FIREWALL_RULES and return True if any block rule matches.

        A rule matches only if ALL its non-None fields match the packet.
        None fields are wildcards — they match anything.
        """
        for rule in FIREWALL_RULES:
            if rule['action'] != 'block':
                continue
            # Each condition: skip this rule if field is set AND doesn't match
            if rule['src_ip'] and rule['src_ip'] != src_ip:
                continue
            if rule['dst_ip'] and rule['dst_ip'] != dst_ip:
                continue
            if rule['proto'] and rule['proto'] != proto:
                continue
            if rule['port'] and rule['port'] != dst_port:
                continue
            # All fields matched — this packet should be blocked
            return True
        return False

    # =========================================================================
    # EVENT 2: Packet arrives at switch with no matching rule (MAIN_DISPATCHER)
    # This is the core event — fires for every unknown packet.
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Main packet handler — called when switch sends an unmatched packet up.

        Steps:
        1. Parse the packet
        2. Learn the source MAC→port mapping
        3. If IP packet: check firewall rules
           - If blocked: log it, install drop rule, discard packet
           - If allowed: fall through to forwarding
        4. Forward the packet (flood if dst unknown, else targeted output)
        5. If dst MAC is known: install a forwarding flow rule
        """
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = datapath.id          # Datapath ID = switch identifier

        # Parse the raw packet bytes into structured layers
        pkt     = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return  # Not an Ethernet frame, ignore

        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        # --- MAC LEARNING ---
        # Record which port this MAC came in on
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Look up output port for destination MAC
        # If unknown: FLOOD (send out all ports except in_port)
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)

        # --- FIREWALL CHECK (IP packets only) ---
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip   = ip_pkt.src
            dst_ip   = ip_pkt.dst
            proto    = None
            dst_port = None

            # Extract transport layer info if present
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            if tcp_pkt:
                proto    = 'tcp'
                dst_port = tcp_pkt.dst_port
            elif udp_pkt:
                proto    = 'udp'
                dst_port = udp_pkt.dst_port

            # Check against firewall rules
            if self.is_blocked(src_ip, dst_ip, proto, dst_port):
                log_msg = (
                    f"[BLOCKED] {datetime.datetime.now()} | "
                    f"{src_ip} -> {dst_ip} | "
                    f"proto={proto} port={dst_port}"
                )
                write_log(log_msg)
                self.logger.warning(log_msg)

                # Install a DROP rule so future packets are blocked at the switch
                # (without hitting the controller again — more efficient)
                match = parser.OFPMatch(
                    eth_type=0x0800,    # 0x0800 = IPv4
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip
                )
                self.add_drop_flow(datapath, priority=100, match=match)
                return  # Discard this packet — do NOT forward

        # --- FORWARDING ---
        actions = [parser.OFPActionOutput(out_port)]

        # If we know the output port, install a forwarding rule
        # so future packets bypass the controller entirely
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(
                datapath, priority=10,
                match=match, actions=actions,
                idle_timeout=30     # Expire after 30s of inactivity
            )

        # Send this specific packet out (it's already in flight, can't wait for rule)
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)