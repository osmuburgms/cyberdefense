from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import json

class IPSController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(IPSController, self).__init__(req, link, data, **config)
        self.my_app_ins = data['my_app']

    @route('ips', '/ips/block', methods=['POST'])
    def block_ip(self, req, **kwargs):
        try:
            body = json.loads(req.body.decode('utf-8'))
            ip_atacante = body.get('ip')
            if not ip_atacante:
                return Response(status=400, body=json.dumps({"error": "IP missing"}))
            
            print(f"🛑 [API] Orden de bloqueo recibida para IP: {ip_atacante}")
            self.my_app_ins.agregar_regla_bloqueo_global(ip_atacante)
            return Response(status=200, body=json.dumps({"status": "blocked", "ip": ip_atacante}))
        except Exception as e:
            return Response(status=500, body=json.dumps({"error": str(e)}))

class IPSSDNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'dpset': dpset.DPSet
    }

    def __init__(self, *args, **kwargs):
        super(IPSSDNController, self).__init__(*args, **kwargs)
        self.wsgi = kwargs['wsgi']
        self.dpset = kwargs['dpset']
        self.wsgi.register(IPSController, {'my_app': self})
        self.mac_to_port = {}

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def _event_dp_handler(self, ev):
        dp = ev.dp
        if ev.enter:
            print(f"✅ [SDN] Switch OVS conectado y registrado (DPID: {dp.id})")
            self.install_table_miss(dp)
        else:
            print(f"❌ [SDN] Switch OVS desconectado (DPID: {dp.id})")

    def install_table_miss(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id is not None:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def agregar_regla_bloqueo_global(self, ip_atacante):
        switches = self.dpset.get_all()
        if not switches:
            print("⚠️ [ERROR] No hay switches registrados. La regla no pudo instalarse.")
            return
        
        for dpid, datapath in switches:
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_atacante)
            actions = [] 
            self.add_flow(datapath, 100, match, actions)
            print(f"🛑 [IPS] Regla DROP aplicada para IP {ip_atacante} en DPID {dpid}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == 0x88cc: return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
