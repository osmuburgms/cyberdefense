from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
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
    """Controlador IPS; OVS_NORMAL aplica el aprendizaje y las VLAN de acceso."""
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
        # El pipeline NORMAL de OVS respeta los tags de acceso y aprende por
        # VLAN. El aprendizaje manual/FLOOD del controlador podría mezclar L2.
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
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

