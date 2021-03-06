from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr,EthAddr,parse_cidr
import pox.lib.packet as pkt
import pox.openflow.spanning_tree
from pox.core import core
import pox.openflow.discovery
import pox.host_tracker.host_tracker
import pox.log.color
import pox.log

import time
import hashlib
import sys

import networkx as nx

log = core.getLogger()
GLOBAL_TIMEOUT = 10

# This is our controller object. In our implementation there is only one Python Object responsible
# for handling all related events.
# The acn_controller handles PacketIn events from all connections, LinkEvents which denote if a link
# is up or down.
# Also our controller tracks for each switch the links and hosts connected to it, as well as wcich 
# mac addresses reside behind each port.

class acn_controller(object):
  
  def __init__(self):
    log.info("Initializing acn controller. Registering listeners for discovery module!")

    # Add listeners for LinkEvent published by the
    # openflow_discovery module.
    core.openflow_discovery.addListeners(self)

    # Dictionary that keeps connection/links/hosts/mac_to_port
    # and possibly name of the switch. This dictionary holds
    # whatever state we need to store per switch
    # switches are recognized with their datapath-ids
    # dpid { hosts : {}, 
    #        links : {},
    #        connection : {},
    #        mac_to_port: {}
    #      }
    self.dpid_dict = {}

    # Hosts observed in the networks (IPs), for each
    # host only keep the dpid which connects on and the 
    # port of the dpit that connects on.
    self.hosts = {}

    # contains the implemented policies for the controller
    # Policies are of the form: 
    # (src_ip, dest_ip, dpid)
    # where: src_ip: The source host IP
    #        dst_ip: The destination host IP
    #        dpid  : The dpid of the switch the traffic has to pass through
    # 
    # The dictionary maps a hash (src_ip, dst_ip) to the dpid of the switch
    self.policies = {}

    # Network graph
    self.graph = nx.Graph()

    # Parses policies from files and returns a dictionary as described above
    # Sanity is assumed regarding the contents of the file (no checks).
    with open('policies.txt', 'r') as f:
      for line in f:
          if line[0] == '#' or line.strip() == '':
            continue
          src_ip, dst_ip, dpid = line.split()
          log.info("Parsed policy {} -> {} via {}".format(src_ip, dst_ip, dpid))
          self.policies[(src_ip, dst_ip)] = int(dpid)
    
  # Tracks a host, specifically for ARP requests/replies
  # if an host ip has never been observed it associates this 
  # ip with the switch and the incoming port on the switch.
  # If an ip has already been tracked in another switch then it
  # does nothing. DOES NOT support host mobility
  # It only looks arp packets, request or replies.
  def track_host(self, packet, packet_in, dpid):
    
    if packet.type == packet.ARP_TYPE:

      src_ip = packet.payload.protosrc      
      if src_ip not in self.hosts:
        log.debug("DISCOVERED host with ip {} at switch with dpid {}".format(src_ip, dpid))

        self.hosts[src_ip] = dpid, packet_in.in_port   
        self.dpid_dict[dpid]["hosts"].append(src_ip.toStr())
    
    return
     
  # Installs an IP policy on specific switch. Connection is the 
  # connection object created upon each new ConnectionUp event
  # which is stored in our controller.
  # Rules installed match in_port, src_ip, dst_ip --> out_port
  def install_ip_policy(self, connection, dpid, priority, in_port, src_ip, dst_ip, out_port, timeout):
    
    msg = of.ofp_flow_mod()
    msg.priority = priority
    msg.match = of.ofp_match( dl_type=0x800,
                              in_port = in_port,
                              nw_src = src_ip.toStr(),
                              nw_dst = dst_ip.toStr())
    msg.hard_timeout = timeout
    msg.actions.append( of.ofp_action_output( port = out_port))

    connection.send(msg)

  # Installs a layer-2 based rule on a switch. Connection is the 
  # connection object created upon each new ConnectionUp event
  # and is stored into our controller.
  # Installed rules match in_port, source mac, destination mac, protocol type (ARP/IP/..) -> out_port
  def install_rule( self, connection, priority, src_port, src_mac, dst_mac, out_port, timeout, dl_type):
    log.debug("Switch-{}: Installing rule src:{} , src_port {}, dst {} -> dst_port {}".
              format( connection.dpid, src_mac, src_port, dst_mac, out_port))
    
    msg = of.ofp_flow_mod()
    msg.priority = priority
    msg.match = of.ofp_match( in_port = src_port,
			      dl_src  = src_mac,
                              dl_dst  = dst_mac,
  			      dl_type = dl_type)
    msg.hard_timeout = timeout
    msg.actions.append( of.ofp_action_output( port = out_port))
    connection.send(msg)

  # Resends a packet that a switch has 
  # sent to controller to an output port.
  def resend_packet (self, conn, packet_in, out_port):

    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    conn.send(msg)

  # Floods a packet with OFPP_FLOOD  
  def flood(self, connection, packet, packet_in):
    
    self.resend_packet(connection, packet_in, of.OFPP_FLOOD)  

  # Policy controller that implements Question 4.3
  # Our controler works with the topology of figure 2
  # and works without fixed mac addresses or datapath ids.
  # We implement the policies as described in the assignments.
  # Our Implementation enforces policies ONLY on IP traffic
  # and not layer-2 only traffic like ARP (etc).
  # Basically, for each incoming packet we need to figure out the 
  # output port by inspecting the whole topology (links, hosts)
  # That our controller is aware of.
  def policy_controller(self, dpid, packet, packet_in):
  
    connection = self.dpid_dict[dpid]["connection"]
    mac_to_port = self.dpid_dict[dpid]["mac_to_port"]


    # if protocol is IP then implement policies 
    # for all other traffic etc. ARP implement l2 switch
    if packet.type == packet.IP_TYPE: 
   
      ip_packet = packet.payload
      src_ip = ip_packet.srcip
      dst_ip = ip_packet.dstip  
      
      hosts = self.dpid_dict[dpid]["hosts"]
      links = self.dpid_dict[dpid]["links"]

      # This will be the path of switches that will be chosen
      chosen_path = []

      src_switch, src_port = self.hosts[src_ip]
      dst_switch, dst_port = self.hosts[dst_ip]
      
      # Check to see if we have to apply policy
      if (src_ip.toStr(), dst_ip.toStr()) in self.policies:
        policy_dpid = self.policies[src_ip.toStr(), dst_ip.toStr()]
        log.debug("Have to implement policy from {} to {} through switch {}".format(src_ip.toStr(), dst_ip.toStr(), policy_dpid))
       
        # Get all simple paths between the switches connected to the hosts
        simple_paths = nx.all_simple_paths(self.graph, src_switch, dst_switch)
        for simple_path in simple_paths:
          if policy_dpid in simple_path:
            chosen_path = simple_path
            break

        if chosen_path == []:
          log.info("Could not satisfy policy. Choosing shortest path!")     
          chosen_path = nx.shortest_path(self.graph, src_switch, dst_switch)
      else:
        log.debug("Have to use shortest path!")
        chosen_path = nx.shortest_path(self.graph, src_switch, dst_switch)

      log.debug("Will use path:")
      log.debug(chosen_path)

      chosen_edges = [(chosen_path[i], chosen_path[i+1]) for i in xrange(0, len(chosen_path) - 1)]
 
      edge_path = []
      switch_order = chosen_path
      for edge in chosen_edges:
        port1= self.graph[edge[0]][edge[1]]['ports'][edge[0]]
        port2= self.graph[edge[0]][edge[1]]['ports'][edge[1]]
        edge_path.append((port1, port2))
        
      edge_path.insert(0, (1, src_port))
      edge_path.append((dst_port, 1))

      # Install IP rules for all the switches in the path
      for i in xrange(0, len(edge_path)-1):
        switch_dpid = switch_order[i]
        switch_connection = self.dpid_dict[switch_dpid]["connection"]
        src_port, dst_port = (edge_path[i][1], edge_path[i+1][0])
        log.debug("Installing policy on switch {}. {} -> {} with ports {} -> {}".format(switch_dpid, src_ip, dst_ip, src_port, dst_port))
        self.install_ip_policy(switch_connection, switch_dpid, 1000, src_port, src_ip, dst_ip, dst_port, 1000)

      self.resend_packet(connection, packet_in, edge_path[1][0])
    else:
      # Packet is not IP
      self.learning_microflow_controller(dpid, packet, packet_in)
    
  # Implements the microflow learning controller of 4.2.3 question.
  # Specifically, we install flow rules on switches related to 
  # src mac, dest mac, in-port AND protocol used (arp/ipv6/ip etc)
  #
  def  learning_microflow_controller(self, dpid, packet, packet_in):
    
    connection = self.dpid_dict[dpid]["connection"]
    self.dpid_dict[dpid]["mac_to_port"][packet.src] = packet_in.in_port

    mac_to_port = self.dpid_dict[dpid]["mac_to_port"]
    # if dst is multicast flood it and return from the method
    if packet.dst.is_multicast:
        log.debug("Switch-{}: Type: {} . host {} --> FLOOD --> host {}".
                 format( str(dpid), pkt.ETHERNET.ethernet.getNameForType(packet.type),str(packet.src), str(packet.dst) ))
        
	self.flood( connection, packet, packet_in)
 
        self.install_rule( connection, 1, packet_in.in_port, packet.src, EthAddr("ff:ff:ff:ff:ff:ff"), of.OFPP_FLOOD, 200, packet.type)

    elif packet.dst in mac_to_port:
        out_port = mac_to_port[packet.dst]

        log.debug("Switch-{}: Type: {} . host {} --> port {} --> host {}".
	          format( dpid,  pkt.ETHERNET.ethernet.getNameForType(packet.type), str(packet.src), str(out_port), str(packet.dst)))
        
        self.resend_packet( connection, packet_in, out_port)
      
        # additionally, install a rule per flow (src, src-port, dst, dst-port)
        self.install_rule( connection, 1, packet_in.in_port, packet.src, packet.dst, out_port, GLOBAL_TIMEOUT, packet.type)
              
    else:
        log.debug("Switch-{}: Type: {} . host {} --> FLOOD --> host {}".
	          format( dpid, pkt.ETHERNET.ethernet.getNameForType(packet.type),str(packet.src), str(packet.dst) ))
        
        # Destination mac of packet not in our dictionary
	# flood the packet.
        self.flood( connection, packet, packet_in) 

    return

  # Implementation of the learning controller.
  # If destination mac is in the dictionary of port-mac
  # of a specific switch then forward it to a specific
  # port otherwise flood it to all ports.
  def learning_controller(self, dpid, packet, packet_in):
          
    connection = self.dpid_dict[dpid]["connection"]
    self.dpid_dict[dpid]["mac_to_port"][packet.src] = packet_in.in_port
 
    mac_to_port = self.dpid_dict[dpid]["mac_to_port"]

    # if dst is multicast flood it and return from the method
    if packet.dst.is_multicast:
       log.debug("Switch-{}: Type: {} . host {} --> FLOOD --> host {}".
                 format( str(dpid), pkt.ETHERNET.ethernet.getNameForType(packet.type),str(packet.src), str(packet.dst) ))
       
       self.flood(connection, packet, packet_in)

    elif packet.dst in mac_to_port:
        out_port = mac_to_port[packet.dst]

        log.debug("Switch-{}: Type: {} . host {} --> port {} --> host {}".
	          format( str(dpid),  pkt.ETHERNET.ethernet.getNameForType(packet.type), str(packet.src), str(out_port), str(packet.dst)))
        
        # send packet to specific port
        self.resend_packet(connection, packet_in, out_port)
    else:
        log.debug("Switch-{}: Type: {} . host {} --> FLOOD --> host {}".
	          format( str(dpid), pkt.ETHERNET.ethernet.getNameForType(packet.type),str(packet.src), str(packet.dst) ))

        self.flood_packet(connection, packet, packet_in)

    return
  
  # Upon receiving a packet from a switch,
  # flood it to all ports except the port 
  # that it originated from
  def simple_hub(self, dpid, packet, packet_in):
	     
    connection = self.dpid_dict[dpid]["connection"]
    
    self.flood(connection, packet, packet_in);

  # Called upon each new ConnectionUp event.
  # It initializes a new switch it the switch dictionary
  # which we identify by the dpid.
  def add_connection(self, conn):
    
    dpid_joined = conn.dpid
	
    log.info("ConnectionUp message for Switch with DPID {}".format(dpid_joined))
    
    conn.addListeners(self)

    self.dpid_dict.update({dpid_joined : {}})
    self.dpid_dict[dpid_joined].update({"connection" : conn})
    self.dpid_dict[dpid_joined].update({"mac_to_port" : {}})
    self.dpid_dict[dpid_joined].update({"links" : []})
    self.dpid_dict[dpid_joined].update({"hosts" : []})

  # Called upon a ConnectionDown event.
  # It removes a switch from the dictionary and 
  # clears all book-keeping for this specific 
  # switch AND the hosts connected to it.
  def remove_connection(self, conn):

    dpid_removed = conn.dpid
    log.info("ConnectionDown message for Switch with DPID {}".format(dpid_removed))
 
    self.dpid_dict.pop( dpid_removed , None)
    self.hosts = {k: v for k, v in self.hosts.iteritems() if v[0] != dpid_removed}

  # Called upon PacketIn events.
  # It calls the specific controller implementation.
  def _handle_PacketIn (self, event):
  
    packet = event.parsed
    packet_in = event.ofp

    dpid = event.dpid
    log.debug("PacketIn message from Switch with dpid = {}".format(dpid))
  
    self.track_host(packet, packet_in, dpid)

    # self.simple_hub(dpid , packet, packet_in) 
    # self.learning_controller(dpid, packet, packet_in) 
    # self.learning_microflow_controller(dpid, packet, packet_in)
    self.policy_controller(dpid, packet, packet_in)

  # Called upon LinkEvent.
  # This could denot a link addition or removal.
  # In addition we keep this link for switches used by it
  # and other bookkeeping information at our per-switch dictionary.
  def _handle_LinkEvent (self, event):
    
    link = event.link

    dpid_source = link.dpid1
    dpid_dest = link.dpid2
    port_source = link.port1
    port_dest = link.port2

    if event.added:
      log.info("Link added for switches S-{}:port-{} --> S-{}:port-{}".format(dpid_source, port_source, dpid_dest, port_dest))
      self.dpid_dict[dpid_source]["links"].append(link)

      # Update our graph with new nodes/edges
      self.graph.add_edge(dpid_source, dpid_dest, ports = {dpid_source : port_source, dpid_dest : port_dest})
      log.debug("Graph Edges")
      log.debug(self.graph.edges())
 
    else:
      log.debug("Link removed for switches S-{}:port-{} --> S-{}:port-{}".format(dpid_source, port_source, dpid_dest, port_dest))

  # Unused
  def _handle_HostEvent (self, event):
    return;   

def launch ():
  """
  Starts the component
  """

  pox.log.color.launch()

  pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " +
                        "@@@bold%(message)s@@@normal")

  # Boot up discovery module and spanning tree module
  # used by our code. discovery module will provide
  # us with link events, spanning tree module will build a spanning 
  # tree of our topology and disable ports that do not belong to it 
  # on our switches.
  pox.openflow.discovery.launch() 
  pox.openflow.spanning_tree.launch()

  # create acn_controller object once
  acn = acn_controller()

  # set up handlers for connection up and connection down
  def connection_added(event):
    acn.add_connection(event.connection)
  def connection_removed(event):
    acn.remove_connection(event.connection)

  # set up the handlers
  core.openflow.addListenerByName("ConnectionUp", connection_added)
  core.openflow.addListenerByName("ConnectionDown", connection_removed)

  

