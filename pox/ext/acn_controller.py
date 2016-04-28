# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr,EthAddr,parse_cidr
import time
import pox.lib.packet as pkt
import hashlib
import pox.openflow.spanning_tree
from pox.core import core
import pox.openflow.discovery
import pox.host_tracker.host_tracker
import pox.log.color
import pox.log
import sys

H1 = "10.0.0.1"
H2 = "10.0.0.2"
H3 = "10.0.0.3"
H4 = "10.0.0.4"

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

    core.openflow_discovery.addListeners(self)

    # dictionary that keeps connection/links/hosts/mac_to_port
    # and possibly name of the switch. This dictionary holds
    # whatever state we need to store per switch
    # switches are recognized with their datapath-ids
    # dpid { hosts : {}, 
    #        links : {},
    #        connection : {},
    #        mac_to_port: {}
    #      }
    self.dpid_dict = {}

    # hosts observed in the networks (IPs), for each
    # host only keep the dpid which connects on and the 
    # port of the dpit that connects on.
    self.hosts = {}

  # Tracks a host, specifically for ARM requests/replies
  # if an host ip has never been observed it associates this 
  # ip with the switch and the incoming port on the switch.
  # If an ip has already been tracked in another switch then it
  # does nothing. DOES NOT support host mobility
  def track_host(self, packet, packet_in, dpid):
    
    if packet.type == packet.ARP_TYPE:

      src_ip = packet.payload.protosrc      
      if src_ip not in self.hosts:
        log.debug("DISCOVERED host with ip {} at switch with dpid {}".format(src_ip, dpid))

        self.hosts[src_ip] = dpid, packet_in.in_port   
        self.dpid_dict[dpid]["hosts"].append(src_ip.toStr())
    
    return
     
  
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


  def install_rule( self, connection, priority, src_port, src_mac, dst_mac, out_port, timeout, dl_type):
    log.debug("Switch-{}: Installing rule src:{} , src_port {}, dst {} -> dst_port {}".
              format( connection.dpid, src_mac, src_port, dst_mac, out_port))
    
    # TODO: Maybe do a more fine-grained match ? 
    msg = of.ofp_flow_mod()
    msg.priority = priority
    msg.match = of.ofp_match( in_port = src_port,
			      dl_src  = src_mac,
                              dl_dst  = dst_mac,
  			      dl_type = dl_type)
    msg.hard_timeout = timeout
    msg.actions.append( of.ofp_action_output( port = out_port))
    connection.send(msg)


  def resend_packet (self, conn, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    conn.send(msg)
  
  def flood(self, connection, packet, packet_in):
    
    self.resend_packet(connection, packet_in, of.OFPP_FLOOD)  

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

      log.debug("Received IP packet from {} to {}, implementing policy!".format(src_ip, dst_ip))
     
      # implementing H1 H4 s3, H2 H4 s3 
      if (H1 == src_ip.toStr() or H2 == src_ip.toStr()) and H4 == dst_ip:

        log.debug("Implement policy from {} to {}. Should pass from upper switch".format(src_ip, dst_ip)) 
        
        # Can only infer switch identity only for hosts connected to us :(
        # if we are S1 install rule to send to S3 (switch with no hosts)
        if H1 in hosts or H2 in hosts:
 	  log.debug("In S1!")
            
          # should pass from S3, find link which dpid has no hosts :) 
          for link in links:
            next_dpid = link.dpid2
            own_port  = link.port1
            # check if link dictionary is empty for this dpid, if yes it is the right switch (S3)
            if not self.dpid_dict[next_dpid]["hosts"]:
              break

          log.debug("Installing flow at S1 for S3!")           
          self.install_ip_policy( connection, dpid, 1, packet_in.in_port, src_ip, dst_ip, own_port, GLOBAL_TIMEOUT)
	  self.resend_packet( connection, packet_in, own_port)

        # if we are S2 install rule to send directly to H4  
        elif H3 in hosts or H4 in hosts:
          log.debug("In S2!")
          
          # retrieve host data from hosts dictionary  
          dpid, own_port = self.hosts[dst_ip]

          log.debug("Installing rule and forwarding data to host!") 
          self.install_ip_policy( connection, dpid, 1, packet_in.in_port, src_ip, dst_ip, own_port, GLOBAL_TIMEOUT)
	  self.resend_packet( connection, packet_in, own_port)

        # if we are S3 install rule to send to S2 (switch with hosts H3,H4)
        else:
          log.debug("In S3!")

          for link in links:
            next_dpid = link.dpid2
            own_port  = link.port1
            # check if link dictionary is empty for this dpid, if yes it is the right switch (S3)
            if H3 in self.dpid_dict[next_dpid]["hosts"] or H4 in self.dpid_dict[next_dpid]["hosts"]:
              break

          log.debug("Installing flow for host!")           
          self.install_ip_policy( connection, dpid, 1, packet_in.in_port, src_ip, dst_ip, own_port, GLOBAL_TIMEOUT)
	  self.resend_packet( connection, packet_in, own_port)
           
      else:
        if H1 in hosts or H2 in hosts:
          log.debug("In S1")
        elif H3 in hosts or H4 in hosts:
          log.debug("In S2")
        else:
          log.debug("In S3") 

        # if dst_ip is connected to switch forward to host and install rule
        if dst_ip.toStr() in hosts: 
           dpid, own_port = self.hosts[dst_ip]
           
           log.debug("Installing rule and forwarding data to host!") 
           self.install_ip_policy( connection, dpid, 1, packet_in.in_port, src_ip, dst_ip, own_port, GLOBAL_TIMEOUT)
 	   self.resend_packet( connection, packet_in, own_port)
	else:
          
          # find dpid which host is connected to, from links to us
          for link in links:
            next_dpid = link.dpid2
            own_port  = link.port1
           
            # check in dpid connected to us if dst_ip is conencted to it, if yes install rule and forward
            if dst_ip.toStr() in self.dpid_dict[next_dpid]["hosts"]:
              break
 
          log.debug("Installing flow for host!")           
          self.install_ip_policy( connection, dpid, 1, packet_in.in_port, src_ip, dst_ip, own_port, GLOBAL_TIMEOUT)
	  self.resend_packet( connection, packet_in, own_port)
    else:
      self.learning_microflow_controller(dpid, packet, packet_in)
    
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

  def simple_hub(self, dpid, packet, packet_in):
	     
    connection = self.dpid_dict[dpid]["connection"]
    
    self.flood(connection, packet, packet_in);

  def add_connection(self, conn):
    
    dpid_joined = conn.dpid
	
    log.info("ConnectionUp message for Switch with DPID {}".format(dpid_joined))
    
    conn.addListeners(self)

    self.dpid_dict.update({dpid_joined : {}})
    self.dpid_dict[dpid_joined].update({"connection" : conn})
    self.dpid_dict[dpid_joined].update({"mac_to_port" : {}})
    self.dpid_dict[dpid_joined].update({"links" : []})
    self.dpid_dict[dpid_joined].update({"hosts" : []})

  def remove_connection(self, conn):

    dpid_removed = conn.dpid
    log.info("ConnectionDown message for Switch with DPID {}".format(dpid_removed))
 
    self.dpid_dict.pop( dpid_removed , None)
    self.hosts = {k: v for k, v in self.hosts.iteritems() if v[0] != dpid_removed}

  def _handle_PacketIn (self, event):
  
    packet = event.parsed
    packet_in = event.ofp

    dpid = event.dpid
    log.debug("PacketIn message from Switch with dpid = {}".format(dpid))
  
    self.track_host(packet, packet_in, dpid)

    # self.simple_hub(dpid , packet, packet_in) 
    # self.learning_controller(dpid, packet, packet_in) 
    self.learning_microflow_controller(dpid, packet, packet_in)
    # self.policy_controller(dpid, packet, packet_in)

  def _handle_LinkEvent (self, event):
    
    link = event.link

    dpid_source = link.dpid1
    dpid_dest = link.dpid2
    port_source = link.port1
    port_dest = link.port2

    if event.added:
      log.debug("Link added for switches S-{}:port-{} --> S-{}:port-{}".format(dpid_source, port_source, dpid_dest, port_dest))
      self.dpid_dict[dpid_source]["links"].append(link)    
    else:
      log.debug("Link removed for switches S-{}:port-{} --> S-{}:port-{}".format(dpid_source, port_source, dpid_dest, port_dest))

  def _handle_HostEvent (self, event):
    return;   

def launch ():
  """
  Starts the component
  """

  pox.log.color.launch()

  pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " +
                        "@@@bold%(message)s@@@normal")

  # boot up discovery module and spanning tree module
  # used by our code
  pox.openflow.discovery.launch() 
  pox.openflow.spanning_tree.launch()

  # create acn_controller object once
  acn = acn_controller()

  # set up handlers for connection up and connection down
  def connection_added(event):
    acn.add_connection(event.connection)
  def connection_removed(event):
    acn.remove_connection(event.connection)

  core.openflow.addListenerByName("ConnectionUp", connection_added)
  core.openflow.addListenerByName("ConnectionDown", connection_removed)

  

