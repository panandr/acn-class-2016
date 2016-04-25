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

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

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

log = core.getLogger()

class acn_controller(object):
  
  def __init__(self):
    log.info("Started")

    core.openflow_discovery.addListeners(self)
    core.host_tracker.addListeners(self)

    # dictionary that keeps connection/links/hosts/mac_to_port
    # and possibly name of the switch
    # per different datapatch-id
    self.dpid_dict = {}

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
    msg.idle_timeout = timeout
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
    return

  def  learning_microflow_controller(self, dpid, packet, packet_in):
    
    connection = self.dpid_dict[dpid]["connection"]
    self.dpid_dict[dpid]["mac_to_port"][packet.src] = packet_in.in_port

    mac_to_port = self.dpid_dict[dpid]["mac_to_port"]
    # if dst is multicast flood it and return from the method
    if packet.dst.is_multicast:
        log.debug("Switch-{}: Type: {} . host {} --> FLOOD --> host {}".
                 format( str(dpid), pkt.ETHERNET.ethernet.getNameForType(packet.type),str(packet.src), str(packet.dst) ))
        
	self.flood( connection, packet, packet_in)
 
        self.install_rule( connection, 1, packet_in.in_port, packet.src, EthAddr("ff:ff:ff:ff:ff:ff"), of.OFPP_FLOOD, 100, packet.type)

    elif packet.dst in mac_to_port:
        out_port = mac_to_port[packet.dst]

        log.debug("Switch-{}: Type: {} . host {} --> port {} --> host {}".
	          format( dpid,  pkt.ETHERNET.ethernet.getNameForType(packet.type), str(packet.src), str(out_port), str(packet.dst)))
        
        self.resend_packet( connection, packet_in, out_port)
      
        # additionally, install a rule per flow (src, src-port, dst, dst-port)
        self.install_rule( connection, 1, packet_in.in_port, packet.src, packet.dst, out_port, 100, packet.type)
              
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
    self.dpid_dict[dpid_joined].update({"links" : {}})
    self.dpid_dict[dpid_joined].update({"hosts" : {}})
 
  def _handle_PacketIn (self, event):
  
    packet = event.parsed
    packet_in = event.ofp

    dpid = event.dpid
    log.debug("PacketIn message from Switch with dpid = {}".format(dpid))
  
    # self.simple_hub(dpid , packet, packet_in) 
    # self.learning_controller(dpid, packet, packet_in) 
    self.learning_microflow_controller(dpid, packet, packet_in)

  def _handle_LinkEvent (self, event):
    
    link = event.link
    dpid_source = link.dpid1
    dpid_dest = link.dpid2
    
    log.debug("LinkUpdate for Link {}->{}".format(dpid_source, dpid_dest))

  def _handle_HostEvent (self, event):
    return;   

def launch ():
  """
  Starts the component
  """

  pox.log.color.launch()

  pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " +
                        "@@@bold%(message)s@@@normal")
  pox.openflow.discovery.launch() 
  pox.openflow.spanning_tree.launch()
  pox.host_tracker.launch()

  acn = acn_controller()

  def connection_added(event):
    acn.add_connection(event.connection)

  core.openflow.addListenerByName("ConnectionUp", connection_added)

  

