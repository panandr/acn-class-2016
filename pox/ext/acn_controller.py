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
import time
import pox.lib.packet as pkt
import hashlib

log = core.getLogger()

class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}
    
    # Structure to keep flooded packets so as not to re-flood them
    # if the topology has loops
    self.flooded_packets = {}

    # timestamp for cleaning flooded packets
    self.flood_timestamp = time.time()

  def resend_packet (self, packet_in, out_port):
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
    self.connection.send(msg)
  
  def install_rule( self, priority, src_port, src_mac, dst_mac):
    log.debug("Switch-{}: Installing rule src:{} , src_port {}, dst {} -> dst_port {}".
              format( self.connection.dpid, src_mac, src_port, dst_mac, self.mac_to_port[str(dst_mac)]))
    
    # TODO: Maybe do a more fine-grained match ? 
    msg = of.ofp_flow_mod()
    msg.priority = priority
    msg.match = of.ofp_match( in_port = src_port,
			      dl_src  = src_mac,
                              dl_dst  = dst_mac)
    msg.actions.append( of.ofp_action_output( port = self.mac_to_port[str(dst_mac)]))
    self.connection.send(msg)

  
  def flood(self, packet, packet_in):
    
    m = hashlib.md5()
    m.update(str(packet.payload))
    
    if m.digest() in self.flooded_packets:
      return
    else:
      self.flooded_packets[ m.digest()] = 0
      self.resend_packet(packet_in, of.OFPP_ALL)
  
  def policy_controller(self, packet, packet_in):
    return      
        
  def learning_microflow_controller(self, packet, packet_in):
          
    # clear flooded packets every 1 sec
    if (time.time() - self.flood_timestamp > 1):
      log.debug("Switch-{}: Clearing flooding table!".format(str(self.connection.dpid)))
      self.flood_timestamp = time.time()
      self.flooded_packets = {}

    # Update mac-to-port entry, if it does not
    # exist, insert it
    self.mac_to_port[str(packet.src)] = packet_in.in_port
  
    # if dst is multicast flood it and return from the method
    if packet.dst.is_multicast:
        log.debug("Switch-{}: Type: {} . host {} --> FLOOD --> host {}".
                 format( str(self.connection.dpid), pkt.ETHERNET.ethernet.getNameForType(packet.type),str(packet.src), str(packet.dst) ))
        
	self.flood(packet, packet_in)

    elif str(packet.dst) in self.mac_to_port:
        out_port = self.mac_to_port[str(packet.dst)]

        log.debug("Switch-{}: Type: {} . host {} --> port {} --> host {}".
	          format( str(self.connection.dpid),  pkt.ETHERNET.ethernet.getNameForType(packet.type), str(packet.src), str(out_port), str(packet.dst)))
        self.resend_packet(packet_in, out_port)
        
        # additionally, install a rule per flow (src, src-port, dst, dst-port)
        self.install_rule( 1, packet_in.in_port, packet.src, packet.dst)
              
    else:
        log.debug("Switch-{}: Type: {} . host {} --> FLOOD --> host {}".
	          format( str(self.connection.dpid), pkt.ETHERNET.ethernet.getNameForType(packet.type),str(packet.src), str(packet.dst) ))
        
        # flood the packet to all ports
        self.flood(packet, packet_in) 

    return

  def learning_controller(self, packet, packet_in):
          
    # Update mac-to-port entry, if it does not
    # exist, insert it
    self.mac_to_port[str(packet.src)] = packet_in.in_port
 
    # if dst is multicast flood it and return from the method
    if packet.dst.is_multicast:
       log.debug("Switch-{}: Type: {} . host {} --> FLOOD --> host {}".
                 format( str(self.connection.dpid), pkt.ETHERNET.ethernet.getNameForType(packet.type),str(packet.src), str(packet.dst) ))
       self.resend_packet(packet_in, of.OFPP_ALL)
    elif str(packet.dst) in self.mac_to_port:
        out_port = self.mac_to_port[str(packet.dst)]

        log.debug("Switch-{}: Type: {} . host {} --> port {} --> host {}".
	          format( str(self.connection.dpid),  pkt.ETHERNET.ethernet.getNameForType(packet.type), str(packet.src), str(out_port), str(packet.dst)))
        self.resend_packet(packet_in, out_port)
    else:
        log.debug("Switch-{}: Type: {} . host {} --> FLOOD --> host {}".
	          format( str(self.connection.dpid), pkt.ETHERNET.ethernet.getNameForType(packet.type),str(packet.src), str(packet.dst) ))

        self.resend_packet(packet_in, of.OFPP_ALL)

    return

  def learning_hub(self, packet, packet_in):
     
     # send packet to all switch ports except the one 
     # that received it   
     self.resend_packet(packet_in, of.OFPP_ALL)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.

    #self.learning_hub(packet, packet_in)
    #self.learning_controller(packet, packet_in)
    self.learning_microflow_controller(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
