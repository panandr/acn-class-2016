from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr,EthAddr,parse_cidr
import time
import pox.lib.packet as pkt
import hashlib
import pox.openflow.spanning_tree

log = core.getLogger()

class Tutorial (object):

  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}
     
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
  
  def install_rule( self, priority, src_port, src_mac, dst_mac, out_port, timeout, dl_type):
    log.debug("Switch-{}: Installing rule src:{} , src_port {}, dst {} -> dst_port {}".
              format( self.connection.dpid, src_mac, src_port, dst_mac, out_port))
    
    # TODO: Maybe do a more fine-grained match ? 
    msg = of.ofp_flow_mod()
    msg.priority = priority
    msg.match = of.ofp_match( in_port = src_port,
			      dl_src  = src_mac,
                              dl_dst  = dst_mac,
  			      dl_type = dl_type)
    msg.idle_timeout = timeout
    msg.actions.append( of.ofp_action_output( port = out_port))
    self.connection.send(msg)

  
  def flood(self, packet, packet_in):
    
    self.resend_packet(packet_in, of.OFPP_FLOOD)
  
  def policy_controller(self, packet, packet_in):
    
    self.mac_to_port[str(packet.src)] = packet_in.in_port
     
    # IP Traffic is handled according to policy.
    # All other traffic is handles by switches as if
    # they are simple learning microflow switches
    if packet.type == packet.IP_TYPE:
      
      # ip_src = packet.
      return
    else:
      self.learning_microflow_controller(packet, packet_in)      
   
    return

  def  learning_microflow_controller(self, packet, packet_in):
    
    # Update mac-to-port entry, if it does not
    # exist, insert it
    self.mac_to_port[str(packet.src)] = packet_in.in_port

    # if dst is multicast flood it and return from the method
    if packet.dst.is_multicast:
        log.debug("Switch-{}: Type: {} . host {} --> FLOOD --> host {}".
                 format( str(self.connection.dpid), pkt.ETHERNET.ethernet.getNameForType(packet.type),str(packet.src), str(packet.dst) ))
        
	self.flood(packet, packet_in)
 
        self.install_rule( 1, packet_in.in_port, packet.src, EthAddr("ff:ff:ff:ff:ff:ff"), of.OFPP_FLOOD, 5, packet.type)

    elif str(packet.dst) in self.mac_to_port:
        out_port = self.mac_to_port[str(packet.dst)]

        log.debug("Switch-{}: Type: {} . host {} --> port {} --> host {}".
	          format( str(self.connection.dpid),  pkt.ETHERNET.ethernet.getNameForType(packet.type), str(packet.src), str(out_port), str(packet.dst)))
        
        self.resend_packet(packet_in, out_port)
      
        # additionally, install a rule per flow (src, src-port, dst, dst-port)
        self.install_rule( 1, packet_in.in_port, packet.src, packet.dst, out_port, 1, packet.type)
              
    else:
        log.debug("Switch-{}: Type: {} . host {} --> FLOOD --> host {}".
	          format( str(self.connection.dpid), pkt.ETHERNET.ethernet.getNameForType(packet.type),str(packet.src), str(packet.dst) ))
        
        # Destination mac of packet not in our dictionary
	# flood the packet.
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
       
       self.flood(packet, packet_in)

    elif str(packet.dst) in self.mac_to_port:
        out_port = self.mac_to_port[str(packet.dst)]

        log.debug("Switch-{}: Type: {} . host {} --> port {} --> host {}".
	          format( str(self.connection.dpid),  pkt.ETHERNET.ethernet.getNameForType(packet.type), str(packet.src), str(out_port), str(packet.dst)))
        
        # send packet to specific port
        self.resend_packet(packet_in, out_port)
    else:
        log.debug("Switch-{}: Type: {} . host {} --> FLOOD --> host {}".
	          format( str(self.connection.dpid), pkt.ETHERNET.ethernet.getNameForType(packet.type),str(packet.src), str(packet.dst) ))

        self.flood_packet(packet, packet_in)

    return

  def hub_controller(self, packet, packet_in):
     
     # send packet to all switch ports except the one 
     # that received it   
    log.debug("Switch-{}: Type: {} . host {} --> FLOOD --> host {}".
	          format( str(self.connection.dpid), pkt.ETHERNET.ethernet.getNameForType(packet.type),str(packet.src), str(packet.dst) ))

    self.flood(packet, packet_in);

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

    self.hub_controller(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  import pox.log.color
  pox.log.color.launch()
  import pox.log
  pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " +
                        "@@@bold%(message)s@@@normal")
  from pox.core import core
  import pox.openflow.discovery
  pox.openflow.discovery.launch()
 
  pox.openflow.spanning_tree.launch()

  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  
  core.openflow.addListenerByName("ConnectionUp", start_switch)

  

