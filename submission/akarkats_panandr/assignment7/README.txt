In our controller we use the spanning tree and the discovery module of POX controller. Specifically, for our controllers to work 
when we start the topology we need to wait some seconds in order for the spanning tree module to activate, create the spanning tree
and disable specific ports to the switches according to the calculated spanning tree.

The discovery module so as to be able to discover the topology of the network by using LLDP packets. Our implementation also subscribes to
LinkEvent events so as to be able to associate links with switches, and in general be informed about the whole topology.

Furthermore, we also track hosts by the first arp request/reply we see from them that arrived on a switch. This way our controller knows all the 
links and the hosts of the topology.
