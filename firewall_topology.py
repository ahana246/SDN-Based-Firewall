# firewall_topology.py
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

class FirewallTopo(Topo):
    """
    Star topology: 1 switch connected to 4 hosts.
    We use RemoteController so Mininet connects to our
    separately-running Ryu controller on port 6653.
    """
    def build(self):
        # Add the switch
        s1 = self.addSwitch('s1')

        # Add 4 hosts with fixed IPs and MACs
        # Fixed MACs make it easier to identify hosts in Wireshark/logs
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        # Connect every host to the switch (star topology)
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)

if __name__ == '__main__':
    setLogLevel('info')
    topo = FirewallTopo()
    # RemoteController tells Mininet: "don't create your own controller,
    # connect to one already running at 127.0.0.1:6653"
    net = Mininet(topo=topo, controller=RemoteController)
    net.start()
    CLI(net)    # Opens the "mininet>" prompt
    net.stop()