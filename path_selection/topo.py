# topo.py
# Mininet 自訂多路徑拓樸:
# h1-s1; h2-s2; and switch links:
# s1-s2, s1-s3, s2-s4, s2-s5, s3-s4, s2-s3, s1-s5

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSBridge, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI

class UserMeshTopo(Topo):
    def build(self):
        # switches
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')
        s4 = self.addSwitch('s4', protocols='OpenFlow13')
        s5 = self.addSwitch('s5', protocols='OpenFlow13')

        # hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        # host links
        self.addLink(h1,s1)
        self.addLink(h2,s2)

        # switch links
        self.addLink(s1,s2)
        self.addLink(s1,s3)
        self.addLink(s1,s5)
        self.addLink(s2,s3)
        self.addLink(s2,s4)
        self.addLink(s2,s5)
        self.addLink(s3,s4)

topos = { 'user_mesh': UserMeshTopo }