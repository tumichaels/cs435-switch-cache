from p4app import P4Mininet
from mininet.topo import SingleSwitchTopo
from mininet.cli import CLI
import sys
import time

topo = SingleSwitchTopo(2)
net = P4Mininet(program='cache.p4', topo=topo)
net.start()

s1, h1, h2 = net.get('s1'), net.get('h1'), net.get('h2')

h1.describe()
h2.describe()

# TODO Populate IPv4 forwarding table
s1.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                    match_fields={'hdr.ipv4.dstAddr': [h1.defaultIntf().IP(), 32]},
                    action_name='MyIngress.ipv4_forward',
                    action_params={'dstAddr': h1.defaultIntf().MAC(),
                                   'port': 1})

s1.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                    match_fields={'hdr.ipv4.dstAddr': [h2.defaultIntf().IP(), 32]},
                    action_name='MyIngress.ipv4_forward',
                    action_params={'dstAddr': h2.defaultIntf().MAC(),
                                   'port': 2})
                                   
# TODO Populate the cache table

s1.insertTableEntry(table_name='MyIngress.kvp_sw_exact',
                    match_fields={'hdr.kvp_req.key': 3},
                    action_name='MyIngress.kvp_redirect',
                    action_params={'value': 33})

# Start the server with some key-values
server = h1.popen('./server.py 1=11 2=22', stdout=sys.stdout, stderr=sys.stdout)
time.sleep(0.4) # wait for the server to be listenning

out = h2.cmd('./client.py 10.0.0.1 1') # expect a resp from server
assert out.strip() == "11"
out = h2.cmd('./client.py 10.0.0.1 1') # expect a value from switch cache (registers)
assert out.strip() == "11"
out = h2.cmd('./client.py 10.0.0.1 2') # resp from server
assert out.strip() == "22"
out = h2.cmd('./client.py 10.0.0.1 3') # from switch cache (table)
assert out.strip() == "33"
out = h2.cmd('./client.py 10.0.0.1 123') # resp not found from server
assert out.strip() == "NOTFOUND"

server.terminate()
