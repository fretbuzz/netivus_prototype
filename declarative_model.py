from pyDatalog import pyDatalog
import ipaddress

# for debugging
import logging
from pyDatalog import pyEngine
pyEngine.Logging = True

# TODO: currently this file can handle basic L1 functionality. Eventually, we'd want to augment it quite significant-
# including some level of L1, L2, L3, and L4 functionality. I think we start by abstracting out the L1-L2 functionality
# and then add in the ACLs, FIBs, and finally the NATS
# (I also think that we need to add the packet headers in when we add the ACLs)

pyDatalog.create_terms('X, Y, Z, S, Q, D, T, link, link_up, can_reach, has_interface, P, P2, all_path, no_interface_mismatch')
pyDatalog.create_terms('cable_intact, is_a_device, link_works, working_link_exists, has_dst_ip, has_src_ip, has_acl')
pyDatalog.create_terms('does_interface_acl_drop_packet, all_paths_packet, packet_allowed, packet_not_dropped_by_link')
# give me all the X so that X is in the range 0..4
#print(X.in_((0,1,2,3,4)))

#################################
# Facts #
#################################

# testing...
#'''
# NOTE: IN FUTURE, CAN PROBABLY USE THE X.in_(range(5)) method here to handle the ranges (though we also have to handle ordering of rules)
+ packet_allowed('host1', '192.168.0.1')
+ packet_allowed('host1', '192.168.0.2')
+ packet_allowed('host1[interface1]', '192.168.0.1')
+ packet_allowed('device1[interface1]', '192.168.0.1')
+ packet_allowed('device1', '192.168.0.1')
+ packet_allowed('device1[interface2]', '192.168.0.1')
+ packet_allowed('host2[interface1]', '192.168.0.1')
+ packet_allowed('host2', '192.168.0.1')
#'''

# need to specify the relevant packet headers
+ has_src_ip('192.168.0.1')
+ has_dst_ip('192.168.0.2')

# need to specify the start/stop locations for the traceroute (?? I think ??)

# link from one device interface to another device interface
+ link("host1[interface1]", "device1[interface1]")
+ link("host2[interface1]", "device1[interface2]")

# is the link from one device interface to another device interface up
+ no_interface_mismatch("host1[interface1]", "device1[interface1]")
+ no_interface_mismatch("host2[interface1]", "device1[interface2]")

# the cable must be intact for the links to work
+ cable_intact("host1[interface1]", "device1[interface1]")
+ cable_intact("host2[interface1]", "device1[interface2]")

# interfaces per device
+ has_interface("host1", "host1[interface1]")
+ has_interface("host2", "host2[interface1]")
+ has_interface("device1", "device1[interface1]")
+ has_interface("device1", "device1[interface2]")

# TODO: ACL (contents) per device interface
acl_device1_interface1 = [('10.10.10.1/32', 'accept'), ('10.10.10.2/32', 'deny'), ('0.0.0.0/0', 'drop')]
+ has_acl("device1[interface1]", acl_device1_interface1)
+ has_acl("device1[interface2]", [])
+ has_acl("host1[interface1]", [])
+ has_acl("host2[interface1]", [])

# TODO: NAT (contents) per device inteface

# TODO: FIB content (per device)
# (device, next_hop_interface, matching_ip_ranges)
# NOTE: just like for the ACLs, I need to have the last item in the tuple handle ranges
+ next_hop("device1", "device1[interface1]", "192.168.0.2")
+ next_hop("device1", "device1[interface2]", "192.168.0.1")


######################################
# Predicates #
######################################

# links are bidirectional
link(X,Y) <= link(Y,X)
no_interface_mismatch(Y, X) <= no_interface_mismatch(X, Y)
cable_intact(Y, X) <= cable_intact(X, Y)

# need to define what the devices are
is_a_device(X) <= has_interface(X, Y)
has_acl(X, []) <= is_a_device(X)

# devices can reach their interfaces. these interfaces always work
link(X,Y) <= has_interface(X, Y)
no_interface_mismatch(X, Y) <= has_interface(X, Y)
cable_intact(X, Y) <= has_interface(X, Y)

# L2 links must perform certain functionality
# link exists AND the link is up (we can put the
working_link_exists(X,Y) <= link(X,Y) & no_interface_mismatch(X,Y) & cable_intact(X,Y)

# interfaces will drop certain packets, as dictated by their ACLs
# we'll write a function to do this, since that simplifies things a bunch
def does_interface_acl_drop_packet(interface_acl_list, src_ip):
    if interface_acl_list == []:
        return "False"

    for acl_component in interface_acl_list:
        print("acl_component", acl_component, interface_acl_list, src_ip)
        acl_target, acl_action = acl_component
        test_net = ipaddress.ip_network(acl_target)
        if ipaddress.ip_address(src_ip) in test_net:
            if acl_action == 'drop':
                return "True"
            else:
                return "False"
    return "False"


# we'll start by just modeling L1 topology - no ACLs, FIBS, NATs, etc.
# warning: loops are allowed in this calculation
can_reach(X,Y) <= link(X,Y) # direct link
can_reach(X,Y) <= link(X,Z) & can_reach(Z,Y) & (X!=Y) # via Z

# let's try making all paths (modified the one here: https://github.com/pcarbonn/pyDatalog/blob/master/pyDatalog/examples/graph.py)
#all_path(X, Y, P) <= all_path(X, Z, P2) & working_link_exists(Z, Y) & (X != Y) & (X._not_in(P2)) & (Y._not_in(P2)) & (P == P2 + [Z])
#all_path(X, Y, P) <= working_link_exists(X, Y) & (P == [])

# let's refine the previous predicate to only apply to specific packets (i.e. particular sets of packet headers)
# we are going to start by adding support for source ips and checking ACLs

all_paths_packet(X, Y, P, S, T) <= all_paths_packet(X, Z, P2, S, T) & working_link_exists(Z, Y) & (X != Y) & (X._not_in(P2)) \
                                & (Y._not_in(P2)) & (P == P2 + [Z]) & packet_allowed(Z, S) & packet_allowed(Y, S)
                                #& has_acl(Z, Q) & has_acl(Y, D)  & (does_interface_acl_drop_packet(Q, S) == T) \
                                #& (does_interface_acl_drop_packet(D, S) == T)
#& has_src_ip(S) #& ~does_interface_acl_drop_packet(D, S) & ~does_interface_acl_drop_packet(Q, S)
all_paths_packet(X, Y, P, S, T) <= working_link_exists(X, Y) & (P == []) & packet_allowed(X, S) & packet_allowed(X, S) & packet_allowed(Y, S)
                                   #& has_acl(X, Q) & has_acl(Y, D) & (does_interface_acl_drop_packet(Q, S) == T) & (does_interface_acl_drop_packet(D, S) == T)
print("Let's see if the two hosts can communicate:")
#print(all_path("host1", "host2", P))

print("############")
print("############")
#print(working_link_exists(X,Y,'192.168.0.1'))

print("############")
print(all_paths_packet("host1", "host2", P, "192.168.0.1", "False"))

print("------gg-----")
####################
# this is a test...
#packet_not_dropped_by_link(X, Y, S) <=  working_link_exists(X, Y) & packet_allowed(X, S) & packet_allowed(Y, S)
#print(packet_not_dropped_by_link(X, Y, '192.168.0.1'))