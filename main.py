from pybatfish.client.commands import *
from pybatfish.question import bfq

from augment_network_representation import generate_graph_representations, discover_important_device_info, connect_nodes_via_manual_analysis
from flowchart_algo import debug_network_problem
from visualization import plot_graph

import networkx as nx
import os, errno
import requests
import shutil
import json
import argparse
import ipaddress


def main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH, start_location, dst_ip, src_ip, desired_path, problematic_path,
         no_interactive_flag):
    G_layer_2, G_layer_3, explanation = run_batfish(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH, start_location,
                                                    dst_ip, src_ip, problematic_path, no_interactive_flag)
    print("Explanation: " + str(explanation))

def run_batfish(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH, start_location, dst_ip, src_ip, problematic_path,
                no_interactive_flag, DEBUG=True, protocol='tcp'):
    #% run startup.py
    #bf_session.host = "172.0.0.1"  # <batfish_service_ip>
    bf_session.host = 'localhost'
    bf_session.port = '9996'

    # make the directory to hold the temporary files
    intermediate_directory = './augmented_scenarios'
    try:
        os.makedirs(intermediate_directory)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    intermediate_scenario_directory = './augmented_scenarios' + '/' + SNAPSHOT_PATH.split('/')[-1]
    intermediate_scenario_directory_hosts = intermediate_scenario_directory + '/' + 'hosts'
    intermediate_scenario_directory_iptables = intermediate_scenario_directory + '/' + 'iptables'
    level_1_topology_path = intermediate_scenario_directory + '/' + 'layer1_topology.json'
    try:
        destination = shutil.copytree(SNAPSHOT_PATH, intermediate_scenario_directory)
    except:
        shutil.rmtree(intermediate_scenario_directory)
        destination = shutil.copytree(SNAPSHOT_PATH, intermediate_scenario_directory)

    try:
        os.makedirs(intermediate_scenario_directory_hosts)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    try:
        os.makedirs(intermediate_scenario_directory_iptables)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    try:
        os.makedirs("./outputs/" + NETWORK_NAME )
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    G, G_layer_2, G_layer_3, color_map = generate_graph_representations(intermediate_scenario_directory, DEBUG)

    plot_graph(G_layer_3, color_map, fig_number=5, title='layer_3_connectivity', layer_2=False)
    plot_graph(G_layer_2, color_map, fig_number=4, title='layer_2_connectivity', layer_2=True)

    if not no_interactive_flag:
        G_layer_2, interface_information_inputted_manually = discover_important_device_info(G_layer_2, color_map,
                                                                                    title='layer_2_connectivity',
                                                                                    figname="./outputs/" + NETWORK_NAME + "/layer_2_diagram.png",
                                                                                    layer_2=True,
                                                                                    intermediate_scenario_directory_hosts=intermediate_scenario_directory_hosts,
                                                                                    level_1_topology_path=level_1_topology_path,
                                                                                    intermediate_scenario_directory=intermediate_scenario_directory,
                                                                                    DEBUG=DEBUG,
                                                                                    intermediate_scenario_directory_iptables=intermediate_scenario_directory_iptables)

        G, G_layer_2, G_layer_3, color_map, manually_connected_layer2_nodes = \
            connect_nodes_via_manual_analysis(title='layer_2_connectivity',
                                              figname="./outputs/" + NETWORK_NAME + "/layer_2_diagram.png",
                                              intermediate_scenario_directory=intermediate_scenario_directory,
                                              level_1_topology_path=level_1_topology_path,
                                              DEBUG=DEBUG)

    ## TODO: hook in a GNS3 interaction module here that can geneate the configs as-needed
    # (ignore l3 functionality entirely for now).

    plot_graph(G_layer_3, color_map, fig_number=5, title='layer_3_connectivity', layer_2=False,
               filename="./outputs/" + NETWORK_NAME + "/layer_3_diagram.png")

    explanation = debug_network_problem(start_location, dst_ip, src_ip, protocol, desired_path, problematic_path)

    return G_layer_2, G_layer_3, explanation

def find_all_routes_with_correct_next_hop(hop_that_happened, hop_that_we_want_to_happen, matching_routes):
    device_that_routed_packet = hop_that_happened[0]
    routes_with_correct_next_hop = []
    vlan_properties = bfq.switchedVlanProperties(nodes=device_that_routed_packet).answer().frame()
    for matching_route in matching_routes:
        network, next_hop_ip, next_hop_interface = matching_route[1]['Network'], matching_route[1]['Next_Hop_IP'], \
                                                   matching_route[1]['Next_Hop_Interface']
        # TODO: what does it mean  when the next_hop_interface is dynamic (looks like it typically occurs when there is a concrete next_hop_ip)

        if 'vlan' in next_hop_interface.lower():
            relevant_vlan_details = vlan_properties.loc[vlan_properties['VLAN_ID'] == next_hop_interface]
            vlan_interface_details = relevant_vlan_details['Interfaces']
            # okay,so now we have a bunch of corresponding interfaces that the packet could go out on. Do any of these go to the
            # device that we want?
            layer1_edges = bfq.layer1Edges(nodes=device_that_routed_packet).answer().frame()
            routing_entry_takes_us_where_we_want_to_go = False
            for edge in layer1_edges.iterrows():
                remote_interface = edge[1]['Remote_Interface']
                remote_node, remote_port = remote_interface.hostname, remote_interface.interface
                # if this is the correct hop
                if remote_node == hop_that_we_want_to_happen[1]:
                    routing_entry_takes_us_where_we_want_to_go = True
                if routing_entry_takes_us_where_we_want_to_go:
                    routes_with_correct_next_hop.append(matching_route)
                    break

    return routes_with_correct_next_hop

def find_all_routes_that_match(hop_that_happened):
    device_that_routed_packet = hop_that_happened[0]
    routing_table_df = bfq.routes().answer().frame().sort_values(by="Node")
    only_relevant_routing_table_rows = routing_table_df[routing_table_df['Node'] == device_that_routed_packet]

    matching_routes = []
    dst_ip_object = ipaddress.ip_address(dst_ip)
    for row in only_relevant_routing_table_rows.iterrows():
        ip_addr_and_mask = row[1]['Network']
        ip_addr_with_mask = ipaddress.ip_network(ip_addr_and_mask, strict=True)
        if dst_ip_object in ip_addr_with_mask:
            matching_routes.append( row )
    return matching_routes

def is_problem_reproduced():
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Runs Netivus Workflow')
    parser.add_argument('--netivus_experiment',dest="netivus_experiment", default=None)
    args = parser.parse_args()

    start_location, dst_ip, src_ip, desired_path, problematic_path = None, None, None, None, None

    # Initialize a network and snapshot
    '''
    # IP address conflict (the HotNets example)
    NETWORK_NAME = "example_network"
    SNAPSHOT_NAME = "example_snapshot"
    SNAPSHOT_PATH = "./scenarios/Access port config"
    #'''

    # Initialize a network and snapshot
    '''
    # my own modified example: the HotNets example, but with an ACL problem instead of an IP address conflict
    NETWORK_NAME = "example_network_acl"
    SNAPSHOT_NAME = "example_snapshot_acl"
    SNAPSHOT_PATH = "./scenarios/Access Port Config ACL"
    #'''

    if args.netivus_experiment == 'hotnets_example':
        #'''
        # IP address conflict (the HotNets example) -- augmented (but the duplicate IP address is still there)
        NETWORK_NAME = "example_network_augmented"
        SNAPSHOT_NAME = "example_snapshot_augmented"
        SNAPSHOT_PATH = "./scenarios/Access port config Augmented"
        start_location = 'abc_mdf3850x[GigabitEthernet1/1/2]' #'abc-3850parts[GigabitEthernet1/0/1]' # 'abc-3850parts[GigabitEthernet1/1/2]'
        dst_ip = '10.10.20.8'
        src_ip = '10.00.20.60' #  '10.10.20.60'
        #'''
    elif args.netivus_experiment == 'hotnets_example_fixed':
        #'''
        # IP address conflict (the HotNets example) -- augmented + correct (so the duplicate IP address is now gone)
        NETWORK_NAME = "example_network_correct"
        SNAPSHOT_NAME = "example_snapshot_correct"
        SNAPSHOT_PATH = "./scenarios/Access Port Config Correct"
        start_location = 'abc-3850parts[GigabitEthernet1/1/2]'
        dst_ip = '10.10.20.8'
        src_ip = '10.10.20.60'
        #'''
    elif args.netivus_experiment == 'inter-vlan':
        '''
        # Another example that works
        NETWORK_NAME = "example_network_inter-vlan"
        SNAPSHOT_NAME = "example_snapshot_inter-vlan"
        SNAPSHOT_PATH = "./scenarios/Dell N2000 - Inter-VLAN routing problem"
        # looks like it doesn't support this type of config files??
        #'''

        #'''
        # Dell N2000 - Inter-VLAN routing problem Augmented
        NETWORK_NAME = "example_network_inter-vlan_augmented"
        SNAPSHOT_NAME = "example_snapshot_inter-vlan_augmented"
        SNAPSHOT_PATH = "./scenarios/Dell N2000 - Inter-VLAN routing problem Augmented"
        # looks like it doesn't support this type of config files??
        #'''
    elif args.netivus_experiment == 'juniper_uplink_unstable':
        #'''
        # Juniper SRX240 unstable uplink when client is connected to VPN
        NETWORK_NAME = "example_network_juniper"
        SNAPSHOT_NAME = "example_snapshot_juniper"
        SNAPSHOT_PATH = "./scenarios/Juniper SRX240 unstable uplink when client is connected to VPN withSecondDevice"
        #'''
        start_location = '--obscured--[fe-0/0/1]'
        dst_ip = '8.8.8.8'
        src_ip = '192.168.2.22'
    elif args.netivus_experiment == 'cisco_asa_doesnt_allow_internet':
        #'''
        # ???
        NETWORK_NAME = "example_network_asdm"
        SNAPSHOT_NAME = "example_snapshot_asdm"
        SNAPSHOT_PATH = "./scenarios/Cisco ASA 5505 doesn't allow internet connection"
        start_location = 'lab-asa[Ethernet0/2]'
        dst_ip = '8.8.8.8'
        src_ip = '172.16.1.4'
        #'''
        '''
        bfq.bidirectionalTraceroute(startLocation='@enter(lab-asa[Ethernet0/2])',
                                    headers=HeaderConstraints(dstIps='8.8.8.8',
                                                              srcIps='172.16.1.4')).answer().frame(
        '''
    elif args.netivus_experiment == 'pc_cannot_ping_eachother_when_using_bgp':
        # PC cannot ping each other when using BGP
        NETWORK_NAME = "pc_cannot_ping_eachother_when_using_bgp"
        SNAPSHOT_NAME = "pc_cannot_ping_eachother_when_using_bgp"
        SNAPSHOT_PATH = "./scenarios/PC cannot ping each other when using BGP"
        #'''
        # PC-A to PC-B
        start_location = 'r1[GigabitEthernet0/1]'
        dst_ip = '192.168.3.4'
        src_ip = '192.168.1.4'
        #'''
        '''
        start_location = 'r3[GigabitEthernet0/1]'
        dst_ip = '192.168.1.4'
        src_ip = '192.168.3.4'
        '''
    elif args.netivus_experiment == "Juniper_SRX240_and_EX2200_network":
        NETWORK_NAME = "Juniper_SRX240_and_EX2200_network"
        SNAPSHOT_NAME = "Juniper_SRX240_and_EX2200_network"
        SNAPSHOT_PATH = "./scenarios/Juniper SRX240 and EX2200 network"
        #'''
        # host on ex2200 trying to reach the WAN (srx240[ge0/0/0.0])
        start_location = 'ex2200[ge-0/0/13]'
        dst_ip = '8.8.8.8'
        src_ip = '192.168.1.5'
        #desired_path = ['ex2200', 'srx240', 'internet']
        desired_path = ['RECEIVED:ex2200[ge-0/0/13]', 'OUTGOING:ex2200[ge-0/0/22]', 'RECEIVED:srx240[ge-0/0/1]',
                        'OUTGOING:srx240[ge-0/0/0]', 'RECEIVED:WAN']
        problematic_path = ['RECEIVED:ex2200[ge-0/0/13]', 'EXITS_NETWORK:ex2200[vlan.100]']
        #'''
    elif args.netivus_experiment == "Juniper_SRX240_and_EX2200_network_FIXED":
        # not actually fixed haha
        NETWORK_NAME = "Juniper_SRX240_and_EX2200_network_fixed"
        SNAPSHOT_NAME = "Juniper_SRX240_and_EX2200_network_fixed"
        SNAPSHOT_PATH = "./scenarios/Juniper SRX240 and EX2200 network FIXED"
        # '''
        # host on ex2200 trying to reach the WAN (srx240[ge0/0/0.0])
        start_location = 'ex2200[ge-0/0/13]'
        dst_ip = '8.8.8.8'
        src_ip = '192.168.1.5'
        # '''
    elif args.netivus_experiment == "batfish_isp_example":
        NETWORK_NAME = "networks_example_live-with-isp"
        SNAPSHOT_NAME = "networks_example_live-with-isp"
        SNAPSHOT_PATH = "./scenarios/example_scenarios_from_batfish_github/batfish/networks/example/live-with-isp/"

    elif args.netivus_experiment == "aaaa":
        NETWORK_NAME = "aaaa"
        SNAPSHOT_NAME = "aaaa"
        SNAPSHOT_PATH = "./scenarios/aaaa"

    elif args.netivus_experiment == "Cisco_Router_Setup_1841":
        NETWORK_NAME = "Cisco_Router_Setup_1841"
        SNAPSHOT_NAME = "Cisco_Router_Setup_1841"
        SNAPSHOT_PATH = "./scenarios/Cisco_Router_Setup_1841"
        start_location = 'router[FastEthernet0/0]'
        dst_ip = '8.8.8.8'
        src_ip = '10.0.4.5'
    elif args.netivus_experiment == 'hotnets_example_acl':
        #'''
        # IP address conflict (the HotNets example) -- augmented + correct (so the duplicate IP address is now gone)
        NETWORK_NAME = "hotnets_example_acl"
        SNAPSHOT_NAME = "hotnets_example_acl"
        SNAPSHOT_PATH = "./scenarios/Access Port Config ACL"
        start_location = 'abc-3850parts[GigabitEthernet1/1/2]'
        dst_ip = '10.10.20.8'
        src_ip = '10.10.20.60'
        #'''
    elif args.netivus_experiment == 'hotnets_example_no_routes':
        #'''
        # IP address conflict (the HotNets example) -- augmented + correct (so the duplicate IP address is now gone)
        NETWORK_NAME = "hotnets_example_no_routes"
        SNAPSHOT_NAME = "hotnets_example_no_routes"
        SNAPSHOT_PATH = "./scenarios/Access Port Config No Routes"
        start_location = 'abc-3850parts[GigabitEthernet1/1/2]'
        dst_ip = '10.10.20.8'
        src_ip = '10.10.20.60'
        #'''
    elif args.netivus_experiment == 'route_based_ipsec':
        # IP address conflict (the HotNets example) -- augmented + correct (so the duplicate IP address is now gone)
        NETWORK_NAME = "route_based_ipsec"
        SNAPSHOT_NAME = "route_based_ipsec"
        SNAPSHOT_PATH = "./scenarios/Route-based ipsec between cisco router end juniper srx"
        start_location = None # TODO
        dst_ip = None # TODO
        src_ip = None # TODO

    elif args.netivus_experiment == 'dhcp_config':
        NETWORK_NAME = "dhcp_config"
        SNAPSHOT_NAME = "dhcp_config"
        SNAPSHOT_PATH = "./scenarios/DHCP Configurauion on Cisco router"
        start_location = 'router250[Ethernet1/1]'  # TODO
        #start_location = 'a_host[eth0]'  # TODO
        dst_ip = '20.0.0.2'  # TODO
        src_ip = '40.0.0.15'  # TODO

    elif args.netivus_experiment == "cannot_access_inside_from_outside":
        NETWORK_NAME = "cannot_access_inside_from_outside"
        SNAPSHOT_NAME = "cannot_access_inside_from_outside"
        SNAPSHOT_PATH = "./scenarios/Can not access PC(inside) from router(outside) through ASA 5512"
        start_location = "router[GigabitEthernet0/0]"
        dst_ip = '192.168.0.5'
        src_ip = '192.168.100.254'

    elif args.netivus_experiment == "problem_with_cisco_asa_nat":
        pass
        NETWORK_NAME = "problem_with_cisco_asa_nat"
        SNAPSHOT_NAME = "problem_with_cisco_asa_nat"
        SNAPSHOT_PATH = "./scenarios/Problem with Cisco ASA 5512 NAT Configuration"
        start_location = 'asa[Outside]'
        dst_ip = "10.3.3.128"
        src_ip = "62.5.3.226"
        #desired_path = ['RECEIVED:ASA[GigabitEthernet0/0]', 'OUTGOING:ASA[GigabitEthernet0/1]']
        desired_path = ['RECEIVED:asa[Outside]', 'OUTGOING:asa[Inside]']
        problematic_path = ['RECEIVED:asa[Outside]', 'DENIED:asa[Inside]']

    elif args.netivus_experiment == "private_lan_cannot_access_internet":
        # Cisco 1921 private LAN can't access internet on WAN interface
        NETWORK_NAME = "private_lan_cannot_access_internet"
        SNAPSHOT_NAME = "private_lan_cannot_access_internet"
        SNAPSHOT_PATH = "./scenarios/Cisco 1921 private LAN can't access internet on WAN interface"
        start_location = 'cisco-1-c[GigabitEthernet0/0]'  # TODO
        dst_ip = '8.8.8.8'  # TODO
        src_ip = '10.1.9.22'  # TODO
    else:
        ########## the following are examples that I am working on.... #########

        '''
        # ???
        NETWORK_NAME = "example_network_stop_passing"
        SNAPSHOT_NAME = "example_snapshot_stop_passing"
        SNAPSHOT_PATH = "./scenarios/Cisco ASA 5505 stop passing traffic randomly"
        #'''

        '''
        # ???
        NETWORK_NAME = "example_network_two_routers"
        SNAPSHOT_NAME = "example_snapshot_two_routers"
        SNAPSHOT_PATH = "./scenarios/Two routers, one modem, dual IPs, second address drops connection occasionally"
        # looks like it doesn't support this type of config files??
        #'''

    no_interactive_flag = True # if true, do not take any input from the operator via the CLI
    main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH, start_location, dst_ip, src_ip, desired_path, problematic_path,
         no_interactive_flag)

    #create_gns3_copy()

    # note: I can interact with the local GNS3 server (and it's API) using these commands:
    # curl -i -u 'admin:iSJeYlFLUSwnKDHA9F3jWYLkioJ5Nn6mrEVgCp06VT9kL08bPd4qmTBANfCdoRJZ' http://127.0.0.1:3080/v2/version
