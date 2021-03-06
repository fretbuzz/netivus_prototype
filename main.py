from pybatfish.client.commands import *
from pybatfish.question import bfq

from flowchart_algo import debug_network_problem
from visualization import plot_graph
from augment_network_representation import connect_nodes_via_manual_analysis, generate_graph_representations, discover_important_device_info

import networkx as nx
import os, errno
import requests
import shutil
import json
import argparse
import ipaddress


def main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH, start_location, dst_ip, src_ip, desired_path, problematic_path,
         no_interactive_flag, type_of_problem, end_location, srcPort, dstPort, ipProtocol, return_after_recreation=False):

    G_layer_2, G_layer_3, explanation, should_we_debug_the_path_forward = run_batfish(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH, start_location,
                                                    dst_ip, src_ip, problematic_path, no_interactive_flag, type_of_problem,
                                                    end_location, srcPort, dstPort, ipProtocol, desired_path,
                                                    return_after_recreation)
    print("Explanation: " + str(explanation))

    return G_layer_2, G_layer_3, explanation, should_we_debug_the_path_forward

def run_batfish(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH, start_location, dst_ip, src_ip, problematic_path,
                no_interactive_flag, type_of_problem, end_location, srcPort, dstPort, ipProtocol, desired_path,
                return_after_recreation, DEBUG=True, protocol='tcp', return_after_initialization = False, ):

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

    G, G_layer_2, G_layer_3, color_map = generate_graph_representations(intermediate_scenario_directory, DEBUG, NETWORK_NAME, SNAPSHOT_NAME)

    #plot_graph(G_layer_3, color_map, fig_number=5, title='layer_3_connectivity', layer_2=False)
    #plot_graph(G_layer_2, color_map, fig_number=4, title='layer_2_connectivity', layer_2=True)

    if not no_interactive_flag:
        G_layer_2, interface_information_inputted_manually = discover_important_device_info(G_layer_2, color_map,
                                                                                    title='layer_2_connectivity',
                                                                                    figname="./outputs/" + NETWORK_NAME + "/layer_2_diagram.png",
                                                                                    layer_2=True,
                                                                                    intermediate_scenario_directory_hosts=intermediate_scenario_directory_hosts,
                                                                                    level_1_topology_path=level_1_topology_path,
                                                                                    intermediate_scenario_directory=intermediate_scenario_directory,
                                                                                    DEBUG=DEBUG,
                                                                                    intermediate_scenario_directory_iptables=intermediate_scenario_directory_iptables,
                                                                                    NETWORK_NAME = NETWORK_NAME,
                                                                                    SNAPSHOT_NAME = SNAPSHOT_NAME)

        G, G_layer_2, G_layer_3, color_map, manually_connected_layer2_nodes = \
            connect_nodes_via_manual_analysis(title='layer_2_connectivity',
                                              figname="./outputs/" + NETWORK_NAME + "/layer_2_diagram.png",
                                              intermediate_scenario_directory=intermediate_scenario_directory,
                                              level_1_topology_path=level_1_topology_path,
                                              DEBUG=DEBUG,
                                              NETWORK_NAME=NETWORK_NAME,
                                              SNAPSHOT_NAME=SNAPSHOT_NAME)

    #plot_graph(G_layer_3, color_map, fig_number=5, title='layer_3_connectivity',
    #           layer_2=False, filename="./outputs/" + NETWORK_NAME + "/interface_connectivity_diagram.png")

    #plot_graph(G, color_map, fig_number=6, title='Interace_connectivity',
    #           layer_2=False, filename="./outputs/" + NETWORK_NAME + "/layer_3_diagram.png")

    if return_after_initialization:
        return start_location, end_location, dst_ip, src_ip, protocol, desired_path, type_of_problem, intermediate_scenario_directory, NETWORK_NAME, SNAPSHOT_NAME, DEBUG

    print("desired_path", desired_path)

    # this will get the device facts in a vendor-neutral format
    # bf_session.extract_facts()

    explanation, should_we_debug_the_path_forward = debug_network_problem(start_location, end_location, dst_ip, src_ip, protocol, desired_path,
                                        type_of_problem, intermediate_scenario_directory, srcPort, dstPort, ipProtocol,
                                        NETWORK_NAME, SNAPSHOT_NAME, DEBUG, return_after_recreation)

    return G_layer_2, G_layer_3, explanation, should_we_debug_the_path_forward

def specify_nodes_to_remove_in_graph(G):

    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Runs Netivus Workflow')
    parser.add_argument('--netivus_experiment',dest="netivus_experiment", default=None)
    args = parser.parse_args()

    start_location, end_location, dst_ip, src_ip, desired_path, problematic_path, type_of_problem = None, None, None, None, None, None, None
    srcPort, dstPort, ipProtocol = None, None, None

    # type_of_problem has two types:
    ## Connecitivity_Allowed  : connectivity was allowed, but should be blocked
    ## Connecitivity_Blocked : connectivity was blocked, but should be allowed

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
        type_of_problem = 'Connecitivity_Blocked_But_Should_Be_Allowed'
        src_ip = '10.10.20.60'
        dst_ip = '10.10.20.8'
        ipProtocol = 'tcp'
        start_location = 'abc-3850parts[GigabitEthernet1/1/2]'
        end_location = "voip_server"
        desired_path = None  # Not needed for this type of problem
        problematic_path = None  # not needed by this system, for any task

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
        # Juniper SRX240 unstable uplink when client is connected to VPN
        NETWORK_NAME = "example_network_juniper"
        SNAPSHOT_NAME = "example_snapshot_juniper"
        SNAPSHOT_PATH = "./scenarios/Juniper SRX240 unstable uplink when client is connected to VPN withSecondDevice"
        type_of_problem = 'Connecitivity_Blocked_But_Should_Be_Allowed'
        src_ip = '192.168.2.22'
        dst_ip = '8.8.8.8'
        ipProtocol = 'tcp'
        start_location = '--obscured--[fe-0/0/1]'
        end_location =   '--obscured--[fe-0/0/0]'
        desired_path = None  # Not needed for this type of problem
        problematic_path = None  # not needed by this system, for any t
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
        type_of_problem = 'Connecitivity_Blocked_But_Should_Be_Allowed'
        src_ip = '192.168.1.5'
        dst_ip = '8.8.8.8'
        ipProtocol = 'tcp'
        start_location = 'ex2200[ge-0/0/13]'
        end_location = 'ex2200[WAN]'
        desired_path = None  # Not needed for this type of problem
        problematic_path = None  # not needed by this system, for any task
        #'''
        # host on ex2200 trying to reach the WAN (srx240[ge0/0/0.0])
        #desired_path = ['RECEIVED:ex2200[ge-0/0/13]', 'TRANSMITED:ex2200[ge-0/0/22]', 'TRANSMITED:srx240[ge-0/0/1]',
        #                'TRANSMITED:srx240[ge-0/0/0]', 'RECEIVED:WAN']
        #problematic_path = ['RECEIVED:ex2200[ge-0/0/13]', 'EXITS_NETWORK:ex2200[vlan.100]']
        #type_of_problem = 'Connecitivity_Blocked'

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
        type_of_problem = 'Connecitivity_Blocked_But_Should_Be_Allowed'
        src_ip = '40.0.0.15'
        dst_ip = '20.0.0.2'
        ipProtocol = 'DHCP'
        start_location = 'router250[Ethernet1/1]'
        end_location = 'Router450[Ethernet0/0]'
        desired_path = None  # Not needed for this type of problem
        problematic_path = None  # not needed by this system, for any task

    elif args.netivus_experiment == "cannot_access_inside_from_outside":
        NETWORK_NAME = "cannot_access_inside_from_outside"
        SNAPSHOT_NAME = "cannot_access_inside_from_outside"
        SNAPSHOT_PATH = "./scenarios/Can not access PC(inside) from router(outside) through ASA 5512"
        start_location = "router[GigabitEthernet0/0]"
        dst_ip = '192.168.0.5'
        src_ip = '192.168.100.254'

    elif args.netivus_experiment == "problem_with_cisco_asa_nat":
        NETWORK_NAME = "problem_with_cisco_asa_nat"
        SNAPSHOT_NAME = "problem_with_cisco_asa_nat"
        SNAPSHOT_PATH = "./scenarios/Problem with Cisco ASA 5512 NAT Configuration"
        type_of_problem = 'Connecitivity_Blocked_But_Should_Be_Allowed'
        src_ip = "62.5.3.226"
        dst_ip = "10.3.3.128"
        srcPort = "20"
        dstPort = "20"
        ipProtocol = 'tcp'
        start_location = 'asa[Outside]'
        end_location = 'asa[Inside]'
        desired_path = None  # Not needed for this type of problem
        problematic_path = None  # not needed by this system, for any task
        #desired_path = ['RECEIVED:asa[Outside]', 'OUTGOING:asa[Inside]']
        #problematic_path = ['RECEIVED:asa[Outside]', 'DENIED:asa[Inside]']

    elif args.netivus_experiment == "private_lan_cannot_access_internet":
        # Cisco 1921 private LAN can't access internet on WAN interface
        NETWORK_NAME = "private_lan_cannot_access_internet"
        SNAPSHOT_NAME = "private_lan_cannot_access_internet"
        SNAPSHOT_PATH = "./scenarios/Cisco 1921 private LAN can't access internet on WAN interface"
        type_of_problem = "Connecitivity_Blocked_But_Should_Be_Allowed"
        src_ip = '10.1.9.22'
        dst_ip = '8.8.8.8'
        ipProtocol = 'tcp'
        start_location = 'cisco-1-c[GigabitEthernet0/0]'
        end_location =  'cisco-1-c[GigabitEthernet0/0/0]'
        desired_path = None  # Not needed for this type of problem
        problematic_path = None  # not needed by this system, for any task

    elif args.netivus_experiment == "synthetic_base_network":
        NETWORK_NAME = "synthetic_base_network"
        SNAPSHOT_NAME = "synthetic_base_network"
        SNAPSHOT_PATH = "./synthetic_scenarios/base_Intenionet_network"

        type_of_problem = 'Connectivity_Allowed_And_Should_Be_Allowed'
        src_ip = '2.128.0.101'
        dst_ip = '2.128.1.101'
        srcPort = "22"
        dstPort = "22"
        ipProtocol = 'tcp'
        start_location = 'host1[eth0]'
        end_location = 'host2[eth0]'
        desired_path = None # Not needed for this type of problem
        problematic_path = None # not needed by this system, for any task

    elif args.netivus_experiment == "synthetic_acl_shadowed_blocked_but_should_be_allowed":
        NETWORK_NAME = "synthetic_acl_shadowed_blocked_but_should_be_allowed"
        SNAPSHOT_NAME = "synthetic_acl_shadowed_blocked_but_should_be_allowed"
        SNAPSHOT_PATH = "./synthetic_scenarios/blocked_but_should_be_allowed/acl_shadowed"

    elif args.netivus_experiment == "synthetic_explicit_acl_drop_packets_forward":
        NETWORK_NAME = "synthetic_explicit_acl_drop_packets_forward"
        SNAPSHOT_NAME = "synthetic_explicit_acl_drop_packets_forward"
        SNAPSHOT_PATH = "./synthetic_scenarios/simple_errors_no_refinement/blocked_but_should_be_allowed/explicit_acl_drop_packets_forward"

        # problem info
        type_of_problem = 'Connecitivity_Blocked_But_Should_Be_Allowed'
        src_ip = '2.128.0.101'
        dst_ip = '2.128.1.101'
        srcPort = "22"
        dstPort = "22"
        ipProtocol = 'tcp'
        start_location = 'host1'
        end_location = 'host2'
        desired_path = None  # Not needed for this type of problem
        problematic_path = None  # not needed by this system, for any task

    elif args.netivus_experiment == "synthetic_explicit_acl_drop_packets_return":
        NETWORK_NAME = "synthetic_explicit_acl_drop_packets_return"
        SNAPSHOT_NAME = "synthetic_explicit_acl_drop_packets_return"
        SNAPSHOT_PATH = "./synthetic_scenarios/simple_errors_no_refinement/blocked_but_should_be_allowed/explicit_acl_drop_packets_return"

        # problem info
        type_of_problem = 'Connecitivity_Blocked_But_Should_Be_Allowed'
        src_ip = '2.128.0.101'
        dst_ip = '2.128.1.101'
        srcPort = "22"
        dstPort = "22"
        ipProtocol = 'tcp'
        start_location = 'host1[eth0]'
        end_location = 'host2[eth0]'
        desired_path = None  # Not needed for this type of problem
        problematic_path = None  # not needed by this system, for any task

    elif args.netivus_experiment == "synthetic_interface_mismatch_vlan_tagging":
        NETWORK_NAME = "synthetic_interface_mismatch_vlan_tagging"
        SNAPSHOT_NAME = "synthetic_interface_mismatch_vlan_tagging"
        SNAPSHOT_PATH = "./synthetic_scenarios/blocked_but_should_be_allowed/interface_mismatch_vlan_tagging"

    elif args.netivus_experiment == "synthetic_route_pkts_the_wrong_way":
        NETWORK_NAME = "synthetic_route_pkts_the_wrong_way"
        SNAPSHOT_NAME = "synthetic_route_pkts_the_wrong_way"
        SNAPSHOT_PATH = "./synthetic_scenarios/simple_errors_no_refinement/blocked_but_should_be_allowed/static_route_sends_pkts_the_wrong_way"

        type_of_problem = 'Connecitivity_Blocked_But_Should_Be_Allowed'
        src_ip = '2.128.0.101'
        dst_ip = '2.128.1.101'
        srcPort = "22"
        dstPort = "22"
        ipProtocol = 'tcp'
        start_location = 'host1[eth0]'
        end_location = 'host2[eth0]'
        desired_path = None  # Not needed for this type of problem
        problematic_path = None  # not needed by this system, for any task

    elif args.netivus_experiment == "synthetic_acl_shadowed":
        pass
    elif args.netivus_experiment == "synthetic_bi_directional_nat":
        pass
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
         no_interactive_flag, type_of_problem, end_location, srcPort, dstPort, ipProtocol)

    #create_gns3_copy()

    # note: I can interact with the local GNS3 server (and it's API) using these commands:
    # curl -i -u 'admin:iSJeYlFLUSwnKDHA9F3jWYLkioJ5Nn6mrEVgCp06VT9kL08bPd4qmTBANfCdoRJZ' http://127.0.0.1:3080/v2/version
