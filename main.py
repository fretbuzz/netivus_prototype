import docker, os

import pandas as pd
from pybatfish.client.commands import *
from pybatfish.datamodel import *
from pybatfish.datamodel.answer import *
from pybatfish.datamodel.flow import *
from pybatfish.question import *
from pybatfish.question import bfq
from flowchart_algo import debug_network_problem

import networkx as nx
import matplotlib.pyplot as plt
import os, errno
import math
import requests
import shutil
from pathlib import Path
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

def generate_graph_representations(intermediate_scenario_directory, DEBUG):
    bf_set_network(NETWORK_NAME)
    bf_init_snapshot(intermediate_scenario_directory, name=SNAPSHOT_NAME, overwrite=True)

    load_questions()

    pd.options.display.max_columns = 6

    if DEBUG:
        parse_status = bfq.fileParseStatus().answer().frame()

        print("----------------------")

        print(parse_status)

        print("----------------------")

        parse_warning = bfq.parseWarning().answer().frame()

        print("----------------------")

        print(parse_warning)

        print("----------------------")

        # vxlanEdges,layer3Edges
        node_properties_trunc = bfq.nodeProperties(properties="Device_Type,Interfaces").answer().frame()

        print(node_properties_trunc)

        print("---------")
        print(bfq.undefinedReferences().answer().frame())

        print("layer1Edges")
        print("----------------------")
        print(bfq.layer1Edges().answer().frame())
        print("LAYER3_EDGES")
        print("----------------------")
        print(bfq.layer3Edges().answer().frame())
        print("----------------------")

        print(bfq.undefinedReferences().answer().frame())

        # Get edges of type layer 3 (IP layer)
        print(bfq.edges(edgeType="layer3").answer().frame())

    # Config files -> batfish -> (our parser) -> GNS3 emulation
    # first, let's get the networkx graph
    G = nx.Graph()
    G_layer_2 = nx.Graph()
    G_layer_3 = nx.Graph()
    color_map = []

    device_dataframe = bfq.nodeProperties().answer().frame()
    add_devices_to_graphs(device_dataframe, G, G_layer_2, G_layer_3, color_map)

    interface_dataframe = bfq.interfaceProperties().answer().frame()
    add_interfaces_to_graphs(interface_dataframe, G, G_layer_2, G_layer_3, color_map)

    edge_dataframe = bfq.edges().answer().frame()
    edges_layer1_dataframe = bfq.layer1Edges().answer().frame()
    edge_interfaces = set()
    connected_interfaces = add_edges_to_graphs(edge_dataframe, G, G_layer_2, G_layer_3, color_map, edge_interfaces, edges_layer1_dataframe)

    for connected_interface in connected_interfaces:
        if str(connected_interface) in G_layer_2.nodes():
            G_layer_2.remove_node( str(connected_interface) )

    return G, G_layer_2, G_layer_3, color_map

def map_to_node_or_none(value1, G_layer_2):
    value = None
    if value1 in G_layer_2.nodes():
        value = value1
    else:
        node_labels_description = nx.get_node_attributes(G_layer_2, 'description')
        if value1 in node_labels_description.values():
            found_node = None
            not_unique = False
            for node, desc in node_labels_description.items():
                if desc == value1:
                    if found_node is None:
                        found_node = node
                    else:
                        print("That value is not a unique identifier for this graph")
                        not_unique = True
                        break

            if not not_unique and found_node is not None:
                print("that node was found, even tho you used the description and not the name!")
                value = found_node
        else:
            print("That node was not recognized. Please check the spelling and try again")

    return value

def connect_nodes_via_manual_analysis(title, figname, intermediate_scenario_directory, DEBUG, level_1_topology_path, layer_2=True):
    G, G_layer_2, G_layer_3, color_map = generate_graph_representations(intermediate_scenario_directory, DEBUG)
    connected_interfaces_via_manual_analysis = []
    print("These are the nodes in the graph:")
    for node in G_layer_2.nodes():
        print(node)
    prompt_for_connected_interfaces = "Please enter one of the connected interfaces (hit enter if none are connected): "
    while True:
        print("----------------")
        print("Are any of these interfaces connected?")
        while True:
            value1 = input(prompt_for_connected_interfaces)
            if value1 == '':
                break
            value1 = map_to_node_or_none(value1, G_layer_2)

            if value1 != None:
                break

        if value1 == '':
            break

        while True:
            value2 = input(prompt_for_connected_interfaces)
            if value2 == '':
                break
            value2 = map_to_node_or_none(value2, G_layer_2)

            if value2 != None:
                break

        if value2 == '':
            break


        # now update the layer1 topology file
        hostname1, interface1 = split_interface_name(value1)
        hostname2, interface2 = split_interface_name(value2)
        return_value = generate_layer_1_topology_config_file(level_1_topology_path, hostname1, interface1, hostname2, interface2)
        # now re-run the graph generation pipeline using our updated topology files
        G, G_layer_2, G_layer_3, color_map = generate_graph_representations(intermediate_scenario_directory, DEBUG)


        ''' # old code...
        node1 = list(G_layer_2.neighbors(value1))
        node2 = list(G_layer_2.neighbors(value2))
        if len(node1) > 1:
            exit('len node1 is bigger than 1')
        if len(node2) > 1:
            exit('len node2 is bigger than 1')
        G_layer_2.remove_node(value1)
        G_layer_2.remove_node(value2)
        G_layer_2.add_edge(node1[0], node2[0])
        connected_interfaces_via_manual_analysis.append( (value1, value2) )
        print('New edge added succesfully! -- removed ' + str(value1) + " and " + str(value2))
        '''

        plot_graph(G_layer_2, color_map, fig_number=4, title=title, show=True, layer_2=layer_2)

    plot_graph(G_layer_2, color_map, fig_number=4, title=title, show=False, layer_2=layer_2)
    plt.tight_layout()
    plt.savefig(fname= figname)

    return G, G_layer_2, G_layer_3, color_map, connected_interfaces_via_manual_analysis

def split_interface_name(device_and_interface_1):
    hostname1, interface1 = device_and_interface_1.split('[')
    interface1 = interface1.replace(']', '')
    return hostname1, interface1

def generate_layer_1_topology_config_file(filename, hostname1, interface1,  hostname2, interface2):
    # check if file exist
    if os.path.exists(filename):
        # if it exists, read in the file
        with open(filename, 'r') as outfile:
            contents = json.load(outfile)
    else:
        # else, need to make the structory ourselves
        contents = {}
        contents['edges'] = []

    '''
    hostname1, interface1 = device_and_interface_1.split('[')
    interface1 = interface1.replace(']', '')
    hostname2, interface2 = device_and_interface_2.split('[')
    interface2 = interface2.replace(']', '')
    '''

    new_edge = {}
    new_edge['node1'] = {}
    new_edge['node1']['hostname'] = hostname1
    new_edge['node1']['interfaceName'] = interface1
    new_edge['node2'] = {}
    new_edge['node2']['hostname'] = hostname2
    new_edge['node2']['interfaceName'] = interface2

    contents['edges'].append(new_edge)

    # write out the file to the correct location
    with open(filename, 'w') as outfile:
        json.dump(contents, outfile, indent=4)

    return 1

def add_devices_to_graphs(device_dataframe, G, G_layer_2, G_layer_3, color_map):
    for device in device_dataframe.iterrows():
        device_name = device[1]['Node']
        device_type = device[1]['Device_Type']
        print(device_name, device_type)
        G.add_node(str(device_name), type=device_type, name=str(device_name))
        G_layer_2.add_node(str(device_name), type=device_type, name=str(device_name))
        G_layer_3.add_node(str(device_name), type=device_type, name=str(device_name))
        color_map.append('red')

def add_edges_to_graphs(edge_dataframe, G, G_layer_2, G_layer_3, color_map, edge_interfaces, edges_layer1_dataframe):
    connected_interfaces = []
    for edge in edge_dataframe.iterrows():
        local_interface = edge[1]['Interface']
        local_device = local_interface.hostname
        local_vlan = local_interface.interface
        G.add_node(str(local_interface), type='interface', name=str(local_interface))

        color_map.append('lightgreen')
        G.add_edge(local_device, local_interface)
        local_ip, remote_ip = list(edge[1]['IPs']), list(edge[1]["Remote_IPs"])

        remote_interface = edge[1]['Remote_Interface']
        remote_device = remote_interface.hostname
        remote_vlan = remote_interface.interface
        print("lr", local_interface, remote_interface)
        G.add_node(str(remote_interface), type='interface', name=str(remote_interface))
        color_map.append('lightgreen')
        G.add_edge(remote_device, remote_interface)

        edge_interfaces.add(local_interface)
        edge_interfaces.add(remote_interface)

        ## this code makes sure that all of the direct edges show up in the layer2 visualization
        if local_device not in G_layer_2.nodes():
            #G_layer_2()
            G_layer_2.add_node(str(local_device), type='unknown', name=str(local_device))
        if remote_device not in G_layer_2.nodes():
            G_layer_2.add_node(str(remote_device), type='unknown', name=str(remote_device))
        G_layer_2.add_edge(local_device, remote_device)
        connected_interfaces.append(local_interface)
        connected_interfaces.append(remote_interface)

        if local_vlan != remote_vlan:
            if 'Vlan' in local_vlan and 'Vlan' not in remote_vlan:
                remote_vlan = local_vlan
            elif 'Vlan' not in local_vlan and 'Vlan' in remote_vlan:
                local_vlan = remote_vlan
            else:
                pass
                #exit('why does local_vlan not equal remote_vlan!?!')

        G.add_edge(local_interface, remote_interface)
        if local_ip is not None and remote_ip is not None:
            # the problem with this is that it doesn't make the type of diagrams that I am looking for
            # G_layer_3.add_edge(local_device, remote_device)
            pass
        # G_layer_2.add_edge(local_device, remote_device)

        # make an edge that connects the devices to (some of) their VLANs
        if 'Vlan' in local_vlan:
            G_layer_3.add_node(local_vlan, name = local_vlan, type='VLAN')
            G_layer_3.add_edge(local_device, local_vlan, ip_address = str(local_ip))
        elif 'Vlan' in remote_vlan:
            G_layer_3.add_node(remote_vlan, name = local_vlan, type='VLAN')
            G_layer_3.add_edge(remote_device, remote_vlan, ip_address = str(remote_ip))

    print("Nodes in graph:")
    for node in G_layer_2.nodes():
        print(node)

    print("edges_layer1_dataframe:")
    print(edges_layer1_dataframe)
    interfaces_removed_so_far = []
    for interface_row in edges_layer1_dataframe.iterrows():
        whole_interface = interface_row[1]['Interface']
        hostname = whole_interface.hostname
        interface = whole_interface.interface

        whole_remote_interface = interface_row[1]['Remote_Interface']
        remote_hostname = whole_remote_interface.hostname
        remote_interface = whole_remote_interface.interface

        #description = interface_row[1]['Description']
        #native_vlan =  interface_row[1]['Native_VLAN']

        G_layer_2.add_edge(hostname, remote_hostname) #, vlan=native_vlan)
        if whole_interface not in interfaces_removed_so_far:
            if whole_interface in G_layer_2.nodes():
                G_layer_2.remove_node(str(whole_interface))
                interfaces_removed_so_far.append(whole_interface)
        if whole_remote_interface not in interfaces_removed_so_far:
            if whole_remote_interface in G_layer_2.nodes():
                G_layer_2.remove_node(str(whole_remote_interface))
                interfaces_removed_so_far.append(whole_remote_interface)

    return connected_interfaces

def add_interfaces_to_graphs(interface_dataframe, G, G_layer_2, G_layer_3, color_map):
    for counter, interface_row in enumerate(interface_dataframe.iterrows()):
        whole_interface = interface_row[1]['Interface']
        hostname = whole_interface.hostname
        interface = whole_interface.interface

        description = interface_row[1]['Description']
        native_vlan = interface_row[1]['Native_VLAN']
        access_vlan = interface_row[1]['Access_VLAN']
        allowed_vlans = interface_row[1]['Allowed_VLANs']
        speed = interface_row[1]['Speed']
        declared_names = interface_row[1]['Declared_Names']

        G.add_node(str(whole_interface), type='interface', description=description, name=str(whole_interface))
        color_map.append('lightgreen')
        G.add_edge(hostname, str(whole_interface))

        if speed is not None:
            #if description is None or len(description) == 0:
            #    pass
            #else:
                # In the Cisco world, links to other switches are known as “Trunk” ports and links to end devices like PCs are known as “Access” ports.
                # On a port, which is an Access Port, the Untagged VLAN is called the Access VLAN
                # On a port, which is a Trunk Port, the Untagged VLAN is called the Native VLAN.
            if access_vlan is None:
                G_layer_2.add_node(str(whole_interface), description=description, name=str(whole_interface))
                G_layer_2.add_edge(hostname, str(whole_interface))
            else:
                G_layer_2.add_node(str(whole_interface), description=description, name=str(whole_interface))
                G_layer_2.add_edge(hostname, str(whole_interface), access_vlan=access_vlan)
        else:
            new_names = []
            for declared_name in declared_names:
                if str(interface) != declared_name:
                    new_names.append(declared_name)
            augmented_name = str(interface)
            for new_name in new_names:
                augmented_name += '\n' + new_name
            primary_address = str(interface_row[1]['Primary_Address'])
            G_layer_3.add_node(str(interface), description=description, name=str(augmented_name))
            G_layer_3.add_edge(hostname, interface, ip_address=primary_address)

def plot_graph(G_layer_2, color_map, fig_number, title, show=True, layer_2=False, filename=None):
    fig = plt.figure(fig_number, figsize=(12, 12))
    fig.clf()
    ax = fig.add_subplot(111)
    #fig, ax = plt.subplots(1)
    margin = 0.44 #.33
    fig.subplots_adjust(margin, margin, 1. - margin, 1. - margin)
    plt.title(title)
    if layer_2:
        edge_labels = nx.get_edge_attributes(G_layer_2, 'access_vlan')
    else:
        edge_labels = nx.get_edge_attributes(G_layer_2, 'ip_address')

    node_labels = nx.get_node_attributes(G_layer_2, 'name')
    node_labels_description = nx.get_node_attributes(G_layer_2, 'description')
    for node,desc in node_labels_description.items():
        if desc is not None:
            node_labels[node] += '\n' + desc
    node_labels_node_type = nx.get_node_attributes(G_layer_2, 'type')
    for node,node_types in node_labels_node_type.items():
        if node_types is not None:
            node_labels[node] += '\n' + node_types
    num_nodes = G_layer_2.number_of_nodes()
    weight = 2.5/math.sqrt(num_nodes) # higher-weight -> edges are longer between connected nodes
    pos= nx.spring_layout(G_layer_2, k = weight)
    nx.draw(G_layer_2, pos=pos, node_color=color_map, with_labels=True, font_size=0, node_size=1200) #, edge_labels = edge_labels)
    nx.draw_networkx_edge_labels(G_layer_2, pos, edge_labels=edge_labels)
    nx.draw_networkx_labels(G_layer_2, pos, labels=node_labels)
    ###############
    # adding a textbox: https://matplotlib.org/3.1.1/gallery/recipes/placing_text_boxes.html
    textstr = 'Red: Devices\nGreen:Interfaces'
    props = dict(boxstyle='round', facecolor='wheat', alpha=0.5)
    ax.text(0.02, 0.98, textstr, transform=ax.transAxes, fontsize=5,
            verticalalignment='top', bbox=props)
    ##############
    #labels = nx.draw_networkx_labels(G, pos=nx.spring_layout(G))
    #plt.tight_layout()
    # now make the subplot size slightly larger...
    plt.draw()
    if filename is not None:
        plt.savefig(fname=filename)

    if show:
        plt.show()

def create_gns3_rough_draft():
    # TODO: check that GNS3 is current running

    # TODO: clear project OR make new project (just make sure there's nothing remaining)

    # TODO: add all nodes (just go through graph and add all the devices)

    # TODO: add all of the edges

    # the above steps are easy for switches... but what about routers...

    pass

def create_gns3_copy():
    auth_tuple = ('admin', 'iSJeYlFLUSwnKDHA9F3jWYLkioJ5Nn6mrEVgCp06VT9kL08bPd4qmTBANfCdoRJZ')
    r = requests.get('http://127.0.0.1:3080/v2/version',
                     auth= auth_tuple)
    print(r.json())

    d = {"name": "testadfgadx",
         "project_id": "ca29d215-eb6c-4562-a8db-2d03a1844b18"}

    r = requests.post("http://localhost:3080/v2/projects",
                      auth=auth_tuple, json=d)

    print("project_creation_response: ", r.json(), r.status_code)

    if r.status_code == 409:
        print("deleting previously existing project")

        r = requests.delete('http://localhost:3080/v2/compute/projects/' + d['project_id'],
                        auth= auth_tuple)
        print(r.json())

        r = requests.post("http://localhost:3080/v2/projects",
                          auth=auth_tuple, json=d)

        print(r.json())

    project_id = r.json()['project_id']

    # might not be open, so we need to open it ourselves...
    r = requests.post("http://localhost:3080/v2/projects/" + project_id + '/open',
                      auth=auth_tuple, json=d)
    print("response to post to open the project:", r.json())

    node1 = {"name": "VPCS 1", "node_type": "vpcs", "compute_id": "local"}
    node2 = {"name": "VPCS 2", "node_type": "vpcs", "compute_id": "local"}

    # make some nodes
    #headers = {'content-type': 'application/json'}
    r = requests.post("http://localhost:3080/v2/projects/" + project_id + "/nodes",
                     auth=auth_tuple, json=node1)
    print("node1_response", r.json())
    node_id_1 = r.json()['node_id']
    r = requests.post("http://localhost:3080/v2/projects/" + project_id + "/nodes",
                     auth=auth_tuple, json=node2)
    print("node2_response", r.json())
    node_id_2 = r.json()['node_id']
    ####

    # now link the nodes that we made
    # TODO TODO: fill in the None categories (what is the adapter number??)
    link_config = { "nodes": [{"adapter_number": 0, "node_id" : node_id_1, "port_number": 0},
                              {"adapter_number": 0, "node_id" : node_id_2, "port_number": 0}]}
    r = requests.post("http://localhost:3080/v2/projects/" + project_id + "/links",
                     auth=auth_tuple,
                      json=link_config)

    print("**link_response:", r.json())

    # curl -X POST  "http://localhost:3080/v2/projects/b8c070f7-f34c-4b7b-ba6f-be3d26ed073f/links" -d '
    #       {"nodes": [{"adapter_number": 0, "node_id": "f124dec0-830a-451e-a314-be50bbd58a00", "port_number": 0},
    #                  {"adapter_number": 0, "node_id": "83892a4d-aea0-4350-8b3e-d0af3713da74", "port_number": 0}]}'

    # let's try exporting this thing...
    ##### GET /v2/projects/{project_id}/export¶
    #header = {'Accept': 'application/json'}
    d = {'project_id': project_id}
    r = requests.get("http://localhost:3080/v2/projects/" + project_id + "/export",
                      auth=('admin', 'iSJeYlFLUSwnKDHA9F3jWYLkioJ5Nn6mrEVgCp06VT9kL08bPd4qmTBANfCdoRJZ'),
                     json = d)
    print(r)
    #print(r.text)

    #print("export_project_response", r.json())

    with open('gns3_archive.zip', 'wb') as f:
        f.write(r.content)

def discover_important_device_info(G,  color_map, title, figname, intermediate_scenario_directory, DEBUG,
                                   intermediate_scenario_directory_hosts, level_1_topology_path, intermediate_scenario_directory_iptables,
                                   layer_2=True):
    interface_information_inputted_manually = []
    print("These are the nodes in the graph:")
    for node in G.nodes():
        print(node)
    node_types = {'switch', 'router', 'host', 'asa'}
    prompt_for_interface_info = "Are any of the interfaces connected to important devices for which we lack the config files?\n" \
                                "If so, please give: interface-name, type-of-device (i.e. switch, router, host, or asa)"
    while True:
        print("----------------")
        #print("Are any of these interfaces connected?")
        node_value, type_of_node = '',''
        while True:
            value1 = input(prompt_for_interface_info)
            if value1 == '':
                break
            if ',' not in value1:
                print("there was no comma! please correct your input and re-enter it")
                continue
            node_value, type_of_node = value1.split(',')
            node_value, type_of_node  = node_value.strip(), type_of_node.strip()
            value1 = map_to_node_or_none(node_value, G)

            if type_of_node not in node_types:
                print("the type of node (i.e. switch, router, etc.) unrecognized. please correct your input and re-enter it (unrecongized value was: ", node_value, ")")
                continue

            if value1 != None:
                break

            interface_information_inputted_manually.append((node_value, type_of_node))

        if value1 == '':
            break

        if type_of_node == 'host':
            ## here's the code to generate the needed config file here
            prompt_for_host_info = 'Please enter followig information about host: hostname, gateway_ip, host_ip, subnet_mask'
            vals = input(prompt_for_host_info)
            hostname, gateway_ip, host_ip, subnet_mask = vals.split(',')
            hostname, gateway_ip, host_ip, subnet_mask = hostname.strip(), gateway_ip.strip(), host_ip.strip(), subnet_mask.strip()
            host_interface = add_generic_host(hostname, intermediate_scenario_directory_hosts, gateway_ip, host_ip, subnet_mask)

            ## also, update the layer-1 toplogy file...
            device_name, device_interface = split_interface_name(node_value)
            return_val = generate_layer_1_topology_config_file(level_1_topology_path, hostname, host_interface, device_name, device_interface)
            add_iptables_accept_all(filename='generic.iptables', path_to_drectory = intermediate_scenario_directory_iptables)
        else:
            print('that node type is not supported!')
            exit(1)

        ## regenerate graphs here
        G, G_layer_2, G_layer_3, color_map = generate_graph_representations(intermediate_scenario_directory, DEBUG)
        ## TODO: add third line that shows type of the node (? maybe ?)
        # hostname, gateway_ip, host_ip, subnet_mask
        attrs = {node_value: {'type': type_of_node}}
        nx.set_node_attributes(G, attrs)
        plot_graph(G_layer_2, color_map, fig_number=4, title=title, show=True, layer_2=layer_2)

    plot_graph(G, color_map, fig_number=4, title=title, show=False, layer_2=layer_2)
    plt.tight_layout()
    plt.savefig(fname=figname)

    return G, interface_information_inputted_manually

def add_iptables_accept_all(filename, path_to_drectory):
    shutil.copyfile(filename, path_to_drectory + '/' + filename)

def add_generic_host(hostname, path_to_directory, gateway_ip, host_ip, subnet_mask):
    filename = path_to_directory + '/' + hostname + '.json'

    # check if file exists
    if os.path.exists(filename):
        print("the config for this host already exists, but let's keep going anyway...")

    new_host = {}
    new_host['hostname'] = hostname
    new_host['iptablesFile'] = 'iptables/generic.iptables'
    new_host['hostInterfaces'] = {}
    new_host['hostInterfaces']['eth0'] = {}
    new_host['hostInterfaces']['eth0']['name'] = "eth0"
    new_host['hostInterfaces']['eth0']['prefix'] = host_ip + '/' + subnet_mask # TODO
    new_host['hostInterfaces']['eth0']['gateway'] = gateway_ip

    # write out the file to the correct location
    with open(filename, 'w') as outfile:
        json.dump(new_host, outfile, indent=4)

    return 'eth0'

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
