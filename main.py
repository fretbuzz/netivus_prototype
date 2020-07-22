import docker, os

import pandas as pd
from pybatfish.client.commands import *
from pybatfish.datamodel import *
from pybatfish.datamodel.answer import *
from pybatfish.datamodel.flow import *
from pybatfish.question import *
from pybatfish.question import bfq

import networkx as nx
import matplotlib.pyplot as plt
import os, errno
import math

def main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH):
    run_batfish(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH)

def run_batfish(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH):
    #% run startup.py
    #bf_session.host = "172.0.0.1"  # <batfish_service_ip>
    bf_session.host = 'localhost'
    bf_session.port = '9996'

    bf_set_network(NETWORK_NAME)
    bf_init_snapshot(SNAPSHOT_PATH, name=SNAPSHOT_NAME, overwrite=True)

    load_questions()

    #print(list_questions())

    pd.options.display.max_columns = 6

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

    edge_dataframe = bfq.edges().answer().frame()
    edges_layer1_dataframe = bfq.layer1Edges().answer().frame()
    edge_interfaces = set()
    add_edges_to_graphs(edge_dataframe, G, G_layer_2, G_layer_3, color_map, edge_interfaces, edges_layer1_dataframe)

    interface_dataframe = bfq.interfaceProperties().answer().frame()
    add_interfaces_to_graphs(interface_dataframe, G, G_layer_2, G_layer_3, color_map)

    plt.figure(3, figsize=(12, 12))
    plt.title('devices (red) & interfaces (green)')
    nx.draw(G, node_color=color_map, with_labels=True)
    #labels = nx.draw_networkx_labels(G, pos=nx.spring_layout(G))
    plt.draw()
    plt.show()

    plot_graph(G_layer_2, color_map, fig_number=4, title='layer_2_connectivity')

    try:
        os.makedirs("./outputs/" + NETWORK_NAME )
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    G_layer_2, manually_connected_layer2_nodes = \
        connect_nodes_via_manual_analysis(G_layer_2, color_map, title='layer_2_connectivity',
                                          figname="./outputs/" + NETWORK_NAME + "/layer_2_diagram.png" )


    plot_graph(G_layer_3, color_map, fig_number=5, title='layer_3_connectivity')

    G_layer_3, manually_connected_layer3_nodes = \
        connect_nodes_via_manual_analysis(G_layer_3, color_map, title='layer_3_connectivity',
                                          figname="./outputs/" + NETWORK_NAME + "/layer_3_diagram.png")

def connect_nodes_via_manual_analysis(G_layer_2, color_map, title, figname):
    connected_interfaces_via_manual_analysis = []
    prompt_for_connected_interfaces = "Please enter one of the connected interfaces (hit enter if none are connected): "
    while True:
        print("----------------")
        print("Are any of these layer2 interfaces connected?")
        while True:
            value1 = input(prompt_for_connected_interfaces)
            if value1 == '':
                break
            if value1 in G_layer_2.nodes():
                break
            else:
                node_labels_description = nx.get_node_attributes(G_layer_2, 'description')
                if value1 in node_labels_description.values():
                    found_node = None
                    not_unique = False
                    for node,desc in node_labels_description.items():
                        if desc == value1:
                            if found_node is None:
                                found_node = node
                            else:
                                print("That value is not a unique identifier for this graph")
                                not_unique = True
                                break

                    if not not_unique and found_node is not None:
                        print("that node was found, even tho you used the description and not the name!")
                        value1 = found_node
                        break
                else:
                    print("That node was not recognized. Please check the spelling and try again")
        if value1 == '':
            break

        while True:
            value2 = input(prompt_for_connected_interfaces)
            if value2 == '':
                break
            if value2 in G_layer_2.nodes():
                break
            else:
                node_labels_description = nx.get_node_attributes(G_layer_2, 'description')
                if value2 in node_labels_description.values():
                    found_node = None
                    not_unique = False
                    for node, desc in node_labels_description.items():
                        if desc == value2:
                            if found_node is None:
                                found_node = node
                            else:
                                print("That value is not a unique identifier for this graph")
                                not_unique = True
                                break

                    if not not_unique and found_node is not None:
                        print("that node was found, even tho you used the description and not the name!")
                        value2 = found_node
                        break
                else:
                    print("That node was not recognized. Please check the spelling and try again")
        if value2 == '':
            break

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

        plot_graph(G_layer_2, color_map, fig_number=4, title=title, show=True)

    plot_graph(G_layer_2, color_map, fig_number=4, title=title, show=False)
    plt.tight_layout()
    plt.savefig(fname= figname)

    return G_layer_2, connected_interfaces_via_manual_analysis

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
    for edge in edge_dataframe.iterrows():
        local_interface = edge[1]['Interface']
        local_device = local_interface.hostname
        local_vlan = local_interface.interface
        G.add_node(str(local_interface), type='interface', name=str(local_interface))
        color_map.append('green')
        G.add_edge(local_device, local_interface)
        local_ip, remote_ip = list(edge[1]['IPs']), list(edge[1]["Remote_IPs"])

        remote_interface = edge[1]['Remote_Interface']
        remote_device = remote_interface.hostname
        remote_vlan = remote_interface.interface
        print("lr", local_interface, remote_interface)
        G.add_node(str(remote_interface), type='interface', name=str(remote_interface))
        color_map.append('green')
        G.add_edge(remote_device, remote_interface)

        edge_interfaces.add(local_interface)
        edge_interfaces.add(remote_interface)

        if local_vlan != remote_vlan:
            exit('why does local_vlan not equal remote_vlan!?!')

        G.add_edge(local_interface, remote_interface)
        if local_ip is not None and remote_ip is not None:
            # the problem with this is that it doesn't make the type of diagrams that I am looking for
            # G_layer_3.add_edge(local_device, remote_device)
            pass
        # G_layer_2.add_edge(local_device, remote_device)

    for interface_row in edges_layer1_dataframe.iterrows():
        whole_interface = interface_row[1]['Interface']
        hostname = whole_interface.hostname
        interface = whole_interface.interface

        description = interface_row[1]['Description']
        native_vlan =  interface_row[1]['Native_VLAN']

        G_layer_2.add_edge(hostname, str(whole_interface), vlan=native_vlan)

def add_interfaces_to_graphs(interface_dataframe, G, G_layer_2, G_layer_3, color_map):
    for counter, interface_row in enumerate(interface_dataframe.iterrows()):
        whole_interface = interface_row[1]['Interface']
        hostname = whole_interface.hostname
        interface = whole_interface.interface

        description = interface_row[1]['Description']
        native_vlan = interface_row[1]['Native_VLAN']
        access_vlan = interface_row[1]['Access_VLAN']
        allowed_vlans = interface_row[1]['Allowed_VLANs']

        G.add_node(str(whole_interface), type='interface', description=description, name=str(whole_interface))
        color_map.append('green')
        G.add_edge(hostname, str(whole_interface))

        if interface_row[1]['Primary_Address'] is None:
            if description is None or len(description) == 0:
                pass
            else:
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
            primary_address = interface_row[1]['Primary_Address']
            G_layer_3.add_node(str(interface), description=description, name=str(whole_interface))
            G_layer_3.add_edge(hostname, interface, ip_address=primary_address)

def plot_graph(G_layer_2, color_map, fig_number, title, show=True):
    fig = plt.figure(fig_number, figsize=(12, 12))
    ax = fig.add_subplot(111)
    #fig, ax = plt.subplots(1)
    margin = 0.44 #.33
    fig.subplots_adjust(margin, margin, 1. - margin, 1. - margin)
    plt.title(title)
    edge_labels = nx.get_edge_attributes(G_layer_2, 'access_vlan')
    node_labels = nx.get_node_attributes(G_layer_2, 'name')
    node_labels_description = nx.get_node_attributes(G_layer_2, 'description')
    for node,desc in node_labels_description.items():
        if desc is not None:
            node_labels[node] += '\n' + desc
    num_nodes = G_layer_2.number_of_nodes()
    weight = 2/math.sqrt(num_nodes)
    pos= nx.spring_layout(G_layer_2, k = weight)
    nx.draw(G_layer_2, pos=pos, node_color=color_map, with_labels=True, font_size=0, node_size=1200) #, edge_labels = edge_labels)
    nx.draw_networkx_edge_labels(G_layer_2, pos, edge_labels=edge_labels)
    nx.draw_networkx_labels(G_layer_2, pos, labels=node_labels)
    ###############
    # adding a textbox: https://matplotlib.org/3.1.1/gallery/recipes/placing_text_boxes.html
    textstr = 'Red: Devices\nGreen:Interfaces'
    props = dict(boxstyle='round', facecolor='wheat', alpha=0.5)
    ax.text(0.02, 0.98, textstr, transform=ax.transAxes, fontsize=14,
            verticalalignment='top', bbox=props)
    ##############
    #labels = nx.draw_networkx_labels(G, pos=nx.spring_layout(G))
    #plt.tight_layout()
    # now make the subplot size slightly larger...
    plt.draw()
    if show:
        plt.show()

if __name__ == "__main__":
    # Initialize a network and snapshot
    #'''
    # IP address conflict (the HotNets example)
    NETWORK_NAME = "example_network"
    SNAPSHOT_NAME = "example_snapshot"
    SNAPSHOT_PATH = "./scenarios/Access port config"
    #'''

    '''
    # ???
    NETWORK_NAME = "example_network_asdm"
    SNAPSHOT_NAME = "example_snapshot_asdm"
    SNAPSHOT_PATH = "./scenarios/Cisco ASA 5505 doesn't allow internet connection"
    #'''

    main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH)

    # note: I can interact with the local GNS3 server (and it's API) using these commands:
    # curl -i -u 'admin:iSJeYlFLUSwnKDHA9F3jWYLkioJ5Nn6mrEVgCp06VT9kL08bPd4qmTBANfCdoRJZ' http://127.0.0.1:3080/v2/version
