import networkx as nx
import pandas as pd
from pybatfish.client.commands import bf_set_network, bf_init_snapshot
from pybatfish.question import load_questions, bfq
import matplotlib.pyplot as plt
from visualization import plot_graph
import os, json, shutil

def discover_important_device_info(G,  color_map, title, figname, intermediate_scenario_directory, DEBUG,
                                   intermediate_scenario_directory_hosts, level_1_topology_path, intermediate_scenario_directory_iptables,
                                   NETWORK_NAME, SNAPSHOT_NAME, layer_2=True):
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
        G, G_layer_2, G_layer_3, color_map = generate_graph_representations(intermediate_scenario_directory, DEBUG, NETWORK_NAME, SNAPSHOT_NAME)
        ## TODO: add third line that shows type of the node (? maybe ?)
        # hostname, gateway_ip, host_ip, subnet_mask
        attrs = {node_value: {'type': type_of_node}}
        nx.set_node_attributes(G, attrs)
        plot_graph(G_layer_2, color_map, fig_number=4, title=title, show=True, layer_2=layer_2)

    plot_graph(G, color_map, fig_number=4, title=title, show=False, layer_2=layer_2)
    plt.tight_layout()
    plt.savefig(fname=figname)

    return G, interface_information_inputted_manually

def connect_nodes_via_manual_analysis(title, figname, intermediate_scenario_directory, DEBUG, level_1_topology_path,
                                      NETWORK_NAME, SNAPSHOT_NAME, layer_2=True):

    G, G_layer_2, G_layer_3, color_map = generate_graph_representations(intermediate_scenario_directory, DEBUG, NETWORK_NAME, SNAPSHOT_NAME)
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
        G, G_layer_2, G_layer_3, color_map = generate_graph_representations(intermediate_scenario_directory, DEBUG,
                                                                            NETWORK_NAME, SNAPSHOT_NAME)


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


def generate_graph_representations(intermediate_scenario_directory, DEBUG, NETWORK_NAME, SNAPSHOT_NAME):
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
        ##G.add_node(str(local_interface), type='interface', name=str(local_interface))

        color_map.append('lightgreen')
        ##G.add_edge(str(local_device), str(local_interface))
        local_ip, remote_ip = list(edge[1]['IPs']), list(edge[1]["Remote_IPs"])

        remote_interface = edge[1]['Remote_Interface']
        remote_device = remote_interface.hostname
        remote_vlan = remote_interface.interface
        print("lr", local_interface, remote_interface)
        ##G.add_node(str(remote_interface), type='interface', name=str(remote_interface))
        color_map.append('lightgreen')
        ###G.add_edge(str(remote_device), str(local_interface))

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

        G.add_edge(str(local_interface), str(remote_interface))
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
