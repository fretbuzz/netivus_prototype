import pandas as pd
from pybatfish.client.commands import *
from pybatfish.datamodel import *
from pybatfish.datamodel.answer import *
from pybatfish.datamodel.flow import *
from pybatfish.question import *
from pybatfish.question import bfq
from augment_network_representation import generate_graph_representations
import networkx as nx
import ipaddress
import pickle
from gui import collab_suggests_refinement, collab_fixes_config_file, user_says_if_fix_works
import visualization
import subprocess

def debug_network_problem(start_location, end_location, dst_ip, src_ip, protocol, desired_path, type_of_problem,
                          intermediate_scenario_directory, srcPort, dstPort, ipProtocol, NETWORK_NAME, SNAPSHOT_NAME, DEBUG,
                          return_after_recreation):
    return_after_recreation = True # remove after testing
    given_desired_path = False
    if desired_path:
        given_desired_path = True

    while True:
        # make sure that graph representation is up to date...
        G, G_layer_2, G_layer_3, color_map = generate_graph_representations(intermediate_scenario_directory, DEBUG,
                                                                            NETWORK_NAME, SNAPSHOT_NAME)

        # TODO: is the topology connecteD?
        is_topology_connected()

        # TODO: can the problem be recreated?
        can_problem_be_recreated_p, problematic_path_forward, problematic_path_return, should_we_debug_the_path_forward, return_immediately = \
            can_problem_be_recreated(type_of_problem, start_location, dst_ip, src_ip, end_location, srcPort, dstPort, ipProtocol)

        if return_immediately or return_after_recreation:
            print_status_of_reproduction(can_problem_be_recreated_p, problematic_path_forward, problematic_path_return,\
                                         type_of_problem, start_location, dst_ip, src_ip, end_location)
            return can_problem_be_recreated_p, should_we_debug_the_path_forward

        if not can_problem_be_recreated_p:
            # TODO: if it cannot be recreated, refine (w/ help from collabs)
            should_we_rerun = refine_network_representation_with_collab(problematic_path_forward, type_of_problem)
            if should_we_rerun:
                continue

        # we can recreate the problem, so we can attempt to debug (though we might find out that we cannot later on)
        # TODO: generate all possible desired_paths (ranked from most likely to least likely)
        ## for now, we can just use the given one above (for convenience...)
        if should_we_debug_the_path_forward:
            path_to_debug = problematic_path_forward
            desired_paths = generate_desired_paths(desired_path, intermediate_scenario_directory, DEBUG, NETWORK_NAME, SNAPSHOT_NAME,
                                                   type_of_problem,
                                                   src_loc=start_location, dest_loc=end_location,
                                                   traceroute_path=problematic_path_forward)
        else:
            path_to_debug = problematic_path_return
            desired_paths = generate_desired_paths(desired_path, intermediate_scenario_directory, DEBUG, NETWORK_NAME, SNAPSHOT_NAME,
                                                   type_of_problem,
                                                   src_loc = end_location, dest_loc = start_location,
                                                   traceroute_path = problematic_path_forward)

        #if desired_path_index > len(desired_paths):
        #    raise('ran out of desired paths to examine')
        must_revisit_network_model = False
        for index in range(0, len(desired_paths)):
            overlap_score, desired_path = desired_paths[index]
            # TODO: for a given problematic path, guess which device is responsible
            ## rank these in order from most likely responsible to least likely responsible
            possible_explanations = generate_guesses_for_remediation(path_to_debug, given_desired_path, desired_path, type_of_problem)

            while True:
                # TODO: switch G_layer_2 to G
                collab_approved_potential_root_causes, collab_approved_potential_fix = \
                    collaborate_indicates_potential_root_causes_and_fixes(possible_explanations, srcPort, dstPort,
                                                                          ipProtocol, start_location, end_location,
                                                                          dst_ip, src_ip, protocol, type_of_problem,
                                                                          G_layer_2, color_map, intermediate_scenario_directory)

                print("updated collab_approved_potential_fix file:", collab_approved_potential_fix)

                if collab_approved_potential_root_causes is None:
                    break

                # now test if the solution worked...
                is_problem_fixed_on_model_p = check_if_suggested_solution_works_on_model(intermediate_scenario_directory, DEBUG, NETWORK_NAME, SNAPSHOT_NAME,
                                                                                         type_of_problem, start_location, dst_ip, src_ip, end_location, srcPort,
                                                                                         dstPort, ipProtocol)

                # if not fixed (according to our model), then write that that did not work and loop
                if not is_problem_fixed_on_model_p:
                    # TODO: probably want to do more here (for instance, keep some kinda library of fixes, or whatever)
                    print("That solution did not work!!")
                    continue

                # if it did fix it (according to our model), then we can ask the admin if this really does fix it
                correct_root_cause, must_revise_network_model, new_constraints = admin_checks_root_cause(collab_approved_potential_root_causes, collab_approved_potential_fix)

                if correct_root_cause:
                    return correct_root_cause, should_we_debug_the_path_forward
                elif must_revise_network_model:
                    ## TODO: have operator revise the network model
                    ## TODO: take into account the additional connectivity constraints
                    must_revisit_network_model = True
                    break

            if must_revisit_network_model:
                break

def admin_checks_root_cause(collab_approved_potential_root_causes, collab_approved_potential_fix):
    # the purpose of this function is to show the changes to the admin and have them tell you if they worked
    # most work will be offloaded to a function in the gui file
    device = collab_approved_potential_fix[0]
    new_config_file_text = collab_approved_potential_fix[1]
    path_to_this_config_file = collab_approved_potential_fix[2]

    print("collab_approved_potential_root_causes", collab_approved_potential_root_causes)
    did_it_work = user_says_if_fix_works(new_config_file_text, device, high_level_root_cause=collab_approved_potential_root_causes)

    # TODO: must eventually implement the rest of this...
    return did_it_work, None, None

def check_if_suggested_solution_works_on_model(intermediate_scenario_directory, DEBUG, NETWORK_NAME, SNAPSHOT_NAME,
                                               type_of_problem, start_location, dst_ip, src_ip, end_location, srcPort,
                                               dstPort, ipProtocol):

    G, G_layer_2, G_layer_3, color_map = generate_graph_representations(intermediate_scenario_directory, DEBUG,
                                                                        NETWORK_NAME, SNAPSHOT_NAME)

    can_problem_be_recreated_p, problematic_path_forward, problematic_path_return, should_we_debug_the_path_forward, return_immediately = \
        can_problem_be_recreated(type_of_problem, start_location, dst_ip, src_ip, end_location, srcPort,
                                 dstPort, ipProtocol)

    # for now, this return is simple (b/c we only have two types of problems (should connect but can't and can't connect
    # but should). later, with more of these, we will probably need more complicated logic
    return (not can_problem_be_recreated_p)

def collaborate_indicates_potential_root_causes_and_fixes(possible_explanations, srcPort, dstPort, ipProtocol,
                                                          start_location, end_location, dst_ip, src_ip, protocol,
                                                          type_of_problem, G, color_map,
                                                          intermediate_scenario_directory):
    # this function does two things:
    # (1) shows the list of possible fixes to the admin and have them indicate which is likely
    # (2) based on the response to (1), have the operator indicate the potential fix (i.e. the step-by-step actions)

    # step one is to display the relevant info to the collab and have them indicate which fix is likely to work
    # use the GUI function TODO this...
    network_img_path = intermediate_scenario_directory + '_connecitivty_graph.png'
    subprocess.check_output(['convert', network_img_path, network_img_path.replace('png','gif')])
    visualization.plot_graph(G, color_map, fig_number=9, title="Network", show=False, layer_2=False, filename=network_img_path)
    list_of_pkt_header_restrictions = construct_list_of_pkt_header_restrictions(srcPort, dstPort, ipProtocol, start_location,
                                                                                end_location, dst_ip, src_ip, protocol,
                                                                                type_of_problem)

    index_of_refinement_layout_to_try, choice_tab_layout = collab_suggests_refinement( network_img_path.replace('png','gif'), list_of_pkt_header_restrictions, possible_explanations,
                               config_file_text_list = [])


    # now fix the relevant config file
    file_parse_status_dataframe = bfq.fileParseStatus().answer().frame()
    relevant_device = possible_explanations[index_of_refinement_layout_to_try][1]
    parse_status_of_this_device = file_parse_status_dataframe.loc[file_parse_status_dataframe['Nodes'].apply(lambda x: x==[relevant_device])]

    path_to_config_file = intermediate_scenario_directory + '/' + list(parse_status_of_this_device['File_Name'])[0]
    with open(path_to_config_file, 'r') as f:
        config_file_text = f.read()

    updated_config_file = collab_fixes_config_file(config_file_text, choices_tab_layout=None)
    with open(path_to_config_file, 'w') as f:
        f.write(updated_config_file)

    print("checkpoint_here", parse_status_of_this_device)

    return possible_explanations[index_of_refinement_layout_to_try], (relevant_device, updated_config_file, path_to_config_file)

def construct_list_of_pkt_header_restrictions(srcPort, dstPort, ipProtocol, start_location, end_location, dst_ip,
                                              src_ip, protocol, type_of_problem):
    list_of_pkt_restrictions = []
    list_of_pkt_restrictions.append("type_of_problem: " + str(type_of_problem))
    list_of_pkt_restrictions.append("src_ip: " + str(src_ip))
    list_of_pkt_restrictions.append("dst_ip: " + str(dst_ip))
    list_of_pkt_restrictions.append("src_port: " + str(srcPort))
    list_of_pkt_restrictions.append("dst_port: " + str(dstPort))
    list_of_pkt_restrictions.append("protocol: " + str(protocol))
    list_of_pkt_restrictions.append("ipProtocol: " + str(ipProtocol))
    list_of_pkt_restrictions.append("start_location: " + str(start_location))
    list_of_pkt_restrictions.append("end_location: " + str(end_location))
    return list_of_pkt_restrictions

def print_status_of_reproduction(can_problem_be_recreated_p, problematic_path_forward, problematic_path_return,
                                         type_of_problem, start_location, dst_ip, src_ip, end_location):
    print("--------------------")
    print("--------------------")
    print("- Type of Problem:", type_of_problem)
    print("- Src_ip:", src_ip, "; Dst_ip:", dst_ip)
    print("- Start_loc: ", start_location, "; End_loc: ", end_location)
    print("- Forward path:")
    if problematic_path_forward is None:
        print(problematic_path_forward)
    else:
        for step in problematic_path_forward:
            print('\t',  step)
    print("- Return path:")
    if problematic_path_return is None:
        print(problematic_path_return)
    else:
        #show(problematic_path_return)
        for step in problematic_path_return:
            print('\t',  step)
    print("- Can the problem be recreated: ", can_problem_be_recreated_p)

def generate_guesses_for_remediation(path_to_debug, given_desired_path, desired_path, type_of_problem):
    possible_explanations = []
    responsible_devices = guess_which_devices_are_responsible(path_to_debug, desired_path, given_desired_path, type_of_problem)

    for responsible_device in responsible_devices:
        # for a given problematic path + device, blame the particular part of the device
        potential_explanation = diagnose_root_cause(desired_path, path_to_debug, responsible_device, type_of_problem)
        possible_explanations.append( (potential_explanation, get_node_name(responsible_device), " -> ".join(desired_path)) )

    return possible_explanations


def can_problem_be_recreated(type_of_problem, start_location, dst_ip, src_ip, end_location, srcPort, dstPort, ipProtocol):
    if '[' in start_location:
        forward_hops, return_hops = run_traceroute('@enter(' + start_location + ')', dst_ip, src_ip, srcPort, dstPort, ipProtocol)
    else:
        forward_hops, return_hops = run_traceroute(start_location, dst_ip, src_ip, srcPort, dstPort, ipProtocol)
    #final_node = forward_hops[-1].node
    print("forward_hops", forward_hops)
    print("return_hops", return_hops)
    forward_final_interface, forward_final_node = find_final_interface_and_node(forward_hops, forward=True)
    return_final_interface, return_final_node = find_final_interface_and_node(return_hops, forward=False)

    # start_location and end_location can be specified as devices (instead of interfaces),
    # so we need to check that case too
    src_can_reach_dst_p = (forward_final_interface == end_location) or (forward_final_node == end_location)
    dst_can_reach_src_p = (return_final_interface == start_location) or (return_final_node == start_location)


    should_we_debug_the_path_forward = None #### if we can
    can_we_recreate_the_problem_p = None
    return_immediately = False

    # run the comparison check here...
    if type_of_problem == "Connecitivity_Blocked_But_Should_Be_Allowed":
        if src_can_reach_dst_p and dst_can_reach_src_p:
            # if the problem is that we CANNOT reach the destination, then if we cam reach the destination
            ## we CANNOT recreate the problem
            can_we_recreate_the_problem_p = False
            should_we_debug_the_path_forward = None # irrelevant b/c we cannot recreate the problem
            #return False, forward_hops, return_hops, should_we_debug_the_path_forward
        else:
            # if the problem is that we CANNOT reach the destination, then if we cannot reach the destination
            ## we CAN recreate the problem
            can_we_recreate_the_problem_p = True
            # if problem is that we CANNOT reach the destination, then if we cannot reach the destination going
            ## forward, then we need to debug the forward path
            should_we_debug_the_path_forward = not src_can_reach_dst_p
            #return True, forward_hops, return_hops, should_we_debug_the_path_forward
    elif type_of_problem =="Connecitivity_Allowed_But_Should_Be_Blocked":
        if src_can_reach_dst_p and dst_can_reach_src_p:
            # if the problem is that we CAN reach the destination, then if we can reach the destination
            ## we can recreate the problem
            can_we_recreate_the_problem_p = True
            should_we_debug_the_path_forward = not src_can_reach_dst_p # TODO© how to do this??
            #return True, forward_hops, return_hops, should_we_debug_the_path_forward
        else:
            # if the problem is that we CAN reach the destination, then if we cannot reach the destination
            ## we cannot recreate the problem
            can_we_recreate_the_problem_p = False

            # if problem is that we CAN reach the destination, then if we CAN reach the destination going
            ## forward, then we need to debug the forward path
            should_we_debug_the_path_forward = src_can_reach_dst_p
            #return False, forward_hops, return_hops, should_we_debug_the_path_forward
    elif type_of_problem == "Connectivity_Allowed_And_Should_Be_Allowed":
        return_immediately = True

        if src_can_reach_dst_p and dst_can_reach_src_p:
            can_we_recreate_the_problem_p = True
            should_we_debug_the_path_forward = None # no problem at all, so set to None
        else:
            can_we_recreate_the_problem_p = False
            should_we_debug_the_path_forward = not src_can_reach_dst_p # if cannot connect forward, then should look at forward path

    elif type_of_problem == "Connectivity_Blocked_And_Should_Be_Blocked":
        return_immediately = True

        if src_can_reach_dst_p and dst_can_reach_src_p:
            can_we_recreate_the_problem_p = False
            should_we_debug_the_path_forward = None # no way to know if should be blocked going there or back, so set to None as a sentinal value
        else:
            can_we_recreate_the_problem_p = True
            should_we_debug_the_path_forward = None # no problem at all, so set to None
    else:
        raise("Unsupported type_of_problem")

    return can_we_recreate_the_problem_p, forward_hops, return_hops, should_we_debug_the_path_forward, return_immediately


def find_final_interface_and_node(forward_hops, forward):
    if forward_hops is None:
        return None, None

    final_node = forward_hops[-1]
    # not sure if the final behavior will be recieving or transmitting, so we must scan for both
    # but first, check if it was dropped or accepted (which are more "final" than recieved or transmitted)
    final_interface = None

    for step in final_node.steps:
        if step.action == "DENIED":
            # TODO: this case is just a placeholder
            # could be dropped by either an INGRESS or EGRESS filter
            try:
                final_interface = 'DENIED:' + final_node.node + '[' + step.detail.outputInterface + ']'
            except:
                final_interface = 'DENIED:' + final_node.node + '[' + step.detail.inputInterface + ']'

    if final_interface is None:
        for step in final_node.steps:
            if step.action == "ACCEPTED":
                final_interface = final_node.node + '[' + step.detail.interface + ']'

    if final_interface is None:
        for step in final_node.steps:
            if step.action == "TRANSMITTED":
                final_interface = final_node.node + '[' + step.detail.outputInterface + ']'
            '''
            if forward:
                if step.action == "TRANSMITTED":
                    final_interface = final_node.node + '[' + step.detail.outputInterface + ']'
            else:
                if step.action == "RECEIVED":
                    final_interface = final_node.node + '[' + step.detail.inputInterface + ']'
            '''
    if final_interface is None:
        for step in final_node.steps:
            if step.action == "RECEIVED":
                final_interface = final_node.node + '[' + step.detail.inputInterface + ']'
            '''
            if forward:
                if step.action == "RECEIVED":
                    final_interface = final_node.node + '[' + step.detail.inputInterface + ']'
            else:
                if step.action == "TRANSMITTED":
                    final_interface = final_node.node + '[' + step.detail.outputInterface + ']'
            '''

    return final_interface, final_node.node

def find_transmitted_interface(device_activity):
    recieved_interface = None
    for step in device_activity.steps:
        if step.action == "TRANSMITTED":
            recieved_interface = device_activity.node + '[' + step.detail.outputInterface + ']'
    return recieved_interface

def find_recieved_interface(device_activity):
    transmitted_interface = None
    for step in device_activity.steps:
        if step.action == "RECEIVED":
            transmitted_interface = device_activity.node + '[' + step.detail.outputInterface + ']'
    return transmitted_interface

def refine_network_representation_with_collab(problematic_path, type_of_problem):
    pass

def generate_desired_paths(desired_path, intermediate_scenario_directory, DEBUG, NETWORK_NAME, SNAPSHOT_NAME, type_of_problem,
                           src_loc, dest_loc, traceroute_path):

    if desired_path is not None:
        # we need to get the graph-based
        return [desired_path]
    else:
        ## TODO: *** probably wanna modify this so that interfaces are represented in the graph ***
        # generate possible desired paths and heuristically rank how likely they are
        G, G_layer_1, _, _ = generate_graph_representations(intermediate_scenario_directory, DEBUG, NETWORK_NAME,
                                                            SNAPSHOT_NAME)
        potential_desired_path_generator = nx.all_simple_paths(G, src_loc, dest_loc)

        '''
        print("G has this many edges:", len( [i for i in G.edges()] ))
        if False:
            potential_desired_paths = [i for i in potential_desired_path_generator]
            pickle.dump( potential_desired_paths, open( "save.p", "wb" ) )
        else:
            potential_desired_paths = pickle.load( open( "save.p", "rb" ) )
        '''

        # now rank the paths...
        paths_with_overlapping_score = []
        for potential_desired_path in potential_desired_path_generator:
            interface_by_interface_potential_desired_path = standardize_desired_paths_format(potential_desired_path, type_of_problem)
            traceroute_path_interfaces = construct_interface_by_interface_hops(traceroute_path)
            overlap_score = calculate_overlap(interface_by_interface_potential_desired_path, traceroute_path_interfaces)
            paths_with_overlapping_score.append( (overlap_score, potential_desired_path))

        paths_with_overlapping_score.sort(key= lambda x: (x[0],))
        paths_with_overlapping_score.reverse()
        return paths_with_overlapping_score

def calculate_overlap(potential_desired_path, traceroute_path_interfaces):
    shortest_path = min(potential_desired_path, traceroute_path_interfaces, key= lambda x: len(x))
    #print("potential_desired_path", potential_desired_path)
    #print("traceroute_path", traceroute_path)
    overlapping_node_count = 0
    for index in range(0, len(shortest_path)):
        potential_desired_hop = potential_desired_path[index]
        traceroute_hop = traceroute_path_interfaces[index]

        print(potential_desired_hop, traceroute_hop, potential_desired_hop == traceroute_hop)
        if potential_desired_hop == traceroute_hop:
            overlapping_node_count += 1

    return overlapping_node_count

def standardize_desired_paths_format(potential_desired_path, type_of_problem):
    # need to make the desired_path be in the same format as the traceroute path is after it goes through construct_interface_by_interface_hops

    # first, find which entries are hosts
    host_bools = []
    for hop in potential_desired_path:
        print("hop", hop)
        if '[' in hop and ']' in hop:
            host_bools.append(False)
        else:
            host_bools.append(True)

    # Second, if an interface is directly after a host, then it is outgoing.
    # If an interface is directly before a host, it is incoming.
    new_potential_desired_path = potential_desired_path[:]
    for index in range(0, len(potential_desired_path)):
        if not host_bools[index]: # if it is an interface...
            if index > 0 and host_bools[index-1]: # if the previous entry is a host...
                new_potential_desired_path[index] = 'TRANSMITTED:' + potential_desired_path[index] # then it is being transmitted
            elif index < (len(potential_desired_path) - 1) and host_bools[index + 1] == True: # if the next entry is a host...
                new_potential_desired_path[index] = 'RECEIVED:' + potential_desired_path[index] # then it is being received
            elif index == 0: # if this is the first interface that the packet is coming out of it...
                new_potential_desired_path[index] = 'TRANSMITTED:' + potential_desired_path[index] # then it is being transmitted
            elif index == len(potential_desired_path) - 1: # if this is the last hop
                if type_of_problem == "Connecitivity_Blocked_But_Should_Be_Allowed": # if it should be allowed
                    new_potential_desired_path[index] = 'RECEIVED:' + potential_desired_path[index]  # then last thing will be recieved
                elif type_of_problem == "Connecitivity_Allowed_But_Should_Be_Blocked": # if it should be blocked
                    new_potential_desired_path[index] = 'DENIED:' + potential_desired_path[index]  # then the last thing will be denied
                else:
                    pass
            else:
                raise('unclear how to classify this hop in the desired path: ', potential_desired_path, index)
        ''' # not needed because drops happen on interfaces
        else: # last element in list can be a node and this can deny or accept packets...
            if index == len(potential_desired_path) - 1: # if this is the last hop
                if type_of_problem == "Connecitivity_Blocked_But_Should_Be_Allowed": # if it should be allowed
                    new_potential_desired_path[index] = 'ACCEPTED:' + potential_desired_path[index]  # then last thing will be accepted
                elif type_of_problem == "Connecitivity_Allowed_But_Should_Be_Blocked": # if it should be blocked
                    new_potential_desired_path[index] = 'DENIED:' + potential_desired_path[index]  # then the last thing will be denied
            else:
                new_potential_desired_path[index] =  "AT_NODE:" + potential_desired_path[index]  # then the last thing will be denied
        '''

    return new_potential_desired_path

def guess_which_devices_are_responsible(traceroute_path, desired_path, given_desired_path_p, type_of_problem):
    # this function determines which device performed the direct action on the packet that caused the incorrect behavior...
    ## note: that another device could be ultimately responsible (e.g., originated the route), but it didn't do anything
    ## to the packe

    # Let's start by assuming that the device where a different decision was made is responsible.
    ## In other words, let's find where behavior diverges (e.g., output interface is different, packet filtering is different)

    # iterate through the paths and find the first
    # place where they diverge in behavior. If you get to the end and no divergent behavior is found, then we can blame
    # the last device in the traceroute path
    ## Specifically, check the input and output...


    #### TODO: need to redo this section so that everything is like the first part (And NOT like the second part!)
    if given_desired_path_p:
        interface_by_interface_traceroute_path = construct_interface_by_interface_hops(traceroute_path)
        potentially_responsible_devices = guess_which_devices_are_responsible_user_specified_desired_path(interface_by_interface_traceroute_path, desired_path,
                                                                                                          traceroute_path)
    else:
        potentially_responsible_devices = guess_which_devices_are_responsible_all_paths_system_generated(traceroute_path, desired_path, type_of_problem)

    return potentially_responsible_devices

def guess_which_devices_are_responsible_user_specified_desired_path(interface_by_interface_traceroute_path, interface_by_interface_desired_path,
                                                                    traceroute_path):
    # use the same general logic specified in the parent function
    potentially_responsible_devices = []
    found_responsible_node = False
    responsible_index = None # assign
    min_path_length = min( len(interface_by_interface_traceroute_path), len(interface_by_interface_desired_path) )
    for index in range(0, min_path_length):
        traceroute_interface = interface_by_interface_traceroute_path[index]
        desired_interface = interface_by_interface_desired_path[index]

        # are the interfaces the same? if they are not, then we need to assign blame to the responsible device
        if traceroute_interface != desired_interface:
            # if packet si outgoing, this device is to blame
            action, device_and_interface = traceroute_interface.split(':')
            if action == 'TRANSMITTED' or 'OUTGOING':
                potentially_responsible_devices.append( device_and_interface.split('[')[0] )
                found_responsible_node = True
                responsible_index = index
                break
            elif action == 'RECIEVED':
                prev_device_and_interface = interface_by_interface_traceroute_path[index - 1].split([':'])
                potentially_responsible_devices.append(prev_device_and_interface.split('[')[0])
                found_responsible_node = True
                responsible_index = index
                break

    #  if we haven't found the node where behavior differs, the last node in the shared path is responsible
    if not found_responsible_node:
        ## NOTE: this two cases are the same (could/should probably simplify at some point...)
        if len(interface_by_interface_traceroute_path) < len(interface_by_interface_desired_path):
            # if desired path is longer, but agrees in behavior up to end of traceroute_path, then the last shared node is responsible
            last_interface_by_interface_node = get_node_name(   interface_by_interface_traceroute_path[len(interface_by_interface_traceroute_path) - 1]   )
            potentially_responsible_devices.append(last_interface_by_interface_node)
            responsible_index = len(interface_by_interface_traceroute_path)
        else:
            # if traceroute path is longer, but agrees in behavior up to end of desired_path, then the last shared node is responsible
            last_shareD_interface_by_interface_node = get_node_name(   interface_by_interface_traceroute_path[len(interface_by_interface_desired_path) - 1]   )
            potentially_responsible_devices.append( last_shareD_interface_by_interface_node )
            responsible_index = len(interface_by_interface_desired_path)


    # Now, let's find any devices that transform that packet... look at all devices that come before this in the list
    ## of devices and scan the list of operations for any kind of packet transforms

    # first we must map the interface index to the traceroute index, so that we can use the more detailed info present there
    traceroute_node_index = None #sentinal value
    responsible_node_name = get_node_name( interface_by_interface_traceroute_path[responsible_index] )
    for tr_index, traceroute_hop in enumerate(traceroute_path[:responsible_index]):
        if traceroute_hop.node == responsible_node_name:
            traceroute_node_index = tr_index

    # TODO: what to do here??
    for i in range(0, traceroute_node_index):
        if any_transformations_present(traceroute_path[i]):
            potentially_responsible_devices.append( traceroute_path[i].node)

    return potentially_responsible_devices

def get_node_name(activity_and_interface_str):
    return activity_and_interface_str.split(':')[1].split('[')[0]

def get_node_activity(activity_and_interface_str):
    return activity_and_interface_str.split(':')[0]

def guess_which_devices_are_responsible_all_paths_system_generated(traceroute_path, desired_path, type_of_problem):
    potentially_responsible_devices = []
    found_responsible_node = False
    responsible_index = None # assign

    interface_by_interface_potential_desired_path = standardize_desired_paths_format(desired_path, type_of_problem)
    traceroute_path_interfaces = construct_interface_by_interface_hops(traceroute_path)

    min_path_length = min( len(traceroute_path_interfaces), len(interface_by_interface_potential_desired_path) )
    for index in range(0, min_path_length):
        traceroute_hop = traceroute_path_interfaces[index]
        desired_hop = interface_by_interface_potential_desired_path[index]

        # zeroth, check if the node is the same
        if traceroute_hop != desired_hop:
            # need to look at the *previous* node, since it made the decision to send it here
            potentially_responsible_devices.append(traceroute_path_interfaces[index])
            found_responsible_node = True
            responsible_index = index
            break

        ''' # this code is no longer relevant b/c we modified the paths...
        # first check if the recieved interface/device is different
        traceroute_recieved_interface, desired_recieved_interface = find_recieved_interface(traceroute_hop), find_recieved_interface(desired_hop)
        if traceroute_recieved_interface != desired_recieved_interface:
            # need to look at the *previous* node, since it made the decision to send it her
            potentially_responsible_devices.append(traceroute_path[index - 1].node)
            found_responsible_node = True
            responsible_index = index
            break
        # second check if the transmitted interface/device is different
        traceroute_transmitted_interface, desired_transmitted_interface = find_transmitted_interface(traceroute_hop), find_recieved_interface(desired_hop)
        if traceroute_transmitted_interface != desired_transmitted_interface:
            potentially_responsible_devices.append(traceroute_path[index].node)
            found_responsible_node = True
            responsible_index = index
            break
        '''
    if not found_responsible_node:
        potentially_responsible_devices.append( traceroute_path_interfaces[ min_path_length - 1] )
        responsible_index = traceroute_path_interfaces[ min_path_length - 1]

    # Now, let's find any devices that transform that packet... look at all devices that come before this in the list
    ## of devices and scan the list of operations for any kind of packet transforms

    # first we must map the interface index to the traceroute index, so that we can use the more detailed info present there
    traceroute_node_index = None #sentinal value
    responsible_node_name = get_node_name( traceroute_path_interfaces[responsible_index] )
    for tr_index, traceroute_hop in enumerate(traceroute_path):
        if traceroute_hop.node == responsible_node_name:
            traceroute_node_index = tr_index

    for i in range(0, traceroute_node_index):
        if any_transformations_present(traceroute_path[i]):
            potentially_responsible_devices.append( traceroute_path[i].node)

    return potentially_responsible_devices

def any_transformations_present(cur_hop):
    ## TODO: THIS IS NOT THE RIGHT WAY TO DO THIS!! (But it works for now b/c we don't have a motivating scenario...)
    for step in cur_hop.steps:
        try:
            if step.detail.transformedFlow is not None:
                return True
        except:
            pass
    return False

def diagnose_root_cause(desired_path, traceroute_path, responsible_device, type_of_problem):
    ## TODO: some parts of this function still need to be written
    ### (but basic ACL functionality should be kinda working now...)
    explanation = []

    # Q: Is routing behavior different?
    acl_behavior_differs, desired_path_node_interface_acl_actions, traceroute_path_node_interface_acl_actions = \
        acl_behavior_diferent_p(traceroute_path, desired_path, responsible_device, type_of_problem)
    if acl_behavior_differs:
        acl_explanation =how_is_acl_behavior_different(traceroute_path_node_interface_acl_actions, desired_path_node_interface_acl_actions)
        return acl_explanation
    # Q: Is ACL behavior different?
    elif routing_behavior_different_p(traceroute_path, desired_path, responsible_device):
        # TODO: this whole section is todo
        explanations_about_routes = generate_explanations_for_different_routing(traceroute_path, desired_path, responsible_device)
        explanation.extend( explanations_about_routes )
    else:
        # TODO: this section needs to at least include a function to blame (and assign blame!) to transformation parts, such
        ## as NATs
        pass

    return explanation

def how_is_acl_behavior_different(traceroute_interface_actions, desired_interface_actions):
    # this function determines how the interface actions of the desired and traceroute path are different

    # each device should have at most 2 actions - at ingress and at egress - that involve ACLs
    if len(traceroute_interface_actions) > 2:
        raise("traceroute_interface_actions is longer than 2!!")
    if len(desired_interface_actions) > 2:
        raise ("desired_interface_actions is longer than 2!!")

    # if the actions don't match at the first action -> then it is an ingress problem
    if (len(traceroute_interface_actions)<1 and len(desired_interface_actions) >= 1) or \
        (traceroute_interface_actions[0] != desired_interface_actions[0]):
        return 'Ingress filter is different'

    # if the actions don't match at the second action -> then it is an egress problem
    if (len(traceroute_interface_actions)<2 and len(desired_interface_actions) == 2) or \
       (traceroute_interface_actions[1] != desired_interface_actions[1]) :
        return 'Egress filter is different'


def acl_behavior_diferent_p(traceroute_path, desired_path, responsible_device, type_of_problem):
    # we must map the interface index to the traceroute index, so that we can use the more detailed info present there
    responsible_device_name = get_node_name(responsible_device)

    # get the interface actions that take place on the device that we think is reponsible
    interface_by_interface_potential_desired_path = standardize_desired_paths_format(desired_path, type_of_problem)
    desired_path_node_interface_actions = get_interface_actions(interface_by_interface_potential_desired_path, responsible_device_name)
    traceroute_path_interfaces = construct_interface_by_interface_hops(traceroute_path)
    traceroute_path_node_interface_actions = get_interface_actions(traceroute_path_interfaces, responsible_device_name)

    # now, extract the actions related to ACLs and check if they are the same for the desired and tracerotue nodes
    # (Are they the same or different?)
    desired_path_node_interface_acl_actions = get_acl_related_actions(desired_path_node_interface_actions)
    traceroute_path_node_interface_acl_actions = get_acl_related_actions(traceroute_path_node_interface_actions)
    acl_interface_actions_are_the_same = True

    if len(desired_path_node_interface_acl_actions) != len(traceroute_path_node_interface_acl_actions):
        acl_interface_actions_are_the_same = False
    else:
        for acl_action_index in range(0, len(desired_path_node_interface_acl_actions)):
            desired_path_action =    desired_path_node_interface_acl_actions[acl_action_index]
            traceroute_path_action = traceroute_path_node_interface_acl_actions[acl_action_index]
            if desired_path_action != traceroute_path_action:
                acl_interface_actions_are_the_same = False

    return (not acl_interface_actions_are_the_same), desired_path_node_interface_acl_actions, traceroute_path_node_interface_acl_actions

def get_acl_related_actions(list_of_node_actions):
    acl_actions = []
    for action in list_of_node_actions:
        if 'TRANSMITTED' in action or 'TRANSMITED' in action or 'RECEIVED' in action or 'DENIED' in action:
            acl_actions.append(action)
    return acl_actions

def get_interface_actions(interface_by_interface_hops, responsilbe_device_name):
    interface_actions = []
    for desired_activity_and_interface in interface_by_interface_hops:
        if responsilbe_device_name in desired_activity_and_interface:
            if ':' in desired_activity_and_interface:
                action = desired_activity_and_interface.split(':')[0]
                interface_actions.append(action)
    return interface_actions

## TODO: this function requires quite a bit of work...
def does_desired_path_hop_have_outgoing_interface(desired_path, responsible_device):
    does_desired_path_have_outgoing_interface_on_node = False
    for desired_activity_and_interface in desired_path:
        if responsible_device in desired_activity_and_interface:
            if 'FORWARD' in desired_activity_and_interface or 'TRANSMITED' in desired_activity_and_interface or \
               'OUTGOING' in desired_activity_and_interface or 'TRANSMITTED' in desired_activity_and_interface:
                does_desired_path_have_outgoing_interface_on_node = True

    return does_desired_path_have_outgoing_interface_on_node

def does_traceroute_hop_have_outgoing_interface(tr_hop):
    for step in tr_hop.steps:
        if step.action == 'FORWARD' or step.action == "TRANSMITED" or step.action == "OUTGOING"  or step.action  == "TRANSMITTED":
            return True
    return False

def routing_behavior_different_p(traceroute_path, desired_path, responsible_device):

    # okay, now we need to determine if the difference in behavior is due to routing behavior.
    # We do this in the same way that we handle acl_behavior_diferent_p...
    ### this is my current task!!!

    mismatch_node_index = find_corresponding_index(traceroute_path, responsible_device)

    last_action = forward_hops_interfaces[mismatch_node_index].split(':')[0]
    desired_action = desired_path[mismatch_node_index].split(':')[0]

    # the routing decision differs
    if last_action == 'OUTGOING' and desired_action == 'OUTGOING':
        return True
    else:
        return False

def find_corresponding_index(traceroute_path, responsible_device):
    for index,traceroute_hop in enumerate(traceroute_path):
        if traceroute_hop.node == responsible_device:
            return index
    return None


def was_one_root_cause_correct(possible_explanations):
    pass

def was_one_root_cause_correct(possible_explanations):
    pass

def construct_interface_by_interface_hops(forward_hops):
    # construct an interface-by-interface hop

    interface_by_interface_hops = []
    for i in range(0, len(forward_hops)):
        cur_node = forward_hops[i].node
        current_node_steps = forward_hops[i].steps
        incoming_interface = current_node_steps[0]
        outgoing_interface = current_node_steps[-1]

        # first add the incoming interface
        try:
            interface_by_interface_hops.append( incoming_interface.action + ':' + cur_node + '[' + incoming_interface.detail.inputInterface + ']' )
        except:
            pass ## TODO: will definitely need to do more here!!

        interface_by_interface_hops.append(cur_node)
        '''
        # then add the node - unless it is the last (not needed because drops are properties of interfaces)
        found_intermediate_step = False
        for on_node_step in current_node_steps[1:-1]:
            if on_node_step.action == "ACCEPTED" or on_node_step.action == "DENIED":
                found_intermediate_step = True
                interface_by_interface_hops.append( on_node_step.action + ':' + cur_node )
        if not found_intermediate_step:
            interface_by_interface_hops.append('AT_NODE:' + cur_node)
        '''

        # finally, add the outgoing interface
        try:
            interface_by_interface_hops.append( outgoing_interface.action + ':'  + cur_node + '[' + outgoing_interface.detail.inputInterface + ']' )
        except:
            try:
                interface_by_interface_hops.append( outgoing_interface.action + ':'  + cur_node + '[' + str(outgoing_interface.detail.outputInterface) + ']' )
            except:
                interface_by_interface_hops.append( outgoing_interface.action + ':'  + cur_node + '[' + str(outgoing_interface.detail.interface) + ']' )

        '''
        if 'RECEIVED' in incoming_interface.action:
            interface_by_interface_hops.append( incoming_interface[9:-2]  )
        if 'OUTGOING' in outgoing_interface:
            interface_by_interface_hops.append( outgoing_interface[9:-2]  )
        '''
    return interface_by_interface_hops

def run_traceroute(start_location, dst_ip, src_ip, srcPort, dstPort, ipProtocol):
    header_constraint_args = {"dstIps": dst_ip, "srcIps": src_ip}
    if srcPort:
        header_constraint_args["srcPorts"]=  srcPort
    if dstPort:
        header_constraint_args["dstPorts"] = dstPort
    if ipProtocol:
        header_constraint_args["ipProtocols"] = ipProtocol

    traceroute_results = bfq.bidirectionalTraceroute(startLocation=start_location,
                                headers=HeaderConstraints( **header_constraint_args ))

    ''',
    dstPorts=52,
    srcPorts=53))'''
    '''
        e.g.,
        traceroute_results = bfq.bidirectionalTraceroute(startLocation='@enter(abc-3850parts[GigabitEthernet1/1/2])',
                                headers=HeaderConstraints(dstIps='10.10.20.8',
                                                          srcIps='10.10.20.5'))
    '''

    forward_hops = traceroute_results.answer().frame().Forward_Traces[0][0].hops
    try:
        return_hops = traceroute_results.answer().frame().Reverse_Traces[0][0].hops
    except:
        return_hops = None
    return forward_hops, return_hops

###################################################################################
###################################################################################

def not_reproducable_because_missing_feature(forward_hops_interfaces, desired_path, mismatch_node_index):
    # TODO: Finish this function sooner rather than later....
    batfish_errors_that_could_cause_reproduction_problems = []
    batfish_errors = bfq.initIssues().answer().frame()

    # Q: Is routing behavior different?
    if routing_behavior_different_p(forward_hops_interfaces, desired_path, mismatch_node_index):
        # check for routing protocol related stuff -- anything with the term route or with a routing protocol name...
        nat_lines = batfish_errors[batfish_errors['Line_Text'].str.contains("nat", na=False)]
        route_linges = batfish_errors[batfish_errors['Line_Text'].str.contains("route", na=False)]
        ospf_lines = batfish_errors[batfish_errors['Line_Text'].str.contains("ospf", na=False)]
        rip_lines = batfish_errors[batfish_errors['Line_Text'].str.contains("rip", na=False)]
        igrp_lines = batfish_errors[batfish_errors['Line_Text'].str.contains("IGRP", na=False)]
        is_is_lines = batfish_errors[batfish_errors['Line_Text'].str.contains("is-is", na=False)]
        bgp_lines = batfish_errors[batfish_errors['Line_Text'].str.contains("bgp", na=False)]

        batfish_errors_that_could_cause_reproduction_problems.append( nat_lines )
        batfish_errors_that_could_cause_reproduction_problems.append( route_linges )
        batfish_errors_that_could_cause_reproduction_problems.append( ospf_lines )
        batfish_errors_that_could_cause_reproduction_problems.append( rip_lines )
        batfish_errors_that_could_cause_reproduction_problems.append( igrp_lines )
        batfish_errors_that_could_cause_reproduction_problems.append( is_is_lines )
        batfish_errors_that_could_cause_reproduction_problems.append( bgp_lines )

    # Q: Is ACL behavior different?
    elif acl_behavior_diferent_p(forward_hops_interfaces, desired_path, mismatch_node_index):
        # check for access-list related stuff
        acl_lines = batfish_errors[batfish_errors['Line_Text'].str.contains("access-list", na=False)]
        batfish_errors_that_could_cause_reproduction_problems.append(acl_lines)
    else:
        pass

    return batfish_errors_that_could_cause_reproduction_problems

def not_reproducbile_because_missing_device():
    pass

def not_reproducible_because_missing_info():
    pass

def is_topology_connected():
    pass

def can_we_recreate_the_problem_p(problematic_path, forward_hops_interfaces):
    # let's see if the problematic path and the concrete path agree
    mismatch_node_index = find_point_where_desired_and_actual_paths_diverge(forward_hops_interfaces, problematic_path)
    if mismatch_node_index is None:
        return True
    else:
        return False

'''
def generate_explanations(mismatch_node_index, forward_hops_interfaces, desired_path, forward_hops, start_location,
                               dst_ip, src_ip):

    explanation = []

    # Q: Is routing behavior different?
    if routing_behavior_different_p(forward_hops_interfaces, desired_path, mismatch_node_index):
        explanatiosn_about_routes = generate_explanations_for_different_routing(forward_hops_interfaces, mismatch_node_index)
        explanation.extend( explanatiosn_about_routes )
    # Q: Is ACL behavior different?
    elif acl_behavior_diferent_p(forward_hops_interfaces, desired_path, mismatch_node_index):
        # TODO: this whole section is todo
        pass
    else:
        pass

    return explanation
'''

def find_difference_between_concrete_and_desired_paths(start_location, dst_ip, src_ip, protocol, desired_path):
    if start_location is not None and dst_ip is not None and src_ip is not None:
        print("finding forward/reverse hops...")

        if protocol == 'DHCP':
            # TODO: find hops to DHCP relay

            # TODO: run traceroute from relay to DHCP server
            pass
        else:
            forward_hops, return_hops = run_traceroute(start_location, dst_ip, src_ip)

            forward_hops_interfaces = construct_interface_by_interface_hops(forward_hops)
            return_hops_interfaces = construct_interface_by_interface_hops(forward_hops)

        if desired_path is None:
            #exit('ERROR: must specify a desired path...')
            mismatch_node_index = 0
        else:
            mismatch_node_index = find_point_where_desired_and_actual_paths_diverge(forward_hops_interfaces, desired_path)

            print("mismatch_node_index", mismatch_node_index)

    return forward_hops_interfaces, return_hops_interfaces, mismatch_node_index, forward_hops, return_hops

def find_point_where_desired_and_actual_paths_diverge(forward_hops_interfaces, desired_path):
    mismatch_node_index = None
    for index in range(0, max(len(forward_hops_interfaces), len(desired_path))):
        if index >= len(desired_path):
            mismatch_node_index = index
            break
        elif index >= len(forward_hops_interfaces):
            mismatch_node_index = index
            break
        elif forward_hops_interfaces[index] != desired_path[index]:
            mismatch_node_index = index
            break
    return mismatch_node_index

def generate_explanations_for_different_routing(traceroute_path, desired_path, responsible_device):
    hop_that_happened = (forward_hops_interfaces[mismatch_index - 1], forward_hops_interfaces[mismatch_index])
    hop_that_we_want_to_happen = (desired_path[mismatch_index - 1], desired_path[mismatch_index])
    explanation = []
    # Q: why is this routed differently?
    # Second, find all of the routes that could have been chosen
    matching_routes = find_all_routes_that_match(hop_that_happened)

    # Third, are there any routes that would have given us what we wanted?
    # We need to map the L3 "next_hop" of the routing table to the corresponding L2 broadcast domain.
    # If the device that we want to send to is on this L2 broadcast domain, then this would give us what we want.
    # If not, then it won't.
    routes_with_correct_next_hop = find_all_routes_with_correct_next_hop(hop_that_happened, hop_that_we_want_to_happen, matching_routes)

    # so now we have the set of routes that we could have taken but that we did NOT take. This brings us to the next step....
    # Fourth, (a) If there are no routes investigate, why not? OR (b) if there is a route, why didn't we use it?
    if len(routes_with_correct_next_hop) == 0:
        cur_explanation = generate_explanations_for_lack_of_routes(hop_that_happened,
                                                                   hop_that_we_want_to_happen)
        explanation.extend(cur_explanation)

    else:
        # If there is a route, investigate why we didn't use it.
        # TODO TODO TODO
        pass

    return explanation

def generate_explanations_for_lack_of_routes(hop_that_happened, hop_that_we_want_to_happen):
    device_that_routed_packet = hop_that_happened[0]
    explanation = []
    # (a) Three basic types of routes: static route, routing protocols (i.e. dynamic), direct (i.e. layer-3 edge)
    # i. Why no static route?
    # -> b/c no configs
    explanation.append('No static routes configured')

    # ii. Why no dynamic route?
    # -> are routing protocols configured?
    # -> if yes, why isn't it working correctly
    ospf_sessions = bfq.ospfSessionCompatibility().answer().frame()
    bgp_sessions = bfq.bgpSessionCompatibility().answer().frame()
    if ospf_sessions.size == 0 and bgp_sessions.size == 0:
        explanation.append('No routing protocols configured')

    else:
        # TODO: need to implement this part
        pass

    # iii. Why no direct route?
    # -> is there a L1 route?
    l1_routes = bfq.layer1Edges(nodes=device_that_routed_packet).answer().frame()
    if l1_routes.size > 0:
        for l1_route in l1_routes.iterrows():
            remote_interface = l1_route[1]['Remote_Interface']
            local_interface = l1_route[1]['Interface']
            if remote_interface.hostname == hop_that_we_want_to_happen[1]:
                # a link exists. Why aren't we using it?
                # -> is there a port mismatch?
                ports_on_device_that_did_the_routing = bfq.interfaceProperties(
                    nodes=device_that_routed_packet).answer().frame()
                relevant_port_src = ports_on_device_that_did_the_routing[
                    ports_on_device_that_did_the_routing['Interface'] == local_interface]
                ports_on_desired_next_hop_device = bfq.interfaceProperties(
                    nodes=hop_that_we_want_to_happen[1]).answer().frame()
                relevant_port_dst = ports_on_desired_next_hop_device[
                    ports_on_desired_next_hop_device['Interface'] == remote_interface]

                port_mismatch_reasons = check_for_port_mismatchs(relevant_port_src, relevant_port_dst, local_interface, remote_interface)

            explanation.extend( port_mismatch_reasons )

    else:
        explanation.append('No L1 routes connecting these devices')

    return explanation

def check_for_port_mismatchs(relevant_port_src, relevant_port_dst, local_interface, remote_interface):
    '''

    :param relevant_port_src:  from bfq.interfacePropeties().answer().frame()
    :param relevant_port_dst: from bfq.interfacePropeties().answer().frame()
    :param local_interface: device_name[port_name]
    :param remote_interface: device_name[port_name]
    :return:
    '''
    explanation = []
    # TODO: much more work to do here, but the key thing (for now) is
    # 1. does VLAN-tagging match? (i.e. both trunk or not?)
    src_port_switchmode = list(relevant_port_src['Switchport_Mode'])[0]
    dst_port_switchmode = list(relevant_port_dst['Switchport_Mode'])[0]
    if src_port_switchmode != dst_port_switchmode:
        string_to_add = 'Link mismatch (' + str(local_interface) + ':' \
                        + str(relevant_port_src['Switchport_Mode']) + ',' + str(remote_interface) \
                        + str(relevant_port_dst['Switchport_Mode']) + ')'
        explanation.append(string_to_add)
    # 2. do the set of support vlans match?
    pass  # TODO
    # 3. does the type of interface supported match
    pass # TODO

    return explanation

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

def find_all_routes_that_match(hop_that_happened, dst_ip):
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
