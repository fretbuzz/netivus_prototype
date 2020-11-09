import pandas as pd
from pybatfish.client.commands import *
from pybatfish.datamodel import *
from pybatfish.datamodel.answer import *
from pybatfish.datamodel.flow import *
from pybatfish.question import *
from pybatfish.question import bfq
from augment_network_representation import generate_graph_representations
import networkx as nx

def debug_network_problem(start_location, end_location, dst_ip, src_ip, protocol, desired_path, type_of_problem,
                          intermediate_scenario_directory, NETWORK_NAME, SNAPSHOT_NAME, DEBUG):
    given_desired_path = False
    if desired_path:
        given_desired_path = True

    while True:
        possible_explanations = []

        # TODO: is the topology connecteD?
        is_topology_connected()

        # TODO: can the problem be recreated?
        can_problem_be_recreated_p, problematic_path_forward, problematic_path_return, should_we_debug_the_path_forward = \
            can_problem_be_recreated(type_of_problem, start_location, dst_ip, src_ip, end_location)

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
                                                   src_loc=start_location, dest_loc=end_location,
                                                   traceroute_path=problematic_path_forward)
        else:
            path_to_debug = problematic_path_return
            desired_paths = generate_desired_paths(desired_path, intermediate_scenario_directory, DEBUG, NETWORK_NAME, SNAPSHOT_NAME,
                                                   src_loc = end_location, dest_loc = start_location,
                                                   traceroute_path = problematic_path_forward)

        for desired_path in desired_paths:
            # TODO: for a given problematic path, guess which device is responsible
            ## rank these in order from most likely responsible to least likely responsible
            responsible_devices = guess_which_devices_are_responsible(path_to_debug, desired_path, given_desired_path)

            for responsible_device in responsible_devices:
                # TODO: for a given problematic path + device, blame the particular part of the device
                potential_explanation = diagnose_root_cause(desired_path, problematic_path_forward, responsible_device)
                possible_explanations.append( potential_explanation )

            was_one_root_cause_correct_p, correct_explanation, must_revise_network_model = was_one_root_cause_correct(possible_explanations)
            if was_one_root_cause_correct_p:
                return correct_explanation
            elif must_revise_network_model:
                ## TODO: the model will have already been refined, so now we just must recreate the model by rerunning Batfish
                generate_graph_representations(intermediate_scenario_directory, False, NETWORK_NAME, SNAPSHOT_NAME)
                ####
                break

        '''
        forward_hops_interfaces, return_hops_interfaces, mismatch_node_index, forward_hops, return_hops = \
            find_difference_between_concrete_and_desired_paths(start_location, dst_ip, src_ip, protocol, desired_path)

        # TODO: can the problem be reproduced ?? this will require additional information...
        if problematic_path is not None:
            problem_could_be_recreated_p = can_we_recreate_the_problem_p(problematic_path, forward_hops_interfaces)
            if not problem_could_be_recreated_p:
                potentially_relevant_batfish_errors = not_reproducable_because_missing_feature(forward_hops_interfaces, desired_path, mismatch_node_index)
                if (potentially_relevant_batfish_errors.size) > 0:
                    print("these are the batfish errors")
                    print(potentially_relevant_batfish_errors)
                    return potentially_relevant_batfish_errors
                elif not_reproducbile_because_missing_device():
                    pass
                elif not_reproducible_because_missing_info():
                    pass

                pass # TODO: perform refinement loop here

        possible_explanations = generate_explanations(mismatch_node_index, forward_hops_interfaces, desired_path, forward_hops, start_location,
                                                      dst_ip, src_ip)

        return possible_explanations
        '''

def can_problem_be_recreated(type_of_problem, start_location, dst_ip, src_ip, end_location):
    forward_hops, return_hops = run_traceroute(start_location, dst_ip, src_ip)
    #final_node = forward_hops[-1].node
    forward_final_interface = find_final_interface(forward_hops, forward=True)
    return_final_interface = find_final_interface(return_hops, forward=False)

    src_can_reach_dst_p = forward_final_interface == end_location
    dst_can_reach_src_p = return_final_interface == start_location

    should_we_debug_the_path_forward = None #### if we can
    can_we_recreate_the_problem_p = None

    # TODO: run the comparison check here...
    if type_of_problem == "Connecitivity_Blocked":
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
    elif type_of_problem =="Connecitivity_Allowed":
        if src_can_reach_dst_p and dst_can_reach_src_p:
            # if the problem is that we CAN reach the destination, then if we can reach the destination
            ## we can recreate the problem
            can_we_recreate_the_problem_p = True
            should_we_debug_the_path_forward = None # TODO:: how to do this??
            #return True, forward_hops, return_hops, should_we_debug_the_path_forward
        else:
            # if the problem is that we CAN reach the destination, then if we cannot reach the destination
            ## we cannot recreate the problem
            can_we_recreate_the_problem_p = False

            # if problem is that we CAN reach the destination, then if we CAN reach the destination going
            ## forward, then we need to debug the forward path
            should_we_debug_the_path_forward = src_can_reach_dst_p
            #return False, forward_hops, return_hops, should_we_debug_the_path_forward
    else:
        raise("Unsupported type_of_problem")

    return can_we_recreate_the_problem_p, forward_hops, return_hops, should_we_debug_the_path_forward


def find_final_interface(forward_hops, forward):
    final_node = forward_hops[-1]
    # not sure if the final behavior will be recieving or transmitting, so we must scan for both
    final_interface = None
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

    return final_interface

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

def generate_desired_paths(desired_path, intermediate_scenario_directory, DEBUG, NETWORK_NAME, SNAPSHOT_NAME,
                           src_loc, dest_loc, traceroute_path):

    if desired_path is not None:
        return [desired_path]
    else:
        # generate possible desired paths and heuristically rank how likely they are
        _, G_layer_1, _, _ = generate_graph_representations(intermediate_scenario_directory, DEBUG, NETWORK_NAME,
                                                            SNAPSHOT_NAME)
        potential_desired_path_generator = nx.all_simple_paths(G_layer_1, src_loc, dest_loc)
        # now rank the paths...
        paths_with_overlapping_score = []
        for potential_desired_path in potential_desired_path_generator[0]:
            overlap_score = calculate_overlap(potential_desired_path, traceroute_path)
            paths_with_overlapping_score.append( (overlap_score, potential_desired_path))

        paths_with_overlapping_score.sort(key= lambda x: (x[0],))
        return paths_with_overlapping_score

def calculate_overlap(potential_desired_path, traceroute_path):
    shortest_path = min(potential_desired_path, traceroute_path)
    overlapping_node_count = 0
    for index in range(0, shortest_path):
        potential_desired_hop = potential_desired_path[index]
        traceroute_hop = traceroute_path[index]

        if potential_desired_hop.node == traceroute_hop.node:
            overlapping_node_count += 1

    return overlapping_node_count

def guess_which_devices_are_responsible(traceroute_path, desired_path, given_desired_path_p):
    # this function determines which device performed the direct action on the packet that caused the incorrect behavior...
    ## note: that another device could be ultimately responsible (e.g., originated the route), but it didn't do anything
    ## to the packe

    # Let's start by assuming that the device where a different decision was made is responsible.
    ## In other words, let's find where behavior diverges (e.g., output interface is different, packet filtering is different)

    # iterate through the paths and find the first
    # place where they diverge in behavior. If you get to the end and no divergent behavior is found, then we can blame
    # the last device in the traceroute path
    ## Specifically, check the input and output...

    if given_desired_path_p:
        interface_by_interface_traceroute_path = construct_interface_by_interface_hops(traceroute_path)
        potentially_responsible_devices = guess_which_devices_are_responsible_user_specified_desired_path(interface_by_interface_traceroute_path, desired_path)
    else:
        potentially_responsible_devices = guess_which_devices_are_responsible_all_paths_system_generated(traceroute_path, desired_path)

    return potentially_responsible_devices

def guess_which_devices_are_responsible_user_specified_desired_path(interface_by_interface_traceroute_path, interface_by_interface_desired_path):
    # use the same general logic specified in the parent function
    potentially_responsible_devices = []
    found_responsible_node = False
    responsible_index = None # assign
    min_path_length = min( len(interface_by_interface_traceroute_path), len(interface_by_interface_desired_path) )
    for index in range(0, min_path_length):
        traceroute_interface = interface_by_interface_traceroute_path[index]
        desired_interface = interface_by_interface_desired_path[index]

        # are the interfaces the same?
        if traceroute_interface != desired_interface:
            # if outgoing, blame this device
            action, device_and_interface = traceroute_interface.split([':'])
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

    ### TODO TODO TODO TODO:: FINISH THIS FUNCTION (just details to work out...)
    if not found_responsible_node:
        if len(interface_by_interface_traceroute_path) < len(interface_by_interface_desired_path):
            potentially_responsible_devices.append(interface_by_interface_traceroute_path[len(interface_by_interface_traceroute_path)].node)
            responsible_index = len(interface_by_interface_traceroute_path)
        else:
            # if traceroute path is longer, but agrees in behavior up to end of desired_path, then the last shared node is responsible
            potentially_responsible_devices.append(interface_by_interface_traceroute_path[len(interface_by_interface_desired_path)].node)
            responsible_index = len(interface_by_interface_desired_path)


    # Now, let's find any devices that transform that packet... look at all devices that come before this in the list
    ## of devices and scan the list of operations for any kind of packet transforms
    for i in range(0, responsible_index):
        if any_transformations_present(traceroute_path[i]):
            potentially_responsible_devices.append( traceroute_path[i].node)

    return potentially_responsible_devices

def guess_which_devices_are_responsible_all_paths_system_generated(traceroute_path, desired_path):
    potentially_responsible_devices = []
    found_responsible_node = False
    responsible_index = None # assign
    min_path_length = min( len(traceroute_path), len(desired_path) )
    for index in range(0, min_path_length):
        traceroute_hop = traceroute_path[index]
        desired_hop = desired_path[index]

        # zeroth, check if the node is the same
        if traceroute_hop.node != desired_hop.node:
            # need to look at the *previous* node, since it made the decision to send it here
            potentially_responsible_devices.append(traceroute_path[index-1].node)
            found_responsible_node = True
            responsible_index = index
            break
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
    if not found_responsible_node:
        if len(traceroute_path) < len(desired_path):
            potentially_responsible_devices.append(traceroute_path[len(traceroute_path)].node)
            responsible_index = len(traceroute_path)
        else:
            # if traceroute path is longer, but agrees in behavior up to end of desired_path, then the last shared node is responsible
            potentially_responsible_devices.append(traceroute_path[len(desired_path)].node)
            responsible_index = len(desired_path)


    # Now, let's find any devices that transform that packet... look at all devices that come before this in the list
    ## of devices and scan the list of operations for any kind of packet transforms
    for i in range(0, responsible_index):
        if any_transformations_present(traceroute_path[i]):
            potentially_responsible_devices.append( traceroute_path[i].node)

    return potentially_responsible_devices

def any_transformations_present(cur_hop):
    ## TODO: THIS IS NOT THE RIGHT WAY TO DO THIS!! (But it works for now b/c we don't have a motivating scenario...)
    for step in cur_hop.steps:
        if step.detail.transformedFlow is not None:
            return True
    return False

def diagnose_root_cause(desired_path, problematic_path, responsible_device):
    pass

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
        interface_by_interface_hops.append( incoming_interface.action + ':' + cur_node + '[' + incoming_interface.detail.inputInterface + ']' )
        #if outgoing_interface.action == "EXITS_NETWORK":
        #    pass
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

def routing_behavior_different_p(forward_hops_interfaces, desired_path, mismatch_node_index):
    last_action = forward_hops_interfaces[mismatch_node_index].split(':')[0]
    desired_action = desired_path[mismatch_node_index].split(':')[0]

    # the routing decision differs
    if last_action == 'OUTGOING' and desired_action == 'OUTGOING':
        return True
    else:
        return False


def acl_behavior_diferent_p(forward_hops_interfaces, desired_path, mismatch_node_index):
    last_action = forward_hops_interfaces[mismatch_node_index].split(':')[0]
    desired_action = desired_path[mismatch_node_index].split(':')[0]

    # the ACL action differs
    if last_action == 'DENIED' or last_action == 'ACCEPTED':
        return True
    else:
        return False

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

def generate_explanations_for_different_routing(forward_hops_interfaces, mismatch_index):
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

def run_traceroute(start_location, dst_ip, src_ip):
    traceroute_results = bfq.bidirectionalTraceroute(startLocation='@enter(' + start_location + ')',
                                headers=HeaderConstraints(dstIps=dst_ip,
                                                          srcIps=src_ip))
    '''
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
