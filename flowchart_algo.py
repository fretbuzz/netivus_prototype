import pandas as pd
from pybatfish.client.commands import *
from pybatfish.datamodel import *
from pybatfish.datamodel.answer import *
from pybatfish.datamodel.flow import *
from pybatfish.question import *
from pybatfish.question import bfq

def debug_network_problem(start_location, dst_ip, src_ip, protocol, desired_path, problematic_path, type_of_problem,
                          src_loc, dst_loc):
    while True:
        possible_explanations = []

        # TODO: is the topology connecteD?
        is_topology_connected()

        # TODO: can the problem be recreated?
        can_problem_be_recreated_p = can_problem_be_recreated(type_of_problem, start_location, dst_ip, src_ip, src_loc, dst_loc)

        if not can_problem_be_recreated_p:
            can_we_recreate_problem_now_p, new_headers = explore_header_space_to_recreate_problem()
            if can_we_recreate_problem_now_p:
                # TODO; set headers here
                break

            # TODO: if it cannot be recreated, refine (w/ help from collabs)
            should_we_rerun = refine_network_representation_with_collab(problematic_path, type_of_problem)
            if should_we_rerun:
                # TODO: need to recreate the model now
                ## maybe do this by calling the function again and
                continue

        # we can recreate the problem, so we can attempt to debug (though we might find out that we cannot later on)

        # TODO: generate all possible desired_paths (ranked from most likely to least likely)
        ## for now, we can just use the given one above (for convenience...)
        desired_paths = generate_desired_paths(desired_path)

        for desired_path in desired_paths:
            # TODO: for a given problematic path, guess which device is responsible
            ## rank these in order from most likely responsible to least likely responsible
            responsible_devices = guess_which_devices_are_responsible(problematic_path, desired_path)

            for responsible_device in responsible_devices:
                # TODO: for a given problematic path + device, blame the particular part of the device
                potential_explanation = diagnose_root_cause(desired_path, problematic_path, responsible_device)
                possible_explanations.append( potential_explanation )

            was_one_root_cause_correct_p, correct_explanation, must_revise_network_model = was_one_root_cause_correct(possible_explanations)
            if was_one_root_cause_correct_p:
                return correct_explanation
            elif must_revise_network_model:
                ## TODO: call the model refinement method to and then rerun
                break

def explore_header_space_to_recreate_problem():
    return False, None

def can_problem_be_recreated(type_of_problem, start_location, dst_ip, src_ip, src_loc, dst_loc):
    forward_hops, return_hops = run_traceroute(start_location, dst_ip, src_ip)

    end_of_traceroute_forward, did_traceroute_reach_expected_destination_forward_p = \
        did_traceroute_reach_expected_destination(forward_hops, dst_loc)

    end_of_traceroute_return, did_traceroute_reach_expected_destination_return_p = \
        did_traceroute_reach_expected_destination(return_hops, src_loc)

    if type_of_problem == "connectivity_accepted":
        # the problem is that the connection succeeds. therefore the problem is recreated if both directions of the
        # traceroute reach the src/dst location
        if did_traceroute_reach_expected_destination_forward_p and did_traceroute_reach_expected_destination_return_p:
            return True
        else:
            return False
    elif type_of_problem == "connectivity_denied":
        # the problem is that the connection fails. therefore the problem is recreated if either directions of the
        # traceroute fails to reach the src/dst location
        if (not did_traceroute_reach_expected_destination_forward_p) or (not did_traceroute_reach_expected_destination_return_p):
            return True
        else:
            return False
    else:
        pass

def did_traceroute_reach_expected_destination(hop_path, expected_dst_loc):
    last_device = hop_path[-1].node
    last_interface = 'None'
    for action in hop_path[-1]:
        if 'TRANSMITTED' in action.action:
            last_interface = action.detail.outputInterface
    if last_interface is None:
        for action in hop_path[-1]:
            if 'RECIEVED' in action.action:
                last_interface = action.detail.inputInterface

    if last_interface is None:
        raise('last device neither transmitted or recieved the packet')

    end_of_traceroute = last_device + '[' + last_interface + ']'

    if expected_dst_loc == end_of_traceroute:
        return end_of_traceroute, True
    else
        return end_of_traceroute, False

def refine_network_representation_with_collab(problematic_path, type_of_problem):
    print("When attempting to recreate this problem, the traceroute returned this path:", problematic_path)

    # question the tool limitations
    potential_tool_limitations_needing_refinement = question_reproduction_tool_limitations()

    # question the untrustworthy input
    potential_untrusthworthy_input_needing_refinement = question_untrustworthy_input()

    all_possible_refinement = potential_tool_limitations_needing_refinement + potential_untrusthworthy_input_needing_refinement
    refinement_to_try = get_feedback_from_collaborator_on_refinemnt(all_possible_refinement)

    if refinement_to_try:
        # TODO: must change the netowrk model here, automatically is probably better here, but let's do it manually now
        print("Please make this change to the input:", refinement_to_try)
        _ = input('Press enter when the input has been modified')
        return True
    else:
        return False

def get_feedback_from_collaborator_on_refinemnt(all_possible_refinement):
    sorted_refinements = sorted(all_possible_refinement, key=lambda x: (x[0],))

    for index, sorted_refinement in enumerate(sorted_refinements):
        print(index, sorted_refinement)

    refinement_to_try = input("[To collaborator] Which of these do you think is the most likely reason for the lack of refinement?")
    return all_possible_refinement[refinement_to_try]

def question_reproduction_tool_limitations():
    '''
    the assumptions due to tool limitations are
    - All devices can get IP address
        - approach: no way that we can check for this, so give it a low rating
    - There are no interface property mismatches
        - approach: check this using our function and then assign this a high score if it looks possible
    - The devices with the source and destination ip addresses are connected to the network (they might not be, since they might not show up in the network model)
        - [is this a real problem?? ignore for now, until we can figure it out later...]
    - The model can reproduce all the important device features included in the config files (i.e. none of the missing features are important b/c e.g. parsing errors)
        - approach:  look at the initIssues and (for now) classify all errors as moderate severity
    '''
    possible_causes_for_reproduction_failure = []

    # All devices can get IP address
    possible_causes_for_reproduction_failure.append( (0, 'All devices can get IP address') )

    # There are no interface property mismatches
    layer1Edges = bfq.layer1Edges().answer().frame()
    for index, row in layer1Edges.iterrows():
        outgoing_interface = row['Interface']
        incoming_interface = row['Remote_Interface']
        interface_properties = bfq.interfaceProperties().answer().frame()
        relevant_port_src = interface_properties.loc[interface_properties['Interface'] == outgoing_interface]
        relevant_port_dst = interface_properties.loc[interface_properties['Interface'] == incoming_interface]
        interface_mismatch_explanations = check_for_port_mismatchs(relevant_port_src, relevant_port_dst, outgoing_interface, incoming_interface)

        if len(interface_mismatch_explanations) > 0:
            possible_causes_for_reproduction_failure.append( (10, interface_mismatch_explanations))

    # The devices with the source and destination ip addresses are connected to the network (they might not be, since they might not show up in the network model)
    # [do this if i still think it makes sense later]

    # The model can reproduce all the important device features included in the config files (i.e. none of the missing features are important b/c e.g. parsing errors)
    config_errors = bfq.initIssues().answer().frame()
    for index, row in config_errors.iterrows():
        possible_causes_for_reproduction_failure.append( (0, row['Details'] + ':' + row['Details']) )

    return possible_causes_for_reproduction_failure

def question_untrustworthy_input():
    '''
    the assumptions due to untrusthworthy input are
    - The model contains all the important devices (i.e. no missing important devices)
        - approach: there's no way to reason about this, since it is outside the model, so we must
            assign it as only slightly suspect
    - The config files contain all the important functionality (i.e. are not missing anything)
        - approach: any device that we added is suspect. all other devices are slightly suspect
    - All the necessary properties of the problematic packet headers are specified
        - approach: all the headers that were inputted are suspect (either wrong or incomplete --
            while we did explore the space of header options ourselves, it is not definitive)
    '''
    possible_causes_for_reproduction_failure = []

    # The model contains all the important devices (i.e. no missing important devices)
    possible_causes_for_reproduction_failure.append( (0, "Important Devices are Missing"))

    # The config files contain all the important functionality (i.e. are not missing anything)
    possible_causes_for_reproduction_failure.append( (0, "Parts of existing config files are missing"))

    # All the necessary properties of the problematic packet headers are specified
    possible_causes_for_reproduction_failure.append( (0, "Parts of the probelmatic packets headers are wrong"))
    possible_causes_for_reproduction_failure.append( (0, "Necessary parts of the probelmatic packets headers are missing"))

    return possible_causes_for_reproduction_failure

def question_correctness_of_problem_specification():
    '''
    the assumptions due to possible problems with the problem specification are
    - All the necessary properties of the problematic packet headers are specified
        - approach: all the headers that were inputted are suspect. we can check the others automtically
            (but should probably still include this as a potential problem)
    '''
    pass

def generate_desired_paths(desired_path):
    return [desired_path]

def guess_which_devices_are_responsible(problematic_path, desired_path):
    pass
    ## start by assuming the device where a different decision was made in responsible
    ## then move to assuming that transformational devices could be responsible (i.e. nats)

def diagnose_root_cause(desired_path, problematic_path, responsible_device):
    pass

def was_one_root_cause_correct(possible_explanations):
    pass

def was_one_root_cause_correct(possible_explanations):
    pass

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

def check_for_port_mismatchs(relevant_port_src, relevant_port_dst, local_interface, remote_interface):
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

def construct_interface_by_interface_hops(forward_hops):
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
