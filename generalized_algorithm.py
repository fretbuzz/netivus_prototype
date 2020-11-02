def debugging_approach_v2(src_ip, dest_ip, type_of_problem):
    traceroute_path_forward, traceroute_path_back = run_batfish_traceroute()
    problem_recreation_p, type_of_reproduction_failure = can_probem_be_recreated(traceroute_path_forward, traceroute_path_back, type_of_problem)

    if problem_recreation_p:
        potential_desired_paths = get_potential_desired_paths()
        problem_not_solved = True

        # TODO: ask the user if one of these paths is preferred. otherwise choose the one that is easierst
        # and we can backtrack if it failes....
        potential_desired_paths = ask_user_for_preferred_paths(potential_desired_paths)

        while problem_not_solved:
            cur_potential_desired_path = potential_desired_paths.pop(0)
            device_where_behavior_differs = find_device_with_different_behavior(cur_potential_desired_path, traceroute_path_forward)
            how_behavior_differs = which_part_of_device_behaves_differently(traceroute_path_forward, device_where_behavior_differs)
            if how_behavior_differs == 'routing':
                suggested_fixes = debug_routing_behavior()
            elif how_behavior_differs == 'ACL':
                suggested_fixes = debug_ACL_behavior()
            else:
                raise('how can behavior differ this wey??')

            # TODO: create suggested fixes for transformative changes as well...
            ## these must be handled seperately from the previous considerations b/c there could be
            ## a routing mistake b/c of an earlier transformation mistake
            ## OR maybe make this an assumption and then revisit it later (if the suggestions don't work)
            ## for instance, we could revisit the various assumptions made instead of moving to a different path immediately...
            ##

            # TODO: we need to try this suggested fix first
            suggested_fixes_that_work_on_our_system = test_suggested_fix(suggested_fixes)

            if len(suggested_fixes_that_work_on_our_system) > 0:
                print("Here are the suggested fixes: ", suggested_fixes_that_work_on_our_system)
                print("Did it work? (y/n)")
                did_it_work = input()
                if did_it_work == 'y':
                    problem_not_solved = False
                else:
                    pass # TODO: revisit assumptions in both the network model and problem spec
                         ## network model: devices can get IP addrsses, devices are connected to the network, model has have all important devices,
                           ## missing features are not important, no interface properties mismatch, config files for existing devices might be missing stuff
                         ## problem model: this is the correct path, transformative functions are not contributing to the incorrect behavior
                         ## TODO: tomorrow, run with this thread, and try to get the whole thing ironed out...

    else:
        remediate_network_model(type_of_reproduction_failure)

def ask_user_for_preferred_paths(potential_desired_paths):
    pass

def test_suggested_fix(suggest_fix):
    # make changes to config file
    # test that config file
    return None

def debug_routing_behavior():
    # TODO: need to map these changes to changes in the config file
    # can do this by
    layer_of_routing_error = find_layer_of_routing_error()
    if layer_of_routing_error == 3:
        if existing_correct_route_is_less_prepared():
            return 'correct path was not selected, even though one exists'
        else:
            return 'error: there is a correct path that is more favorable... it should have been selected'
    else:
        if is_there_l1_route():
            if is_there_interface_mismatch():
                return('interface mismatch, static routes, and dyanamic routes')
            else:
                return('static routes, and dyanamic routes')
        else:
            return 'no l1 route'

def debug_ACL_behavior():
    matching_rule = any_matching_acl_rules_that_would_give_desired_behavior()
    if matching_rule:
        rule_shadowing_desired_rule = find_shadowing_rule(matching_rule)
        if rule_shadowing_desired_rule:
            return "this rule is shadowing the desired rule " + rule_shadowing_desired_rule
        else:
            return "error: desired rule should have been used"
    else:
        rule_that_dropped_the_packet = find_rule_that_dropped_the_packet()
        return "this rule dropped the packet " + rule_that_dropped_the_packet

def find_rule_that_dropped_the_packet():
    pass

def any_matching_acl_rules_that_would_give_desired_behavior():
    pass

def find_shadowing_rule():
    pass

def is_there_l1_route():
    pass

def is_there_interface_mismatch():
    pass

def existing_correct_route_is_less_prepared():
    return None

def is_there_existing_correct_route_that_is_less_prepared():
    return None

def find_layer_of_routing_error():
    return None

def run_batfish_traceroute():
    return None, None

def can_probem_be_recreated(traceroute_path_forward, traceroute_path_back, type_of_problem)
    return None, None

def get_potential_desired_paths():
    return None

def remediate_network_model(type_of_failure):
    return None

def find_device_with_different_behavior(cur_potential_desired_path, traceroute_path_forward)
    return None

def which_part_of_device_behaves_differently(traceroute_path_forward, device_where_behavior_differs):
    return None