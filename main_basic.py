import pandas as pd
from pybatfish.client.commands import *
from pybatfish.datamodel import *
from pybatfish.datamodel.answer import *
from pybatfish.datamodel.flow import *
from pybatfish.question import *
from pybatfish.question import bfq
import argparse
from main import query_engine, run_traceroute

def  main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH, start_location, dst_ip, src_ip, desired_path):
    bf_session.host = 'localhost'
    bf_session.port = '9996'

    bf_set_network(NETWORK_NAME)
    bf_init_snapshot(SNAPSHOT_PATH, name=SNAPSHOT_NAME, overwrite=True)

    load_questions()

    pd.options.display.max_columns = 6

    parse_status = bfq.fileParseStatus().answer().frame()

    print("----------------------")
    print("File Parse Status:")

    print(parse_status)

    print("----------------------")
    print("File Parse Warnings:")

    parse_warning = bfq.parseWarning().answer().frame()

    print(parse_warning)

    # todo: run the traceroute commadn
    forward_hops, explanation = None, None
    if start_location is not None and dst_ip is not None and src_ip is not None:
        print("finding forward hops...")
        forward_hops = run_traceroute(start_location, dst_ip, src_ip)

        foward_hops_node_only = [forward_hops[i].node for i in range(0,len(forward_hops))]

        if len(forward_hops[-1].steps) > 3:
            if forward_hops[-1][-1].action == 'EXITS_NETWORK':
                foward_hops_node_only.append('LEFT_NETWORK via ' + forward_hops[-1][-1].detail.outputInterface)

        if desired_path is not None:
            mismatch_node_index = None
            for index in range(0,max( len(foward_hops_node_only), len(desired_path) ) ):
                if index >= len(desired_path):
                    mismatch_node_index = index
                    break
                elif index >= len(foward_hops_node_only):
                    mismatch_node_index = index
                    break
                elif foward_hops_node_only[index] != desired_path[index]:
                    mismatch_node_index = index
                    break
            print("mismatch_node_index", mismatch_node_index)
            #the_hop_that_we_need_to_explain = (forward_hops[mismatch_node_index-1].node, forward_hops[mismatch_node_index].node)

            explanation = query_engine(mismatch_node_index, forward_hops, desired_path, foward_hops_node_only, start_location, dst_ip, src_ip)

    # todo: see if the traceroute command reproduces the problem that we expect it to reproduce

    return forward_hops, explanation

def parse_input(netivus_experiment):
    start_location, dst_ip, src_ip, desired_path = None, None, None, None

    if netivus_experiment == 'hotnets_example':
        #'''
        # IP address conflict (the HotNets example) -- augmented (but the duplicate IP address is still there)
        NETWORK_NAME = "example_network_augmented"
        SNAPSHOT_NAME = "example_snapshot_augmented"
        SNAPSHOT_PATH = "./scenarios/Access port config Augmented"
        start_location = 'abc_mdf3850x[GigabitEthernet1/1/2]' #'abc-3850parts[GigabitEthernet1/0/1]' # 'abc-3850parts[GigabitEthernet1/1/2]'
        dst_ip = '10.10.20.8'
        src_ip = '10.00.20.60' #  '10.10.20.60'
        #'''
    elif netivus_experiment == 'hotnets_example_fixed':
        #'''
        # IP address conflict (the HotNets example) -- augmented + correct (so the duplicate IP address is now gone)
        NETWORK_NAME = "example_network_correct"
        SNAPSHOT_NAME = "example_snapshot_correct"
        SNAPSHOT_PATH = "./scenarios/Access Port Config Correct"
        start_location = 'abc-3850parts[GigabitEthernet1/1/2]'
        dst_ip = '10.10.20.8'
        src_ip = '10.10.20.60'
        #'''
    elif netivus_experiment == 'inter-vlan':
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
    elif netivus_experiment == 'juniper_uplink_unstable':
        #'''
        # Juniper SRX240 unstable uplink when client is connected to VPN
        NETWORK_NAME = "example_network_juniper"
        SNAPSHOT_NAME = "example_snapshot_juniper"
        SNAPSHOT_PATH = "./scenarios/Juniper SRX240 unstable uplink when client is connected to VPN"
        #'''
    elif netivus_experiment == 'cisco_asa_doesnt_allow_internet':
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
    elif netivus_experiment == 'pc_cannot_ping_eachother_when_using_bgp':
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
    elif netivus_experiment == "Juniper_SRX240_and_EX2200_network":
            NETWORK_NAME = "Juniper_SRX240_and_EX2200_network"
            SNAPSHOT_NAME = "Juniper_SRX240_and_EX2200_network"
            SNAPSHOT_PATH = "./scenarios/Juniper SRX240 and EX2200 network"
            #'''
            # host on ex2200 trying to reach the WAN (srx240[ge0/0/0.0])
            start_location = 'ex2200[ge-0/0/13]'
            dst_ip = '8.8.8.8'
            src_ip = '192.168.1.5'
            desired_path = ['ex2200', 'srx240', 'internet']
            #'''
    elif netivus_experiment == "Juniper_SRX240_and_EX2200_network_FIXED":
        NETWORK_NAME = "Juniper_SRX240_and_EX2200_network_fixed"
        SNAPSHOT_NAME = "Juniper_SRX240_and_EX2200_network_fixed"
        SNAPSHOT_PATH = "./scenarios/Juniper SRX240 and EX2200 network FIXED"
        # '''
        # host on ex2200 trying to reach the WAN (srx240[ge0/0/0.0])
        start_location = 'ex2200[ge-0/0/13]'
        dst_ip = '8.8.8.8'
        src_ip = '192.168.1.5'
        # '''
    elif netivus_experiment == "batfish_isp_example":
        NETWORK_NAME = "networks_example_live-with-isp"
        SNAPSHOT_NAME = "networks_example_live-with-isp"
        SNAPSHOT_PATH = "./scenarios/example_scenarios_from_batfish_github/batfish/networks/example/live-with-isp/"

    elif netivus_experiment == "aaaa":
        NETWORK_NAME = "aaaa"
        SNAPSHOT_NAME = "aaaa"
        SNAPSHOT_PATH = "./scenarios/aaaa"

    elif netivus_experiment == "Cisco_Router_Setup_1841":
        NETWORK_NAME = "Cisco_Router_Setup_1841"
        SNAPSHOT_NAME = "Cisco_Router_Setup_1841"
        SNAPSHOT_PATH = "./scenarios/Cisco_Router_Setup_1841"
        start_location = 'router[FastEthernet0/0]'
        dst_ip = '8.8.8.8'
        src_ip = '10.0.4.5'
    else:
        ########## the following are examples that I am working on.... #########

        #'''
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

    main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH, start_location, dst_ip, src_ip, desired_path)

    #create_gns3_copy()

    # note: I can interact with the local GNS3 server (and it's API) using these commands:
    # curl -i -u 'admin:iSJeYlFLUSwnKDHA9F3jWYLkioJ5Nn6mrEVgCp06VT9kL08bPd4qmTBANfCdoRJZ' http://127.0.0.1:3080/v2/version

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Runs Netivus Workflow')
    parser.add_argument('--netivus_experiment', dest="netivus_experiment", default=None)
    args = parser.parse_args()
    parse_input(args.netivus_experiment)