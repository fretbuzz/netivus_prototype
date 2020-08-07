import pandas as pd
from pybatfish.client.commands import *
from pybatfish.datamodel import *
from pybatfish.datamodel.answer import *
from pybatfish.datamodel.flow import *
from pybatfish.question import *
from pybatfish.question import bfq

def main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH):
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




if __name__ == "__main__":
    ''' # Scenario 1: the HotNets example (comment out this line to enable this scenario)
    #Dell N2000 - Inter-VLAN routing problem
    NETWORK_NAME = "example_network_augmented"
    SNAPSHOT_NAME = "example_snapshot_augmented"
    SNAPSHOT_PATH = "./scenarios/Access port config augmented"
    #'''
    ''' # test for problem reproduction (don't uncomment)
    bfq.bidirectionalTraceroute(startLocation='@enter(abc-3850parts[GigabitEthernet1/1/2])',
                                headers=HeaderConstraints(dstIps='10.10.20.8',
                                                          srcIps='10.10.20.60')).answer().frame()
    '''


    ''' # Scenario #2 (comment out this line to enable this scenario)
    # DO NOT USE- DEVICES UNSUPPORTED
    # Dell N2000 - Inter-VLAN routing problem
    NETWORK_NAME = "example_network_inter-vlan"
    SNAPSHOT_NAME = "example_snapshot_inter-vlan"
    SNAPSHOT_PATH = "./scenarios/Dell N2000 - Inter-VLAN routing problem"
    # looks like it doesn't support this type of config files??
    #'''

    ''' # Scenario #3 (comment out this line to enable this scenario)
    # Cisco ASA 5505 doesn't allow internet connection
    NETWORK_NAME = "example_network_asdm"
    SNAPSHOT_NAME = "example_snapshot_asdm"
    SNAPSHOT_PATH = "./scenarios/Cisco ASA 5505 doesn't allow internet connection"
    start_location = 'lab-asa[Ethernet0/2]'
    dst_ip = '8.8.8.8'
    src_ip = '172.16.1.4'
    #'''
    ''' test for problem reproduction (don't uncomment)
    bfq.bidirectionalTraceroute(startLocation='@enter(lab-asa[Ethernet0/2])',
                                headers=HeaderConstraints(dstIps='8.8.8.8',
                                                          srcIps='172.16.1.4')).answer().frame(
    '''

    ''' # Scenario #4 (comment out this line to enable this scenario)
    # Juniper SRX240 unstable uplink when client is connected to VPN
    NETWORK_NAME = "example_network_juniper"
    SNAPSHOT_NAME = "example_snapshot_juniper"
    SNAPSHOT_PATH = "./scenarios/Juniper SRX240 unstable uplink when client is connected to VPN"
    #'''

    main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH)