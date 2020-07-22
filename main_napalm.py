from napalm import get_network_driver

def main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH):
    driver = get_network_driver('cisco')

    device = driver()

    test = device.load_replace_candidate(filename=SNAPSHOT_PATH)

if __name__ == "__main__":
    # Initialize a network and snapshot
    #'''
    # IP address conflict (the HotNets example)
    NETWORK_NAME = "example_network"
    SNAPSHOT_NAME = "example_snapshot"
    SNAPSHOT_PATH = "./scenarios/Access port config/mdf.cfg"
    #'''

    '''
    # ???
    NETWORK_NAME = "example_network_asdm"
    SNAPSHOT_NAME = "example_snapshot_asdm"
    SNAPSHOT_PATH = "./scenarios/Cisco ASA 5505 doesn't allow internet connection"
    #'''

    main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH)

