import docker, os

import pandas as pd
from pybatfish.client.commands import *
from pybatfish.datamodel import *
from pybatfish.datamodel.answer import *
from pybatfish.datamodel.flow import *
from pybatfish.question import *
from pybatfish.question import bfq

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

    print(list_questions())

    # vxlanEdges, layer3Edges

    pd.options.display.max_columns = 6

    parse_status = bfq.fileParseStatus().answer().frame()

    print("----------------------")

    print(parse_status)

    print("----------------------")

    parse_warning = pd.DataFrame(bfq.parseWarning().answer().frame())

    print("----------------------")

    print(parse_warning)

    print("----------------------")

    node_properties_trunc = bfq.nodeProperties(properties="Device_Type,Interfaces").answer().frame()

    print(node_properties_trunc)



if __name__ == "__main__":
    # Initialize a network and snapshot
    NETWORK_NAME = "example_network"
    SNAPSHOT_NAME = "example_snapshot"
    SNAPSHOT_PATH = "./scenarios/Access port config"

    main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH)