import requests

def create_gns3_rough_draft():
    # TODO: check that GNS3 is current running

    # TODO: clear project OR make new project (just make sure there's nothing remaining)

    # TODO: add all nodes (just go through graph and add all the devices)

    # TODO: add all of the edges

    # the above steps are easy for switches... but what about routers...

    pass

def create_gns3_copy():
    auth_tuple = ('admin', 'iSJeYlFLUSwnKDHA9F3jWYLkioJ5Nn6mrEVgCp06VT9kL08bPd4qmTBANfCdoRJZ')
    r = requests.get('http://127.0.0.1:3080/v2/version',
                     auth= auth_tuple)
    print(r.json())

    d = {"name": "testadfgadx",
         "project_id": "ca29d215-eb6c-4562-a8db-2d03a1844b18"}

    r = requests.post("http://localhost:3080/v2/projects",
                      auth=auth_tuple, json=d)

    print("project_creation_response: ", r.json(), r.status_code)

    if r.status_code == 409:
        print("deleting previously existing project")

        r = requests.delete('http://localhost:3080/v2/compute/projects/' + d['project_id'],
                        auth= auth_tuple)
        print(r.json())

        r = requests.post("http://localhost:3080/v2/projects",
                          auth=auth_tuple, json=d)

        print(r.json())

    project_id = r.json()['project_id']

    # might not be open, so we need to open it ourselves...
    r = requests.post("http://localhost:3080/v2/projects/" + project_id + '/open',
                      auth=auth_tuple, json=d)
    print("response to post to open the project:", r.json())

    node1 = {"name": "VPCS 1", "node_type": "vpcs", "compute_id": "local"}
    node2 = {"name": "VPCS 2", "node_type": "vpcs", "compute_id": "local"}

    # make some nodes
    #headers = {'content-type': 'application/json'}
    r = requests.post("http://localhost:3080/v2/projects/" + project_id + "/nodes",
                     auth=auth_tuple, json=node1)
    print("node1_response", r.json())
    node_id_1 = r.json()['node_id']
    r = requests.post("http://localhost:3080/v2/projects/" + project_id + "/nodes",
                     auth=auth_tuple, json=node2)
    print("node2_response", r.json())
    node_id_2 = r.json()['node_id']
    ####

    # now link the nodes that we made
    # TODO TODO: fill in the None categories (what is the adapter number??)
    link_config = { "nodes": [{"adapter_number": 0, "node_id" : node_id_1, "port_number": 0},
                              {"adapter_number": 0, "node_id" : node_id_2, "port_number": 0}]}
    r = requests.post("http://localhost:3080/v2/projects/" + project_id + "/links",
                     auth=auth_tuple,
                      json=link_config)

    print("**link_response:", r.json())

    # curl -X POST  "http://localhost:3080/v2/projects/b8c070f7-f34c-4b7b-ba6f-be3d26ed073f/links" -d '
    #       {"nodes": [{"adapter_number": 0, "node_id": "f124dec0-830a-451e-a314-be50bbd58a00", "port_number": 0},
    #                  {"adapter_number": 0, "node_id": "83892a4d-aea0-4350-8b3e-d0af3713da74", "port_number": 0}]}'

    # let's try exporting this thing...
    ##### GET /v2/projects/{project_id}/export¶
    #header = {'Accept': 'application/json'}
    d = {'project_id': project_id}
    r = requests.get("http://localhost:3080/v2/projects/" + project_id + "/export",
                      auth=('admin', 'iSJeYlFLUSwnKDHA9F3jWYLkioJ5Nn6mrEVgCp06VT9kL08bPd4qmTBANfCdoRJZ'),
                     json = d)
    print(r)
    #print(r.text)

    #print("export_project_response", r.json())

    with open('gns3_archive.zip', 'wb') as f:
        f.write(r.content)