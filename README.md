## setup instrunctions ##

Step 0: Install docker and python 3.8

Step 1: install + start the batfish docker container

```
docker pull batfish/allinone

docker run --name batfish -v batfish-data  -p 8888:8888 -p 9997:9997 -p 9996:9996 batfish/allinone
```

Step 2a: install pybatfish
```
python3 -m pip install --upgrade pybatfish
```

Step 2b: Install other libraries required by Netivus:
```
pip3 install -r requirements.txt # requirements.txt can be found in the current directory
```


Step 3: You are now ready to run main.py via

```
python main.py --netivus_experiment [experiment_name]
```
where experiment_name is associated with the necessary parameters in main.py. For instance, try experiment names
synthetic_explicit_acl_drop_packets_forward or problem_with_cisco_asa_nat or Juniper_SRX240_and_EX2200_network
or private_lan_cannot_access_internet (see the technical case studies google doc for the corresponding NESE post)

NOTE: double check that your experiment_name has these parameters defined (some experiments are missing all these, b/c of legacy reasons):
* NETWORK_NAME
* SNAPSHOT_NAME
* SNAPSHOT_PATH
* type_of_problem
* src_ip
* dst_ip
* srcPort
* dstPort
* ipProtocol,
* start_location
* end_location
* desired_path (can be none)
* problematic_path (can be none)

Note: You may want to use a debugger with good Pandas support so you can see the errors better (e.g., pycharm)