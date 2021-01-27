## setup instrunctions ##

Step 0: Install docker and python 3.8

Step 1: install + start the batfish docker container

```
docker pull batfish/allinone

docker run --name batfish -v batfish-data  -p 8888:8888 -p 9997:9997 -p 9996:9996 batfish/allinone
```

Step 2: install pybatfish + other required library
```
python3 -m pip install --upgrade pybatfish
pip3 install -r requirements.txt
```

Step 3: Go into main_basic.py and uncomment which of the 4 scenarios that you want to run. To be specific, uncomment the lines
for NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH for that scenario.

Step 4: You are now ready to run main.py via

```
python main.py --netivus_experiment [experiment_name]
```
where experiment_name is associated with the necessary parameters in main.py 

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