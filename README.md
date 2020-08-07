## setup instrunctions ##

Step 1: install + start the batfish docker container

```
docker pull batfish/allinone

docker run --name batfish -v batfish-data:/data -p 8888:8888 -p 9997:9997 -p 9996:9996 batfish/allinone
```

Step 2: install pybatfish 
```
python3 -m pip install --upgrade pybatfish
```

Step 3: Go into main_basic.py and uncomment which of the 4 scenarios that you want to run. To be specific, uncomment the lines
for NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH for that scenario.

Step 4: You are now ready to run main_basic.py via

```
python main_basic.py
```
Note: You may want to use a debugger with good Pandas support so you can see the errors better (e.g., pycharm)