## setup instrunctions ##

install + start the batfish docker container

```
docker pull batfish/allinone

docker run --name batfish -v batfish-data:/data -p 8888:8888 -p 9997:9997 -p 9996:9996 batfish/allinone
```

Then install pybatfish 
```
python3 -m pip install --upgrade pybatfish
```

Finally, you are ready to run main.py (maybe some other dependency problems, but can install them w/ pip trivially)