# XDPeriments
Example programs for the Journeying into XDP blogs

# Setup
After cloning the repository:
```
git submodule update --init
cd libbpf/src
(possibly apt install libelf-dev)
make
cd ../../Cookies
make
```

(Substitute "Cookies" for another program if desirable)

Then use (and change where nesecary) the different `make` commands to interact with the bpf programs.
