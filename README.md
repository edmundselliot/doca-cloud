Prereqs
```
# DOCA and DPDK must be installed
pkg-config --modversion doca-flow doca-common doca-dpdk-bridge libdpdk
# yaml-cpp used to parse input
sudo apt-get install libyaml-cpp-dev
```

Build
```
# Following packages must be in PKG_CONFIG_PATH:
#   doca-flow, doca-common, doca-dpdk-bridge, libdpdk, yaml-cpp
meson build
ninja -C build
```

Run
```
build/doca-cloud app_cfg.yml
```
