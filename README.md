Build
```
# Following packages must be in PKG_CONFIG_PATH:
#   doca-flow, doca-common, doca-dpdk-bridge, libdpdk
meson build
ninja -C build
```

Run
```
build/doca-cloud app_cfg.yml
```
