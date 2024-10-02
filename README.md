# DOCA cloud

### Prereqs
```sh
# DOCA and DPDK must be installed
pkg-config --modversion doca-flow doca-common doca-dpdk-bridge libdpdk
# yaml-cpp used to parse input
sudo apt-get install libyaml-cpp-dev
```

### Build
```sh
# Following packages must be in PKG_CONFIG_PATH:
#   doca-flow, doca-common, doca-dpdk-bridge, libdpdk, yaml-cpp
meson build
ninja -C build
```

### Run
```sh
build/doca-cloud app_cfg.yml
```

## Pipeline

### Egress datapath
```mermaid
flowchart LR
    A[rx root
    --------------------
    match: port_meta]

    B[tx root
    -------------
    match: all]

    C[tx geneve
    -----------------------
    match: outer.dst_ip
    action: geneve encap]

    D[tx ipsec
    -----------------------
    match: outer.dst_ip
    action: ipsec encrypt]

    E[tx vlan
    -----------------------
    match: outer.dst_ip
    action: VLAN push]

    F((to wire))

    A -->|port_meta == VF| B
    B --> C
    C --> D
    D --> E
    E --> F
```

### Ingress datapath
```mermaid
flowchart LR
    A[rx root
    --------------------
    match: port_meta]

    B[rx geneve
    -----------------------
    match: outer.src_ip, tun.vni
    action: geneve decap]

    C[rx ipsec
    -----------------------
    match: outer.src_ip, tun.spi
    action: ipsec decrypt]

    D[rx vlan
    -----------------------
    match: outer.eth_vlan.tci
    action: VLAN pop]

    E((to wire))

    A -->|port_meta == PF| D
    D --> C
    C --> B
    B --> E
```

### TODO
1. ARP responder
2. IPSEC syndrome pipes
