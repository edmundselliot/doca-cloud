# DOCA cloud

### Prereqs
```sh
# DOCA and DPDK must be installed, verify with
pkg-config --modversion doca-common doca-flow doca-dpdk-bridge libdpdk

# yaml-cpp used to parse input, install it work
sudo apt-get install libyaml-cpp-dev
```

### Build
```sh
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

    D[rx ipsec synd
    -----------------------
    match: parser_meta.ipsec_syndrome
    ]

    E[rx vlan
    -----------------------
    match: outer.eth_vlan.tci
    action: VLAN pop]

    F((to vf))

    A -->|port_meta == PF| E
    E --> C
    C --> D
    D --> B
    B --> F
```

### TODO
1. ARP responder
