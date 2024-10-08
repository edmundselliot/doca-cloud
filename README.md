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

    VF((from vf))
    WIRE((to wire))

    VF --> A
    A -->|port_meta == VF| B
    B --> C
    C --> D
    D --> E
    E --> WIRE
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

    WIRE((from wire))
    VF((to vf))

    WIRE --> A
    A -->|port_meta == PF| E
    E --> C
    C --> D
    D --> B
    B --> VF
```

### ARP responder datapath
```mermaid
flowchart LR
    A[rx root
    --------------------
    match: ethertype]

    B[tx root
    -------------
    match: ethertype]

    RSS((DOCA app
    --------------------
    replies using fake MAC))

    VFTX((to vf))
    VFRX((from vf))

    VFRX --> A
    A -->|arp request| RSS
    RSS -->|arp response| B
    B -->|arp response| VFTX
```
