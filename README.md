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

## Host topology
![host topology](doc/topology.png)

```sh
# Replace with your PF
$PF=ens5np0

configure_interface() {
    echo "Configuring $1 with $2 VFs"
    echo 0 > /sys/class/net/$1/device/sriov_numvfs
    echo switchdev > /sys/class/net/$1/compat/devlink/mode
    echo $2 > /sys/class/net/$1/device/sriov_numvfs
    ifconfig $1 mtu 9216 up
}

/opt/mellanox/dpdk/bin/dpdk-hugepages.py -r8G
configure_interface $PF 1
```

## Pipeline Architecture

### Configuration
The application reads IPv6 addresses from `app_cfg.yml`:

```yaml
ipv6_cfg:
- hostname: localhost
  addresses:
  - ipv6_address: "2001:db8::1"
  - ipv6_address: "2001:db8::2"
  - ipv6_address: "2001:db8::3"
```
