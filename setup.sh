/etc/init.d/openibd restart

PF0=eth2
PF1=eth3

VF_IP=10.0.0.1
PF_IP1=101.0.0.1
PF_IP2=102.0.0.1

/opt/mellanox/dpdk/bin/dpdk-hugepages.py -r8G
echo switchdev > /sys/class/net/$PF0/compat/devlink/mode

echo 0 > /sys/class/net/$PF0/device/sriov_numvfs
echo 0 > /sys/class/net/$PF1/device/sriov_numvfs

ifconfig $PF0 up $PF_IP1/24
ifconfig $PF1 up $PF_IP2/24

echo 1 > /sys/class/net/$PF0/device/sriov_numvfs

REP0=eth4
VF0=eth5
ifconfig $REP0 up
ifconfig $VF0 up $VF_IP/24
