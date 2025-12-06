## Practice

```bash
$ docker build -t host ./host
$ docker run --privileged --cap-add NET_ADMIN \
   --cap-add NET_BROADCAST -d \
   --name h1 host

$ docker run --privileged --cap-add NET_ADMIN \
   --cap-add NET_BROADCAST -d \
   --name h2 host
```

```bash
$ docker pull frrouting/frr-debian
$ docker run --privileged --cap-add NET_ADMIN \
   --cap-add NET_BROADCAST -d \
   --name R1 frrouting/frr-debian

$ docker run --privileged --cap-add NET_ADMIN \
   --cap-add NET_BROADCAST -d \
   --name R2 frrouting/frr-debian
```

```bash
$ docker container rm -f $(docker container ls -aq)
```

```bash
$ docker compose -f docker-compose-practice.yaml up -d
$ docker compose -f docker-compose-practice.yaml down
```

---

## Lab6

### ip setting

h1(container) - ovs - h2(container)
```bash
sudo ovs-vsctl add-br br0                               # create the ovs named `br0`
sudo ovs-vsctl set bridge br0 protocols=OpenFlow14
sudo ovs-vsctl set-controller br0 tcp:0.0.0.0:6653

sudo ip link add veth-h1 type veth peer name eth-h1     # create veth pair <veth-h1> - <eth-h1>
sudo ip link set eth-h1 netns $(docker inspect -f '{{.State.Pid}}' h1)  # put eth-h1 to container

sudo ip link add veth-h2 type veth peer name eth-h2
sudo ip link set eth-h2 netns $(docker inspect -f '{{.State.Pid}}' h2) 

sudo ip link set veth-h1 up                             # activate the veth-h1
sudo ip link set veth-h2 up

docker exec -it h1 ip addr add 10.0.1.2/24 dev eth-h1
docker exec -it h2 ip addr add 10.0.1.3/24 dev eth-h2

docker exec -it h1 ip link set eth-h1 up
docker exec -it h2 ip link set eth-h2 up

sudo ovs-vsctl add-port br0 veth-h1                     # put veth-h1 to ovs
sudo ovs-vsctl add-port br0 veth-h2

sudo ovs-vsctl del-br br0
sudo ip link delete veth-h1
sudo ip link delete veth-h2
```


h1(172.16.10.2/24) - ovs1 - ovs2 - h2(172.16.10.3/24)
```bash
sudo ovs-vsctl add-br ovs1 -- set bridge ovs1 protocols=OpenFlow14 -- set-controller ovs1 tcp:192.168.100.1:6653
sudo ovs-vsctl add-br ovs2 -- set bridge ovs2 protocols=OpenFlow14 -- set-controller ovs2 tcp:192.168.100.1:6653

sudo ip link add veth-h1 type veth peer name eth-h1         # ovs1 - h1(container)
sudo ip link add veth-h2 type veth peer name eth-h2         # ovs2 - h2(container)
sudo ip link add veth-ovs1 type veth peer name veth-ovs2    # ovs1 - ovs2

sudo ovs-vsctl add-port ovs1 veth-h1
sudo ovs-vsctl add-port ovs1 veth-ovs1
sudo ovs-vsctl add-port ovs2 veth-ovs2
sudo ovs-vsctl add-port ovs2 veth-h2

sudo ip link set veth-h1 up
sudo ip link set veth-h2 up
sudo ip link set veth-ovs1 up
sudo ip link set veth-ovs2 up

sudo ip link set eth-h1 netns $(docker inspect -f '{{.State.Pid}}' h1)
sudo ip link set eth-h2 netns $(docker inspect -f '{{.State.Pid}}' h2) 
docker exec -it h1 ip addr add 172.16.10.2/24 dev eth-h1
docker exec -it h2 ip addr add 172.16.10.3/24 dev eth-h2

docker exec -it h1 ip link set eth-h1 up
docker exec -it h2 ip link set eth-h2 up

sudo ovs-vsctl del-br ovs1
sudo ovs-vsctl del-br ovs2
sudo ip link delete veth-h1
sudo ip link delete veth-h2
sudo ip link delete veth-ovs1
```

ovs2 -<vxlan>- TA(192.168.70.253)
```bash
sudo ovs-vsctl add-port ovs2 TO_TA_VXLAN -- set interface TO_TA_VXLAN type=vxlan options:remote_ip=192.168.60.10
```

ovs1 - frr(172.16.10.1/24)(192.168.63.1/24)(192.168.70.10/24)
```bash
sudo ip link add veth-frr type veth peer name eth-frr
sudo ovs-vsctl add-port ovs1 veth-frr
sudo ip link set veth-frr up
sudo ip link set eth-frr netns $(docker inspect -f '{{.State.Pid}}' frr)
docker exec -it frr ip addr add 172.16.10.1/24 dev eth-frr
docker exec -it frr ip addr add 192.168.63.1/24 dev eth-frr
docker exec -it frr ip addr add 192.168.70.10/24 dev eth-frr
docker exec -it frr ip link set eth-frr up

sudo ip link delete veth-frr
```

ovs1 - router(192.168.63.2/24)
```bash
sudo ip link add veth-r type veth peer name eth-r
sudo ovs-vsctl add-port ovs1 veth-r
sudo ip link set veth-r up
sudo ip link set eth-r netns $(docker inspect -f '{{.State.Pid}}' router)
docker exec router ip addr add 192.168.63.2/24 dev eth-r
docker exec router ip link set eth-r up

sudo ip link delete veth-r

docker exec -it router ip route add 192.168.70.0/24 via 192.168.63.1 dev eth-r
```

h3(172.17.10.2/24) - router(172.17.10.1/24)
```bash
sudo ip link add veth-h3 type veth peer name eth-h3

sudo ip link set eth-h3 netns $(docker inspect -f '{{.State.Pid}}' h3)
sudo ip link set veth-h3 netns $(docker inspect -f '{{.State.Pid}}' router)

docker exec h3 ip addr add 172.17.10.2/24 dev eth-h3
docker exec router ip addr add 172.17.10.1/24 dev veth-h3
docker exec h3 ip link set eth-h3 up
docker exec router ip link set veth-h3 up


docker exec h3 ip route del default 
docker exec h3 ip route add default via 172.17.10.1

sudo ip link delete veth-h3
```

### install learning bridge

```bash
onos-app localhost install! ~/SDN/Lab5/bridge-app/target/bridge-app-1.0-SNAPSHOT.oar
```

### command

Find the container's namespace(ns)
```bash
docker inspect -f '{{.State.Pid}}' < container name / container id >
docker inspect -f '{{.State.Pid}}' h1
```

#### Run project
```bash
wg-quick up wg0
make deploy
make clean
wg-quick down wg0
```

#### Network tools
```bash
ip a
ip -br -c a
ip route
ip -6 route

ip neigh
ip neigh flush all

ping 172.17.10.2
ping -6 2a0b:4e07:c4:110::2
```

#### Dashboard
http://140.113.60.186:8880/lg

#### Onos api
```bash
# Install Flow rule
curl -u onos:rocks -X POST -H 'Content-Type: application/json' \
-d @config/flow_ovs2.json 'http://localhost:8181/onos/v1/flows/of:0000011155014202'

# Network config
onos-netcfg localhost ./config/proxyndp.json
onos-netcfg localhost ./config/WANConnectionPoint
```

#### Onos terminal
```bash
onos onos@localhost
rocks
onos@root > interfaces

onos@root > routes
onos@root > hosts | grep 192.168.63.1

onos@root > apps -a -s
onos@root > app deactivate nycu.winlab.vrouter
onos@root > app uninstall nycu.winlab.vrouter

onos@root > logout
Ctrl + D
```

## Final
change frr ip from 172.16.10.1 to 172.16.10.69
disable ip forward on frr

bgp port 179
router:xxx (AS65101) <-> frr:179 (AS65100) passive
frr:xxx    (AS65100) <-> IXP:179 (AS65000) passive


### issue

#### IPV6 Connection between AS65xx0 and AS65xx1

On frr, find the mac of fd63::2 change frequently
```bash
root@e58c2612640d:/# ip -6 neigh
fe80::e0f1:adff:fecb:e0df dev eth-frr lladdr e2:f1:ad:cb:e0:df router REACHABLE
fe80::44a3:a3ff:fece:faf6 dev eth-frr lladdr 46:a3:a3:ce:fa:f6 STALE
fd70::fe dev eth-frr lladdr 0e:a7:1a:c5:29:15 router REACHABLE
fe80::200:ff:fe00:2 dev eth-frr lladdr 00:00:00:00:00:02 STALE
fe80::f42d:e8ff:fecb:edff dev eth-frr lladdr f6:2d:e8:cb:ed:ff STALE
fd63::2 dev eth-frr lladdr e2:f1:ad:cb:e0:df router REACHABLE

root@e58c2612640d:/# ip -6 neigh
fe80::e0f1:adff:fecb:e0df dev eth-frr lladdr e2:f1:ad:cb:e0:df router STALE
fe80::44a3:a3ff:fece:faf6 dev eth-frr lladdr 46:a3:a3:ce:fa:f6 STALE
fd70::fe dev eth-frr lladdr 0e:a7:1a:c5:29:15 router REACHABLE
fe80::200:ff:fe00:2 dev eth-frr lladdr 00:00:00:00:00:02 STALE
fe80::f42d:e8ff:fecb:edff dev eth-frr lladdr f6:2d:e8:cb:ed:ff STALE
fd63::2 dev eth-frr lladdr 00:00:00:00:00:02 router REACHABLE
```

Using wireshark catch the packets on veth-frr (filter: ICMP6).
Find the NDP NS with target fd63::2 send from other AS.

```pcap
Frame 5568: 86 bytes on wire (688 bits), 86 bytes captured (688 bits) on interface veth-frr, id 0
Ethernet II, Src: 00:00:00_00:00:04 (00:00:00:00:00:04), Dst: IPv6mcast_ff:00:00:02 (33:33:ff:00:00:02) Internet Protocol Version 6, Src: fd63::1, Dst: ff02::1:ff00:2
Internet Control Message Protocol v6 
Type: Neighbor Solicitation (135) 
Code: 0 
Checksum: 0x7ece [correct] [Checksum Status: Good] 
Reserved: 00000000 
Target Address: fd63::2 
ICMPv6 Option (Source link-layer address : 00:00:00:00:00:04) Type: Source link-layer address (1) Length: 1 (8 bytes) Link-layer address: 00:00:00_00:00:04 (00:00:00:00:00:04)
```

##### In Lab6 Solution
ovs routing base on Learning Bridge
Block the packet on ovs3 port 3
```json
{
  "priority": 50000,
  "timeout": 0,
  "isPermanent": true,
  "selector": {
    "criteria": [
      {
        "type": "IN_PORT",
        "port": "3"
      },
      { 
        "type": "ETH_TYPE", "ethType": "0x86DD"
      },
      { 
        "type": "IPV6_DST", "ip": "ff02::1:ff00:2/128" 
      }
    ]
  },
  "treatment": {}
}
```

##### In Final Solution
Implement the firewall in proxyndp to block the 192.168.63.0/24, fd63::/64 directly.


#### Vrouter try method

1. Point-To-Point Intent
  Intent has no timeout. There will be a lot of intent in onos.
2. Learning Bridge base
  There are many stupid packet from outside. Learn the wrong mac.
3. RouteService LogestPrefixMatch().nextHopMac
  The onos host provider learn/provide the wrong mac cause the nextHopMac return the wrong mac address.
  Ip ConnectPoint table learn the wrong cp, too.