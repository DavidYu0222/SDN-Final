#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'
BRIDGE_APP_PATH="${HOME}/SDN/Lab5/bridge-app/target/bridge-app-1.0-SNAPSHOT.oar"
PROXYNDP_APP_PATH="./proxyndp/target/proxyndp-1.0-SNAPSHOT.oar"

function create_topology() {
    echo -e "${GREEN}Starting Topology deploying.${NC}"

    echo -e "${YELLOW}Starting Docker containers...${NC}"
    docker compose up -d

    echo -e "${YELLOW}Creating OVS bridges...${NC}"
    sudo ovs-vsctl --if-exists del-br ovs1
    sudo ovs-vsctl --if-exists del-br ovs2
    sudo ovs-vsctl add-br ovs1 -- set bridge ovs1 protocols=OpenFlow14 -- set-controller ovs1 tcp:192.168.100.1:6653 -- set bridge ovs1 other-config:datapath-id=0000011155014201
    sudo ovs-vsctl add-br ovs2 -- set bridge ovs2 protocols=OpenFlow14 -- set-controller ovs2 tcp:192.168.100.1:6653 -- set bridge ovs2 other-config:datapath-id=0000011155014202

    echo -e "${YELLOW}Creating veth pairs...${NC}"
    sudo ip link add veth-h1 type veth peer name eth-h1 || true
    sudo ip link add veth-h2 type veth peer name eth-h2 || true
    sudo ip link add veth-ovs1 type veth peer name veth-ovs2 || true
    sudo ip link add veth-frr type veth peer name eth-frr || true
    sudo ip link add veth-r type veth peer name eth-r || true
    sudo ip link add veth-h3 type veth peer name eth-h3 || true

    echo -e "${YELLOW}Connecting veths to OVS...${NC}"
    sudo ovs-vsctl add-port ovs1 veth-h1 || true
    sudo ovs-vsctl add-port ovs2 veth-h2 || true
    sudo ovs-vsctl add-port ovs1 veth-ovs1 || true
    sudo ovs-vsctl add-port ovs2 veth-ovs2 || true
    sudo ovs-vsctl add-port ovs1 veth-frr || true
    sudo ovs-vsctl add-port ovs1 veth-r || true
    sudo ovs-vsctl add-port ovs2 TO_TA_VXLAN -- set interface TO_TA_VXLAN type=vxlan options:remote_ip=192.168.60.10

    echo -e "${YELLOW}Setting veths up...${NC}"
    sudo ip link set veth-h1 up
    sudo ip link set veth-h2 up
    sudo ip link set veth-ovs1 up
    sudo ip link set veth-ovs2 up
    sudo ip link set veth-frr up
    sudo ip link set veth-r up

    echo -e "${YELLOW}Moving container interfaces to namespaces...${NC}"
    sudo ip link set eth-h1 netns $(docker inspect -f '{{.State.Pid}}' h1)
    sudo ip link set eth-h2 netns $(docker inspect -f '{{.State.Pid}}' h2)
    sudo ip link set eth-frr netns $(docker inspect -f '{{.State.Pid}}' frr)
    sudo ip link set eth-r netns $(docker inspect -f '{{.State.Pid}}' router)
    sudo ip link set veth-h3 netns $(docker inspect -f '{{.State.Pid}}' router)
    sudo ip link set eth-h3 netns $(docker inspect -f '{{.State.Pid}}' h3)

    echo -e "${YELLOW}Assigning IPs inside containers...${NC}"
    docker exec h1 ip addr add 172.16.10.2/24 dev eth-h1
    docker exec h1 ip -6 addr add 2a0b:4e07:c4:10::2/64 dev eth-h1
    docker exec h2 ip addr add 172.16.10.3/24 dev eth-h2
    docker exec h2 ip -6 addr add 2a0b:4e07:c4:10::3/64 dev eth-h2
    docker exec frr ip addr add 172.16.10.69/24 dev eth-frr
    docker exec frr ip addr add 192.168.63.1/24 dev eth-frr
    docker exec frr ip addr add 192.168.70.10/24 dev eth-frr
    docker exec frr ip -6 addr add 2a0b:4e07:c4:10::69/64 dev eth-frr
    docker exec frr ip -6 addr add fd63::1/64 dev eth-frr
    docker exec frr ip -6 addr add fd70::10/64 dev eth-frr
    docker exec router ip addr add 192.168.63.2/24 dev eth-r
    docker exec router ip addr add 172.17.10.1/24 dev veth-h3
    docker exec router ip -6 addr add fd63::2/64 dev eth-r
    docker exec router ip -6 addr add 2a0b:4e07:c4:110::1/64 dev veth-h3
    docker exec h3 ip addr add 172.17.10.2/24 dev eth-h3
    docker exec h3 ip -6 addr add 2a0b:4e07:c4:110::2/64 dev eth-h3

    echo -e "${YELLOW}Bringing container interfaces up...${NC}"
    docker exec h1 ip link set eth-h1 up
    docker exec h2 ip link set eth-h2 up
    docker exec frr ip link set eth-frr up
    docker exec router ip link set eth-r up
    docker exec router ip link set veth-h3 up
    docker exec h3 ip link set eth-h3 up

    echo -e "${GREEN}Topology deployed successfully.${NC}"
}

function set_route() {
    echo -e "${GREEN}Set host default route. ${NC}"
    docker exec h1 ip route del default 
    docker exec h1 ip route add default via 172.16.10.1
    docker exec h1 ip -6 route add default via 2a0b:4e07:c4:10::1
    docker exec h2 ip route del default 
    docker exec h2 ip route add default via 172.16.10.1
    docker exec h2 ip -6 route add default via 2a0b:4e07:c4:10::1
    docker exec h3 ip route del default 
    docker exec h3 ip route add default via 172.17.10.1
    docker exec h3 ip -6 route add default via 2a0b:4e07:c4:110::1

    echo -e "${YELLOW}Set route router(AS65101) - frr(AS65100) ${NC}"
    docker exec router ip route add 192.168.70.0/24 via 192.168.63.1 dev eth-r
    docker exec router ip -6 route add fd70::/64 via fd63::1 dev eth-r

    echo -e "${GREEN}Route setting completed.${NC}"
}

function clean_topology() {
    echo -e "${RED}Stopping containers...${NC}"
    docker compose down

    echo -e "${RED}Deleting OVS bridges...${NC}"
    sudo ovs-vsctl --if-exists del-br ovs1
    sudo ovs-vsctl --if-exists del-br ovs2

    echo -e "${RED}Deleting veth pairs...${NC}"
    sudo ip link del veth-h1 2>/dev/null || true
    sudo ip link del veth-h2 2>/dev/null || true
    sudo ip link del veth-ovs1 2>/dev/null || true
    sudo ip link del veth-frr 2>/dev/null || true
    sudo ip link del veth-frr63 2>/dev/null || true
    sudo ip link del veth-r 2>/dev/null || true
    sudo ip link del veth-h3 2>/dev/null || true

    echo -e "${RED}Topology cleaned.${NC}"
}

function install_bridge_app() {
echo -e "${GREEN}Waiting for ONOS to accept app installation...${NC}"

until onos-app localhost install! "${BRIDGE_APP_PATH}" 2>&1 | grep -q '"state":"ACTIVE"'; do
    echo -e "${YELLOW}[WAIT] ONOS not ready yet... retry in 2 seconds${NC}"
    sleep 2
done

echo -e "${GREEN}bridge-app is ACTIVE!${NC}"
}

function install_proxyndp_app() {
echo -e "${GREEN}Install Proxy NDP app to ONOS.${NC}"

until onos-app localhost install! "${PROXYNDP_APP_PATH}" 2>&1 | grep -q '"state":"ACTIVE"'; do
    echo -e "${YELLOW}[WAIT] ONOS not ready yet... retry in 2 seconds${NC}"
    sleep 2
done

echo -e "${GREEN}proxyndp-app is ACTIVE!${NC}"

sleep 4
echo -e "${GREEN}Pass config using netcfg.${NC}"
onos-netcfg localhost ./config/proxyndp.json
}

function install_flow_rule() {
echo -e "${GREEN}Install flow rule for OVS2${NC}"

while true; do
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -u onos:rocks \
        -X POST -H 'Content-Type: application/json' \
        -d @config/flow_ovs2.json \
        'http://localhost:8181/onos/v1/flows/of:0000011155014202')

    if [ "$RESPONSE" -eq 201 ]; then
        echo -e "${GREEN}[SUCCESS] Flow rule installed!${NC}"
        break
    else
        echo -e "${YELLOW}[WAIT] Flow install failed (HTTP $RESPONSE), retrying in 2 seconds...${NC}"
        sleep 2
    fi
done
}


case "$1" in
    up)
        create_topology
        set_route
        install_proxyndp_app
        install_bridge_app
        # wg-quick up wg0
        # sleep 10
        # install_flow_rule
        ;;
    down)
        clean_topology
        # wg-quick down wg0
        ;;
    *)
        echo "Usage: $0 {up|down}"
        exit 1
        ;;
esac
