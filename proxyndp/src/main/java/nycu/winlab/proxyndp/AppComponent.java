/*
 * Copyright 2025-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nycu.winlab.proxyndp;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.nio.ByteBuffer;
import java.util.Optional;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;

import org.onosproject.net.flow.DefaultTrafficTreatment;
// import org.onosproject.net.flow.TrafficTreatment;

import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.HostLocation;
import org.onosproject.net.PortNumber;

import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;

import org.onosproject.net.provider.ProviderId;
import org.onosproject.net.host.DefaultHostDescription;
import org.onosproject.net.host.HostDescription;
import org.onosproject.net.host.HostProvider;
import org.onosproject.net.host.HostProviderRegistry;
import org.onosproject.net.host.HostProviderService;

import org.onosproject.net.edge.EdgePortService;

import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onlab.packet.ARP;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.IPv6;
import org.onlab.packet.ICMP6;
import org.onlab.packet.ndp.NeighborSolicitation;
import org.onlab.packet.ndp.NeighborAdvertisement;

/**
 * Proxy ARP application component.
 */
@Component(immediate = true)
public class AppComponent implements HostProvider { // [CHANGE] Implements HostProvider

    private final Logger log = LoggerFactory.getLogger("ProxyNDP");

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    // [CHANGE] Inject HostProviderRegistry
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostProviderRegistry hostProviderRegistry;

    private ProxyNdpProcessor processor = new ProxyNdpProcessor();
    private ApplicationId appId;

    // [CHANGE] Variables for Host Provider
    private HostProviderService providerService;
    private static final ProviderId PID = new ProviderId("app", "nycu.winlab.proxyndp");

    // Table: IP -> MAC
    private Map<IpAddress, MacAddress> ipMacTable = new HashMap<>();

    // Table: requestIP -> ConnectPoint(devID, port)
    private Map<IpAddress, ConnectPoint> requestTable = new HashMap<>();

    private final DeviceId ovs1 = DeviceId.deviceId("of:0000011155014201");
    private final DeviceId ovs2 = DeviceId.deviceId("of:0000011155014202");
    private final DeviceId ovs3 = DeviceId.deviceId("of:0000226f63cd0340");

    private final ProxyNdpConfigListener cfgListener = new ProxyNdpConfigListener();
    private final ConfigFactory<ApplicationId, ProxyNdpConfig> factory = new ConfigFactory<>(
        APP_SUBJECT_FACTORY, ProxyNdpConfig.class, "ProxyNdpConfig") {
            @Override
            public ProxyNdpConfig createConfig() {
                return new ProxyNdpConfig();
            }
        };

    @Activate
    protected void activate() {
        // register your app
        appId = coreService.registerApplication("nycu.winlab.proxyndp");

        // [CHANGE] Register as a HostProvider
        providerService = hostProviderRegistry.register(this);

        // add a packet processor to packetService
        packetService.addProcessor(processor, PacketProcessor.director(2));

        cfgService.addListener(cfgListener);
        cfgService.registerConfigFactory(factory);

        // Register ARP packets
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        TrafficSelector.Builder selIpv6 = DefaultTrafficSelector.builder();
        selIpv6.matchEthType(Ethernet.TYPE_IPV6);
        selIpv6.matchIPProtocol(IPv6.PROTOCOL_ICMP6);
        packetService.requestPackets(selIpv6.build(), PacketPriority.REACTIVE, appId);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        // [CHANGE] Unregister HostProvider
        hostProviderRegistry.unregister(this);
        providerService = null;

        // remove your packet processor
        packetService.removeProcessor(processor);
        processor = null;

        cfgService.removeListener(cfgListener);
        cfgService.unregisterConfigFactory(factory);

        // remove flowrule you installed for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        TrafficSelector.Builder selIpv6 = DefaultTrafficSelector.builder();
        selIpv6.matchEthType(Ethernet.TYPE_IPV6);
        selIpv6.matchIPProtocol(IPv6.PROTOCOL_ICMP6);
        packetService.cancelPackets(selIpv6.build(), PacketPriority.REACTIVE, appId);

        log.info("Stopped");
    }

    // [CHANGE] Required method for HostProvider interface
    @Override
    public ProviderId id() {
        return PID;
    }

    // [CHANGE] Required method for HostProvider interface
    @Override
    public void triggerProbe(Host host) {
        // Optional: Logic to probe host if needed (e.g. send ARP request)
    }

    // [CHANGE] Helper method to push Host info to ONOS Core
    private void learnHost(IpAddress ip, MacAddress mac, VlanId vlan, DeviceId deviceId, PortNumber port) {
        if (providerService == null) {
            return;
        }

        // Prepare Host ID
        HostId hostId = HostId.hostId(mac, vlan);

        // Prepare Location
        HostLocation loc = new HostLocation(deviceId, port, System.currentTimeMillis());

        // Create Description
        // This tells the core: This MAC has this IP, and is at this location
        HostDescription desc = new DefaultHostDescription(
                mac,
                vlan,
                loc,
                Collections.singleton(ip)
        );

        // Push to core
        providerService.hostDetected(hostId, desc, false);
        //log.info("Pushed Host to Core: IP={} MAC={}", ip, mac);
    }

    private class ProxyNdpConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
            && event.configClass().equals(ProxyNdpConfig.class)) {
                ProxyNdpConfig config = cfgService.getConfig(appId, ProxyNdpConfig.class);
                if (config != null) {
                    MacAddress vrouterMac =  MacAddress.valueOf(config.getVrouterMac());
                    IpAddress vrouterIpv4 = IpAddress.valueOf(config.getVrouterIpv4());
                    IpAddress vrouterIpv6 = IpAddress.valueOf(config.getVrouterIpv6());

                    ipMacTable.put(vrouterIpv4, vrouterMac);
                    ipMacTable.put(vrouterIpv6, vrouterMac);
                    log.info("Insert vrouter to table. Ipv4 = {}, Ipv6 = {}, MAC = {}",
                    config.getVrouterIpv4(), config.getVrouterIpv6(), config.getVrouterMac());
                }
            }
        }
    }

    private class ProxyNdpProcessor implements PacketProcessor {
        IpAddress my70 = IpAddress.valueOf("192.168.70.10");
        IpAddress peerA70 = IpAddress.valueOf("192.168.70.11");
        IpAddress ixp70 = IpAddress.valueOf("192.168.70.253");

        IpAddress myFd70 = IpAddress.valueOf("fd70::10");
        IpAddress peerAFd70 = IpAddress.valueOf("fd70::11");
        IpAddress ixpFd70 = IpAddress.valueOf("fd70::fe");

        // 63 only exist in ovs1
        IpPrefix prefix63 = IpPrefix.valueOf("192.168.63.0/24");
        IpPrefix prefixFd63 = IpPrefix.valueOf("fd63::/64");

        // My network
        IpPrefix prefix65100 = IpPrefix.valueOf("172.16.10.0/24");
        IpPrefix prefix65101 = IpPrefix.valueOf("172.17.10.0/24");
        IpPrefix prefix65100v6 = IpPrefix.valueOf("2a0b:4e07:c4:10::/64");
        IpPrefix prefix65101v6 = IpPrefix.valueOf("2a0b:4e07:c4:110::/64");

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            if (context.isHandled()) {
                return;
            }
            InboundPacket inPkt = context.inPacket();
            Ethernet ethPkt = inPkt.parsed();
            DeviceId recDevId = inPkt.receivedFrom().deviceId();
            PortNumber recPort = inPkt.receivedFrom().port();
            VlanId vlan = VlanId.vlanId(ethPkt.getVlanID()); // Get VLAN for Host learning

            if (ethPkt == null) {
                return;
            }

            // Handle ARP and NDP
            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                ARP arp = (ARP) ethPkt.getPayload();

                MacAddress srcMac = MacAddress.valueOf(arp.getSenderHardwareAddress());
                IpAddress srcIp = IpAddress.valueOf(IpAddress.Version.INET, arp.getSenderProtocolAddress());
                MacAddress dstMac = MacAddress.valueOf(arp.getTargetHardwareAddress());
                IpAddress dstIp = IpAddress.valueOf(IpAddress.Version.INET, arp.getTargetProtocolAddress());

                // Block 192.168.63.0/24 from outside
                if ((prefix63.contains(srcIp) || prefix63.contains(dstIp)) && !recDevId.equals(ovs1)) {
                    log.info("[DEBUG] Skip process for ARP: {} -> {} on {}", srcIp, dstIp, recDevId);
                    context.block();
                    return; // don't flood, don't handle this ARP
                }

                // [CHANGE] Learn host info immediately from the incoming ARP packet
                learnHost(srcIp, srcMac, vlan, recDevId, recPort);

                // Add src to table
                if (ipMacTable.get(srcIp) == null) {
                    ipMacTable.put(srcIp, srcMac);
                }

                // Firewall whitelist
                if (!dstIp.equals(my70) && !dstIp.equals(ixp70) && !dstIp.equals(peerA70) &&
                    !prefix63.contains(dstIp) && !prefix65100.contains(dstIp) && !prefix65101.contains(dstIp)) {
                    //log.info("Skip flood for ARP: {}", dstIp);
                    context.block();
                    return; // don't flood, don't handle this ARP
                }

                if (arp.getOpCode() == ARP.OP_REQUEST) {
                    if (ipMacTable.get(dstIp) == null) {
                        // Flood ARP Request to edge port
                        flood(context, ethPkt);
                        requestTable.put(srcIp, new ConnectPoint(recDevId, recPort));
                        log.info("ARP TABLE MISS. {} -> {}, Flood", srcIp, dstIp);
                    } else {
                        // Send ARP Reply to the requester
                        MacAddress targetMac = ipMacTable.get(dstIp);
                        Ethernet arpReply = ARP.buildArpReply(dstIp.getIp4Address(), targetMac, ethPkt);
                        sendReply(arpReply, recDevId, recPort);
                        log.info("ARP TABLE HIT. {} -> {} Requested MAC = {}", srcIp, dstIp, targetMac);
                    }
                } else if (arp.getOpCode() == ARP.OP_REPLY) {
                    // Send ARP Reply to the original requester
                    ConnectPoint requestHost = requestTable.get(dstIp);
                    if (requestHost != null) {
                        sendReply(ethPkt, requestHost.deviceId(), requestHost.port());
                        //log.info("RECV REPLY. {} <- {} Requested MAC = {}", dstIp, srcIp, srcMac);
                    }
                    //requestTable.remove(dstIp);
                }
                // Blocks the outbound packet
                context.block();
                return;
            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6 = (IPv6) ethPkt.getPayload();
                if (ipv6.getNextHeader() == IPv6.PROTOCOL_ICMP6) {
                    MacAddress srcMac = ethPkt.getSourceMAC();
                    IpAddress srcIp = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getSourceAddress());
                    ICMP6 icmp6 = (ICMP6) ipv6.getPayload();
                    byte icmpType = icmp6.getIcmpType();

                    // Handle NDP (A -> B) Neighbor Solicitation
                    if (icmpType == ICMP6.NEIGHBOR_SOLICITATION) {
                        // Block fd63::/64 from outside
                        IpAddress srcIp63 = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getSourceAddress());
                        IpAddress dstIp63 = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getDestinationAddress());
                        if ((prefixFd63.contains(srcIp63) || prefixFd63.contains(dstIp63)) && !recDevId.equals(ovs1)) {
                            log.info("[DEBUG] Skip process for ICMP6: {} -> {} on {}", srcIp63, dstIp63, recDevId);
                            context.block();
                            return; // don't flood, don't handle this IPv6
                        }

                        // [CHANGE] Learn host info immediately from incoming IPv6 packet
                        learnHost(srcIp, srcMac, vlan, recDevId, recPort);

                        // Add src to table
                        if (ipMacTable.get(srcIp) == null) {
                            ipMacTable.put(srcIp, srcMac);
                        }

                        // Get Taget IP from NS
                        NeighborSolicitation ns = (NeighborSolicitation) icmp6.getPayload();
                        IpAddress dstIp = IpAddress.valueOf(IpAddress.Version.INET6, ns.getTargetAddress());

                        // Firewall whitelist
                        if (!dstIp.equals(myFd70) && !dstIp.equals(ixpFd70) && !prefixFd63.contains(dstIp) &&
                            !prefix65100v6.contains(dstIp) && !prefix65101v6.contains(dstIp)) {
                            //log.info("[DEBUG] Skip flood for NS: {}", dstIp);
                            context.block();
                            return; // don't flood, don't handle this ARP
                        }

                        if (ipMacTable.get(dstIp) == null) {
                            // Flood NDP NS to edge port
                            flood(context, ethPkt);
                            requestTable.put(srcIp, new ConnectPoint(recDevId, recPort));
                            log.info("NDP TABLE MISS. {} -> {}, Flood", srcIp, dstIp);
                        } else {
                            // Send NDP NA to the requester
                            MacAddress targetMac = ipMacTable.get(dstIp);
                            Ethernet ndpReply = NeighborAdvertisement.buildNdpAdv(
                                dstIp.getIp6Address(), targetMac, ethPkt);
                            IPv6 ipv6NdpReply = (IPv6) ndpReply.getPayload();
                            ipv6NdpReply.setHopLimit((byte) 255);   // buildNdpAdv use 85 which is wrong
                            sendReply(ndpReply, recDevId, recPort);
                            log.info("NDP TABLE HIT. {} -> {}, Requested MAC = {}", srcIp, dstIp, targetMac);
                        }
                        // Blocks the outbound packet
                        context.block();
                        return;
                    } else if (icmpType == ICMP6.NEIGHBOR_ADVERTISEMENT) {
                        // Block fd63::/64 from outside
                        IpAddress srcIp63 = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getSourceAddress());
                        IpAddress dstIp63 = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getDestinationAddress());
                        if ((prefixFd63.contains(srcIp63) || prefixFd63.contains(dstIp63)) && !recDevId.equals(ovs1)) {
                            log.info("[DEBUG] Skip process for ICMP6: {} -> {} on {}", srcIp63, dstIp63, recDevId);
                            context.block();
                            return; // don't flood, don't handle this IPv6
                        }

                        // [CHANGE] Learn host info immediately from incoming IPv6 packet
                        learnHost(srcIp, srcMac, vlan, recDevId, recPort);

                        // Add src to table
                        if (ipMacTable.get(srcIp) == null) {
                            ipMacTable.put(srcIp, srcMac);
                        }
                        // Send NA to the original requester
                        IpAddress dstIp = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getDestinationAddress());

                        // Firewall whitelist
                        if (!dstIp.equals(myFd70) && !dstIp.equals(ixpFd70) && !prefixFd63.contains(dstIp) &&
                            !prefix65100v6.contains(dstIp) && !prefix65101v6.contains(dstIp)) {
                            //log.info("[DEBUG] Skip flood for NA: {}", dstIp);
                            context.block();
                            return; // don't flood, don't handle this ARP
                        }

                        ConnectPoint requestHost = requestTable.get(dstIp);
                        if (requestHost != null) {
                            sendReply(ethPkt, requestHost.deviceId(), requestHost.port());
                            //log.info("RECV REPLY. Requested MAC = {}", srcMac);
                        }
                        requestTable.remove(dstIp);

                        // Blocks the outbound packet
                        context.block();
                        return;
                    }
                }
            }
        }
    }

    private void sendReply(Ethernet eth, DeviceId devID, PortNumber outPort) {
        packetService.emit(
            new DefaultOutboundPacket(
                devID,
                DefaultTrafficTreatment.builder().setOutput(outPort).build(),
                ByteBuffer.wrap(eth.serialize())
            )
        );
    }

    private void flood(PacketContext context, Ethernet ethPkt) {
        // Serialize the ARP packet
        ByteBuffer data = ByteBuffer.wrap(ethPkt.serialize());

        // Emit packet to all edge ports
        edgePortService.emitPacket(
            data,
            Optional.of(DefaultTrafficTreatment.emptyTreatment())
        );
    }
}