/*
 * Copyright 2025-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
import org.onosproject.net.PortNumber;

import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;

import org.onosproject.net.edge.EdgePortService;

import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
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
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger("ProxyNDP");

    /** Some configurable property. */

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    private ProxyNdpProcessor processor = new ProxyNdpProcessor();
    private ApplicationId appId;

    // Table: IP -> MAC
    private Map<IpAddress, MacAddress> ipMacTable = new HashMap<>();

    // Table: requestIP -> ConnectPoint(devID, port)
    private Map<IpAddress, ConnectPoint> requestTable = new HashMap<>();

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
        IpPrefix prefix70 = IpPrefix.valueOf("192.168.70.0/24");
        IpAddress my70 = IpAddress.valueOf("192.168.70.10");
        IpAddress ixp70 = IpAddress.valueOf("192.168.70.253");
        IpPrefix prefixFd70 = IpPrefix.valueOf("fd70::/64");
        IpAddress myFd70 = IpAddress.valueOf("fd70::10");
        IpAddress ixpFd70 = IpAddress.valueOf("fd70::fe");

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

            if (ethPkt == null) {
                return;
            }

            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                ARP arp = (ARP) ethPkt.getPayload();

                MacAddress srcMac = MacAddress.valueOf(arp.getSenderHardwareAddress());
                IpAddress srcIp = IpAddress.valueOf(IpAddress.Version.INET, arp.getSenderProtocolAddress());
                MacAddress dstMac = MacAddress.valueOf(arp.getTargetHardwareAddress());
                IpAddress dstIp = IpAddress.valueOf(IpAddress.Version.INET, arp.getTargetProtocolAddress());

                // Add src to table
                if (ipMacTable.get(srcIp) == null) {
                    ipMacTable.put(srcIp, srcMac);
                }

                // Block other AS's ARP
                if (prefix70.contains(dstIp) && !dstIp.equals(my70) && !dstIp.equals(ixp70)) {
                    //log.info("Skip flood for NS: {} in 192.168.70.0/24 (except 192.168.70.10)", dstIp);
                    context.block();
                    return; // don't flood, don't handle this NS
                }

                // Handle ARP (A -> B)
                if (arp.getOpCode() == ARP.OP_REQUEST) {
                    if (ipMacTable.get(dstIp) == null) {
                        // B's IP (dstIp)
                        // Flood ARP Request to edge port
                        flood(context, ethPkt);

                        // Add A's IP to requestTable
                        requestTable.put(srcIp, new ConnectPoint(recDevId, recPort));
                        log.info("ARP TABLE MISS. Requested IP = {}, Send request to edge ports", dstIp);
                    } else {
                        // Send ARP Reply to the requester
                        MacAddress targetMac = ipMacTable.get(dstIp);
                        //buildArpReply​(Ip4Address srcIp, MacAddress srcMac, Ethernet request)
                        Ethernet arpReply = ARP.buildArpReply(
                            dstIp.getIp4Address(), targetMac, ethPkt);

                        sendReply(arpReply, recDevId, recPort);
                        log.info("ARP TABLE HIT. Requested MAC = {}", targetMac);
                    }
                } else if (arp.getOpCode() == ARP.OP_REPLY) {
                    // Send ARP Reply to the original requester
                    // A's IP (dstIp)
                    ConnectPoint requestHost = requestTable.get(dstIp);
                    if (requestHost != null) {
                        sendReply(ethPkt, requestHost.deviceId(), requestHost.port());
                        //log.info("RECV REPLY. Requested MAC = {}", srcMac);
                    }
                    requestTable.remove(dstIp);
                }
            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6 = (IPv6) ethPkt.getPayload();
                if (ipv6.getNextHeader() == IPv6.PROTOCOL_ICMP6) {
                    MacAddress srcMac = ethPkt.getSourceMAC();
                    IpAddress srcIp = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getSourceAddress());

                    ICMP6 icmp6 = (ICMP6) ipv6.getPayload();
                    byte icmpType = icmp6.getIcmpType();

                    // Handle NDP (A -> B) Neighbor Solicitation
                    if (icmpType == ICMP6.NEIGHBOR_SOLICITATION) {
                        // Add src to table
                        if (ipMacTable.get(srcIp) == null) {
                            ipMacTable.put(srcIp, srcMac);
                        }
                        // Get Taget IP from NS
                        NeighborSolicitation ns = (NeighborSolicitation) icmp6.getPayload();
                        IpAddress dstIp = IpAddress.valueOf(IpAddress.Version.INET6, ns.getTargetAddress());

                        // Block other AS's NS
                        if (prefixFd70.contains(dstIp) && !dstIp.equals(myFd70) && !dstIp.equals(ixpFd70)) {
                            //log.info("Skip flood for NS: {} in fd70::/64 (except fd70::10)", dstIp);
                            context.block();
                            return; // don't flood, don't handle this NS
                        }

                        if (ipMacTable.get(dstIp) == null) {
                            // Flood NDP NS to edge port
                            flood(context, ethPkt);

                            // Add A's IP to requestTable
                            requestTable.put(srcIp, new ConnectPoint(recDevId, recPort));
                            log.info("NDP TABLE MISS. Requested IP = {}, Send NDP Solicitation to edge ports", dstIp);
                        } else {
                            // Send NDP NA to the requester
                            MacAddress targetMac = ipMacTable.get(dstIp);
                            Ethernet ndpReply = NeighborAdvertisement.buildNdpAdv(
                                dstIp.getIp6Address(), targetMac, ethPkt);

                            IPv6 ipv6NdpReply = (IPv6) ndpReply.getPayload();
                            ipv6NdpReply.setHopLimit((byte) 255);   // buildNdpAdv use 85 which is wrong

                            sendReply(ndpReply, recDevId, recPort);
                            log.info("NDP TABLE HIT. Requested MAC = {}", targetMac);
                        }
                    } else if (icmpType == ICMP6.NEIGHBOR_ADVERTISEMENT) {
                        // Add src to table
                        if (ipMacTable.get(srcIp) == null) {
                            ipMacTable.put(srcIp, srcMac);
                        }
                        // Send NA to the original requester
                        // A's IP (dstIp)
                        IpAddress dstIp = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getDestinationAddress());
                        ConnectPoint requestHost = requestTable.get(dstIp);
                        if (requestHost != null) {
                            sendReply(ethPkt, requestHost.deviceId(), requestHost.port());
                            //log.info("RECV REPLY. Requested MAC = {}", srcMac);
                        }
                        requestTable.remove(dstIp);
                    }
                }
            }
            // Blocks the outbound packet
            context.block();
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

