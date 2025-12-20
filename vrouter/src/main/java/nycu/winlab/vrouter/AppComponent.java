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
package nycu.winlab.vrouter;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;
import java.util.Optional;
//import java.util.Collection;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.nio.ByteBuffer;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;

import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;

import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;

import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IPv6;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.IPv4;

import org.onosproject.net.PortNumber;
import org.onosproject.net.DeviceId;

import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.FlowRule;

import org.onosproject.net.ConnectPoint;
import org.onosproject.net.FilteredConnectPoint;

import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.PointToPointIntent;
import org.onosproject.net.intent.MultiPointToSinglePointIntent;
//import org.onosproject.net.intent.SinglePointToMultiPointIntent;

import org.onosproject.net.intf.InterfaceService;
import org.onosproject.routeservice.RouteService;
import org.onosproject.routeservice.ResolvedRoute;

/**
 * Learning Bridge application component.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger("VRouter");

    /** Some configurable property. */
    // @Reference(cardinality = ReferenceCardinality.MANDATORY)
    // protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected RouteService routeService;

    // private final VRouterConfigListener cfgListener = new VRouterConfigListener();
    // private final ConfigFactory<ApplicationId, ProxyNdpConfig> factory = new ConfigFactory<>(
    //     APP_SUBJECT_FACTORY, ProxyNdpConfig.class, "ProxyNdpConfig") {
    //         @Override
    //         public ProxyNdpConfig createConfig() {
    //             return new ProxyNdpConfig();
    //         }
    //     };


    private RouteProcessor processor = new RouteProcessor();
    private ApplicationId appId;
    private MacAddress vrouterMac = MacAddress.valueOf("00:00:00:00:00:12");
    private final DeviceId ovs1 = DeviceId.deviceId("of:0000031355101801");
    private final DeviceId ovs2 = DeviceId.deviceId("of:0000031355101802");
    private final DeviceId ovs3 = DeviceId.deviceId("of:0000a68674038149");
    private IpAddress bgpSpeakerIpv4 = IpAddress.valueOf("192.168.70.12");
    private IpAddress bgpSpeakerIpv6 = IpAddress.valueOf("fd70::12");

    @Activate
    protected void activate() {

        // register app
        appId = coreService.registerApplication("nycu.winlab.vrouter");

        // // add a packet processor to packetService
        packetService.addProcessor(processor, PacketProcessor.director(2));

        TrafficSelector.Builder selv4 = DefaultTrafficSelector.builder();
        selv4.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selv4.build(), PacketPriority.REACTIVE, appId);

        TrafficSelector.Builder selv6 = DefaultTrafficSelector.builder();
        selv6.matchEthType(Ethernet.TYPE_IPV6);
        packetService.requestPackets(selv6.build(), PacketPriority.REACTIVE, appId);

        installBgpIntent();
        FilteredConnectPoint peerA = new FilteredConnectPoint(ConnectPoint.deviceConnectPoint("of:0000031355101802/4"));
        FilteredConnectPoint peerB = new FilteredConnectPoint(ConnectPoint.deviceConnectPoint("of:0000031355101802/5"));
        installPeerIntent(peerA, IpPrefix.valueOf("192.168.70.10/32"), IpPrefix.valueOf("fd70::10/128"));
        installPeerIntent(peerB, IpPrefix.valueOf("192.168.70.11/32"), IpPrefix.valueOf("fd70::11/128"));

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {

        // remove flowrule installed by app
        flowRuleService.removeFlowRulesById(appId);

        // remove packet processor
        packetService.removeProcessor(processor);
        processor = null;

        TrafficSelector.Builder selv4 = DefaultTrafficSelector.builder();
        selv4.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selv4.build(), PacketPriority.REACTIVE, appId);

        TrafficSelector.Builder selv6 = DefaultTrafficSelector.builder();
        selv6.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(selv6.build(), PacketPriority.REACTIVE, appId);

        log.info("Stopped");
    }

    private void installBgpIntent() {
        FilteredConnectPoint bgpSpeaker = new FilteredConnectPoint(
            interfaceService.getMatchingInterface(bgpSpeakerIpv4).connectPoint()
        );

        log.info("BGP Speaker CP: {}", bgpSpeaker);

        Set<FilteredConnectPoint> wanCps = new HashSet<>();
        FilteredConnectPoint wan1 = new FilteredConnectPoint(ConnectPoint.deviceConnectPoint("of:0000031355101801/4"));
        FilteredConnectPoint wan2 = new FilteredConnectPoint(ConnectPoint.deviceConnectPoint("of:0000a68674038149/3"));
        wanCps.add(wan1);
        wanCps.add(wan2);

        MultiPointToSinglePointIntent wan2SpeakerIpv4Intent = MultiPointToSinglePointIntent.builder()
            .appId(appId)
            .filteredIngressPoints(wanCps)
            .filteredEgressPoint(bgpSpeaker)
            .selector(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .matchIPDst(IpPrefix.valueOf(bgpSpeakerIpv4, 32))
                .build()
            )
            .treatment(DefaultTrafficTreatment.builder().build())
            .build();

        MultiPointToSinglePointIntent wan2SpeakerIpv6Intent = MultiPointToSinglePointIntent.builder()
            .appId(appId)
            .filteredIngressPoints(wanCps)
            .filteredEgressPoint(bgpSpeaker)
            .selector(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV6)
                .matchIPProtocol(IPv6.PROTOCOL_TCP)
                .matchIPv6Dst(IpPrefix.valueOf(bgpSpeakerIpv6, 128))
                .build()
            )
            .treatment(DefaultTrafficTreatment.builder().build())
            .build();

        intentService.submit(wan2SpeakerIpv4Intent);
        intentService.submit(wan2SpeakerIpv6Intent);

        PointToPointIntent speaker2Wan1Ipv4Intent = PointToPointIntent.builder()
            .appId(appId)
            .filteredIngressPoint(bgpSpeaker)
            .filteredEgressPoint(wan1)
            .selector(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .matchIPSrc(IpPrefix.valueOf(bgpSpeakerIpv4, 32))
                .matchIPDst(IpPrefix.valueOf("192.168.63.2/32"))
                .build()
            )
            .treatment(DefaultTrafficTreatment.builder().build())
            .build();

        PointToPointIntent speaker2Wan2Ipv4Intent = PointToPointIntent.builder()
            .appId(appId)
            .filteredIngressPoint(bgpSpeaker)
            .filteredEgressPoint(wan2)
            .selector(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .matchIPSrc(IpPrefix.valueOf(bgpSpeakerIpv4, 32))
                .matchIPDst(IpPrefix.valueOf("192.168.70.253/32"))
                .build()
            )
            .treatment(DefaultTrafficTreatment.builder().build())
            .build();

        PointToPointIntent speaker2Wan1Ipv6Intent = PointToPointIntent.builder()
            .appId(appId)
            .filteredIngressPoint(bgpSpeaker)
            .filteredEgressPoint(wan1)
            .selector(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV6)
                .matchIPProtocol(IPv6.PROTOCOL_TCP)
                .matchIPv6Src(IpPrefix.valueOf(bgpSpeakerIpv6, 128))
                .matchIPv6Dst(IpPrefix.valueOf("fd63::2/128"))
                .build()
            )
            .treatment(DefaultTrafficTreatment.builder().build())
            .build();

        PointToPointIntent speaker2Wan2Ipv6Intent = PointToPointIntent.builder()
            .appId(appId)
            .filteredIngressPoint(bgpSpeaker)
            .filteredEgressPoint(wan2)
            .selector(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV6)
                .matchIPProtocol(IPv6.PROTOCOL_TCP)
                .matchIPv6Src(IpPrefix.valueOf(bgpSpeakerIpv6, 128))
                .matchIPv6Dst(IpPrefix.valueOf("fd70::fe/128"))
                .build()
            )
            .treatment(DefaultTrafficTreatment.builder().build())
            .build();

        intentService.submit(speaker2Wan1Ipv4Intent);
        intentService.submit(speaker2Wan2Ipv4Intent);
        intentService.submit(speaker2Wan1Ipv6Intent);
        intentService.submit(speaker2Wan2Ipv6Intent);
    }

    private void installPeerIntent(FilteredConnectPoint peerCP, IpPrefix peerIpv4, IpPrefix peerIpv6) {
        FilteredConnectPoint bgpSpeaker = new FilteredConnectPoint(
            interfaceService.getMatchingInterface(bgpSpeakerIpv4).connectPoint()
        );

        log.info("BGP Speaker CP: {}", bgpSpeaker);

        PointToPointIntent peerIpv4IntentOut = PointToPointIntent.builder()
            .appId(appId)
            .filteredIngressPoint(bgpSpeaker)   // ingress
            .filteredEgressPoint(peerCP)          // egress
            .selector(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .matchIPSrc(IpPrefix.valueOf(bgpSpeakerIpv4, 32))
                .matchIPDst(peerIpv4)
                .build()
            )
            .priority(110)
            .treatment(DefaultTrafficTreatment.builder().build())
            .build();

        PointToPointIntent peerIpv4IntentIn = PointToPointIntent.builder()
            .appId(appId)
            .filteredIngressPoint(peerCP)         // ingress
            .filteredEgressPoint(bgpSpeaker)    // egress
            .selector(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .matchIPSrc(peerIpv4)
                .matchIPDst(IpPrefix.valueOf(bgpSpeakerIpv4, 32))
                .build()
            )
            .priority(110)
            .treatment(DefaultTrafficTreatment.builder().build())
            .build();

        PointToPointIntent peerIpv6IntentOut = PointToPointIntent.builder()
            .appId(appId)
            .filteredIngressPoint(bgpSpeaker)   // ingress
            .filteredEgressPoint(peerCP)          // egress
            .selector(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV6)
                .matchIPProtocol(IPv6.PROTOCOL_TCP)
                .matchIPv6Src(IpPrefix.valueOf(bgpSpeakerIpv6, 128))
                .matchIPv6Dst(peerIpv6)
                .build()
            )
            .priority(110)
            .treatment(DefaultTrafficTreatment.builder().build())
            .build();

        PointToPointIntent peerIpv6IntentIn = PointToPointIntent.builder()
            .appId(appId)
            .filteredIngressPoint(peerCP)         // ingress
            .filteredEgressPoint(bgpSpeaker)    // egress
            .selector(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV6)
                .matchIPProtocol(IPv6.PROTOCOL_TCP)
                .matchIPv6Src(peerIpv6)
                .matchIPv6Dst(IpPrefix.valueOf(bgpSpeakerIpv6, 128))
                .build()
            )
            .priority(110)
            .treatment(DefaultTrafficTreatment.builder().build())
            .build();
        intentService.submit(peerIpv4IntentOut);
        intentService.submit(peerIpv4IntentIn);
        intentService.submit(peerIpv6IntentOut);
        intentService.submit(peerIpv6IntentIn);
    }

    // private class VRouterConfigListener implements NetworkConfigListener {
    //     @Override
    //     public void event(NetworkConfigEvent event) {
    //         if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
    //         && event.configClass().equals(ProxyNdpConfig.class)) {
    //             ProxyNdpConfig config = cfgService.getConfig(appId, ProxyNdpConfig.class);
    //             if (config != null) {
    //                 MacAddress vrouterMac =  MacAddress.valueOf(config.getVrouterMac());
    //                 IpAddress vrouterIpv4 = IpAddress.valueOf(config.getVrouterIpv4());
    //                 IpAddress vrouterIpv6 = IpAddress.valueOf(config.getVrouterIpv6());

    //                 ipMacTable.put(vrouterIpv4, vrouterMac);
    //                 ipMacTable.put(vrouterIpv6, vrouterMac);
    //                 log.info("Insert vrouter to table. Ipv4 = {}, Ipv6 = {}, MAC = {}",
    //                 config.getVrouterIpv4(), config.getVrouterIpv6(), config.getVrouterMac());
    //             }
    //         }
    //     }
    // }

    private class RouteProcessor implements PacketProcessor {
        IpPrefix prefix63 = IpPrefix.valueOf("192.168.63.0/24");
        IpPrefix prefixFd63 = IpPrefix.valueOf("fd63::/64");
        // My network
        IpPrefix prefix65xx0 = IpPrefix.valueOf("172.16.12.0/24");
        IpPrefix prefix65xx1 = IpPrefix.valueOf("172.17.12.0/24");
        IpPrefix prefix65xx0v6 = IpPrefix.valueOf("2a0b:4e07:c4:12::/64");
        IpPrefix prefix65xx1v6 = IpPrefix.valueOf("2a0b:4e07:c4:112::/64");

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            if (context.isHandled()) {
                return;
            }
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            DeviceId recDevId = pkt.receivedFrom().deviceId();
            PortNumber recPort = pkt.receivedFrom().port();
            ConnectPoint recvCp = new ConnectPoint(recDevId, recPort);
            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();

            // This handle by ProxyNdp App
            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                return;
            }
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6 = (IPv6) ethPkt.getPayload();
                // Block fd63::/64 from outside
                IpAddress srcIp63 = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getSourceAddress());
                IpAddress dstIp63 = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getDestinationAddress());
                if ((prefixFd63.contains(srcIp63) || prefixFd63.contains(dstIp63)) && !recDevId.equals(ovs1)) {
                    // log.info("[Tag] Skip flood for IPv6: {} -> {} on {}", srcIp63, dstIp63, recDevId);
                    context.block();
                    return; // don't flood, don't handle this IPv6
                }
                if (ipv6.getNextHeader() == IPv6.PROTOCOL_ICMP6) {
                    ICMP6 icmp6 = (ICMP6) ipv6.getPayload();
                    byte icmpType = icmp6.getIcmpType();
                    if (icmpType == ICMP6.NEIGHBOR_SOLICITATION || icmpType == ICMP6.NEIGHBOR_ADVERTISEMENT) {
                        return;
                    }
                }
            }

            IpAddress srcIp = null;
            IpAddress dstIp = null;
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4 = (IPv4) ethPkt.getPayload();
                if (ipv4 != null) {
                    srcIp = IpAddress.valueOf(ipv4.getSourceAddress());
                    dstIp = IpAddress.valueOf(ipv4.getDestinationAddress());
                }
            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6 = (IPv6) ethPkt.getPayload();
                if (ipv6 != null) {
                    srcIp = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getSourceAddress());
                    dstIp = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getDestinationAddress());
                }
            }

            if (dstIp == null) {
                return;
            }

            // Intra to Inter
            log.info("[Routing] SrcIp: {}, DstIp: {}", srcIp, dstIp);
            if (vrouterMac.equals(dstMac)) {
                Optional<ResolvedRoute> resolvedRoute = routeService.longestPrefixLookup(dstIp);
                if (resolvedRoute.isPresent()) {
                    ResolvedRoute route = resolvedRoute.get();
                    IpAddress nextHopIp = route.nextHop();
                    log.info("[Routing] Next Hop IP: {}", nextHopIp);
                    MacAddress nextHopMac = interfaceService.getMatchingInterface(nextHopIp).mac();
                    if (nextHopMac == null) {
                        log.warn("[Routing] Next Hop Mac Loss: {}", nextHopIp);
                        context.block();
                        return;
                    }
                    log.info("[Routing] ROUTE FOUND: {} → next-hop = {} {}", dstIp, nextHopIp, nextHopMac);

                    ConnectPoint nextHopCp = interfaceService.getMatchingInterface(nextHopIp).connectPoint();
                    if (nextHopCp == null) {
                        log.warn("[Routing] Next Hop Cp Loss: {}", nextHopIp);
                        context.block();
                        return;
                    }
                    log.info("[Routing] Next Hop Cp Found: {}", nextHopCp);

                    installPath(recvCp, nextHopCp, context, nextHopMac);

                    // Emit packet
                    ethPkt.setSourceMACAddress(dstMac);
                    ethPkt.setDestinationMACAddress(nextHopMac);
                    packetService.emit(new DefaultOutboundPacket(
                        nextHopCp.deviceId(),
                        DefaultTrafficTreatment.builder().setOutput(nextHopCp.port()).build(),
                        ByteBuffer.wrap(ethPkt.serialize())
                    ));
                } else {
                    log.warn("[Routing] ROUTE NOT FOUND for {}", dstIp);
                    context.block();
                    return;
                }
            // Any to Intra
            } else if (prefix65xx0.contains(dstIp) || prefix65xx0v6.contains(dstIp)) {
                MacAddress nextHopMac = interfaceService.getMatchingInterface(dstIp).mac();
                if (nextHopMac == null) {
                    log.warn("[Routing] Next Hop Mac Loss: {}", dstIp);
                    context.block();
                    return;
                }
                log.info("[Routing] ROUTE FOUND: {} → next-hop = {} {}", dstIp, dstIp, nextHopMac);

                ConnectPoint nextHopCp = interfaceService.getMatchingInterface(dstIp).connectPoint();
                if (nextHopCp == null) {
                    log.warn("[Routing] Next Hop Cp Loss: {}", dstIp);
                    context.block();
                    return;
                }
                log.info("[Routing] Next Hop Cp Found: {}", nextHopCp);

                installPath(recvCp, nextHopCp, context, nextHopMac);

                // Emit packet
                ethPkt.setSourceMACAddress(vrouterMac);
                ethPkt.setDestinationMACAddress(nextHopMac);
                packetService.emit(new DefaultOutboundPacket(
                    nextHopCp.deviceId(),
                    DefaultTrafficTreatment.builder().setOutput(nextHopCp.port()).build(),
                    ByteBuffer.wrap(ethPkt.serialize())
                ));
            // AS65xx1 to inter
            } else if (prefix65xx1.contains(srcIp) || prefix65xx1v6.contains(srcIp)) {
                IpAddress defaultIp = IpAddress.valueOf("192.168.70.253");
                MacAddress nextHopMac = interfaceService.getMatchingInterface(defaultIp).mac();
                log.info("[Routing] ROUTE FOUND: {} → next-hop = {} {}", dstIp, dstIp, nextHopMac);

                ConnectPoint nextHopCp = interfaceService.getMatchingInterface(defaultIp).connectPoint();
                log.info("[Routing] Next Hop Cp Found: {}", nextHopCp);

                installPath(recvCp, nextHopCp, context, nextHopMac);

                // Emit packet
                ethPkt.setSourceMACAddress(vrouterMac);
                ethPkt.setDestinationMACAddress(nextHopMac);
                packetService.emit(new DefaultOutboundPacket(
                    nextHopCp.deviceId(),
                    DefaultTrafficTreatment.builder().setOutput(nextHopCp.port()).build(),
                    ByteBuffer.wrap(ethPkt.serialize())
                ));
            // Transit Traffic
            } else {
                Optional<ResolvedRoute> resolvedRoute = routeService.longestPrefixLookup(dstIp);
                if (resolvedRoute.isPresent()) {
                    ResolvedRoute route = resolvedRoute.get();
                    IpAddress nextHopIp = route.nextHop();
                    log.info("[Routing] Next Hop IP: {}", nextHopIp);
                    MacAddress nextHopMac = interfaceService.getMatchingInterface(nextHopIp).mac();
                    if (nextHopMac == null) {
                        log.warn("[Routing] Next Hop Mac Loss: {}", nextHopIp);
                        context.block();
                        return;
                    }
                    log.info("[Routing] ROUTE FOUND: {} → next-hop = {} {}", dstIp, nextHopIp, nextHopMac);

                    ConnectPoint nextHopCp = interfaceService.getMatchingInterface(nextHopIp).connectPoint();
                    if (nextHopCp == null) {
                        log.warn("[Routing] Next Hop Cp Loss: {}", nextHopIp);
                        context.block();
                        return;
                    }
                    log.info("[Routing] Next Hop Cp Found: {}", nextHopCp);

                    installPath(recvCp, nextHopCp, context, nextHopMac); // dstMac = vrouterMac

                    // Emit packet
                    ethPkt.setSourceMACAddress(vrouterMac);
                    ethPkt.setDestinationMACAddress(nextHopMac);
                    packetService.emit(new DefaultOutboundPacket(
                        nextHopCp.deviceId(),
                        DefaultTrafficTreatment.builder().setOutput(nextHopCp.port()).build(),
                        ByteBuffer.wrap(ethPkt.serialize())
                    ));
                } else {
                    log.warn("[Routing] ROUTE NOT FOUND for {}", dstIp);
                    context.block();
                    return;
                }
            }

        }
    }

    // Ordered list of switches in the topology
    private final List<DeviceId> switchOrder = Arrays.asList(ovs1, ovs2, ovs3);

    private void installPath(ConnectPoint recvCp, ConnectPoint nextHopCp,
                             PacketContext context, MacAddress nextHopMac) {
        // Parse the packet
        Ethernet ethPkt = (Ethernet) context.inPacket().parsed();

        MacAddress srcMac = ethPkt.getSourceMAC();
        MacAddress dstMac = ethPkt.getDestinationMAC();
        IpAddress srcIp = null;
        IpAddress dstIp = null;
        short ethType = ethPkt.getEtherType();
        if (ethType == Ethernet.TYPE_IPV4) {
            IPv4 ipv4 = (IPv4) ethPkt.getPayload();
            if (ipv4 != null) {
                srcIp = IpAddress.valueOf(ipv4.getSourceAddress());
                dstIp = IpAddress.valueOf(ipv4.getDestinationAddress());
            }
        } else if (ethType == Ethernet.TYPE_IPV6) {
            IPv6 ipv6 = (IPv6) ethPkt.getPayload();
            if (ipv6 != null) {
                srcIp = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getSourceAddress());
                dstIp = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getDestinationAddress());
            }
        }

        DeviceId startDevice = recvCp.deviceId();
        DeviceId endDevice = nextHopCp.deviceId();

        // Get path
        List<DeviceId> path = getPath(startDevice, endDevice);
        if (path == null || path.isEmpty()) {
            log.info("DEBUG: NO PATH");
            return;
        }

        if (path.size() == 1) {
            // Same switch
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                    .matchEthSrc(srcMac)
                    .matchEthDst(dstMac)
                    .matchEthType(ethType);
            if (ethType == Ethernet.TYPE_IPV4) {
                selector.matchIPDst(IpPrefix.valueOf(dstIp, 32));
            } else {
                selector.matchIPv6Dst(IpPrefix.valueOf(dstIp, 128));
            }


            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setEthSrc(vrouterMac)
                    .setEthDst(nextHopMac)
                    .setOutput(nextHopCp.port())
                    .build();

            FlowRule rule = DefaultFlowRule.builder()
                    .forDevice(startDevice)
                    .withSelector(selector.build())
                    .withTreatment(treatment)
                    .withPriority(50)
                    .makeTemporary(30)
                    .fromApp(appId)
                    .build();

            flowRuleService.applyFlowRules(rule);
            log.info("[Routing] Install path on {} for dstIp: {}", startDevice, dstIp);
        } else {
            // Multiple switches
            // Install on first switch
            PortNumber firstOutPort = getConnectPort(path.get(0), path.get(1));
            if (firstOutPort == null) {
                return;
            }

            TrafficSelector.Builder firstSelector = DefaultTrafficSelector.builder()
                    .matchEthSrc(srcMac)
                    .matchEthDst(dstMac)
                    .matchEthType(ethType);
            if (ethType == Ethernet.TYPE_IPV4) {
                firstSelector.matchIPDst(IpPrefix.valueOf(dstIp, 32));
            } else {
                firstSelector.matchIPv6Dst(IpPrefix.valueOf(dstIp, 128));
            }

            TrafficTreatment firstTreatment = DefaultTrafficTreatment.builder()
                    .setEthSrc(vrouterMac)
                    .setEthDst(nextHopMac)
                    .setOutput(firstOutPort)
                    .build();

            FlowRule firstRule = DefaultFlowRule.builder()
                    .forDevice(path.get(0))
                    .withSelector(firstSelector.build())
                    .withTreatment(firstTreatment)
                    .withPriority(50)
                    .makeTemporary(30)
                    .fromApp(appId)
                    .build();

            flowRuleService.applyFlowRules(firstRule);
            log.info("[Routing] Install path on {} for dstIp: {}", path.get(0), dstIp);

            // Install on intermediate switches
            for (int i = 1; i < path.size() - 1; i++) {
                DeviceId curr = path.get(i);
                PortNumber outPort = getConnectPort(curr, path.get(i + 1));
                if (outPort == null) {
                    return;
                }

                TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                        .matchEthSrc(vrouterMac)
                        .matchEthDst(nextHopMac)
                        .matchEthType(ethType);
                if (ethType == Ethernet.TYPE_IPV4) {
                    selector.matchIPDst(IpPrefix.valueOf(dstIp, 32));
                } else {
                    selector.matchIPv6Dst(IpPrefix.valueOf(dstIp, 128));
                }

                TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                        .setOutput(outPort)
                        .build();

                FlowRule rule = DefaultFlowRule.builder()
                        .forDevice(curr)
                        .withSelector(selector.build())
                        .withTreatment(treatment)
                        .withPriority(50)
                        .makeTemporary(30)
                        .fromApp(appId)
                        .build();

                flowRuleService.applyFlowRules(rule);
                log.info("[Routing] Install path on {} for dstIp: {}", curr, dstIp);
            }
            DeviceId curr = path.get(path.size() - 1);

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                    .matchEthSrc(vrouterMac)
                    .matchEthDst(nextHopMac)
                    .matchEthType(ethType);
            if (ethType == Ethernet.TYPE_IPV4) {
                selector.matchIPDst(IpPrefix.valueOf(dstIp, 32));
            } else {
                selector.matchIPv6Dst(IpPrefix.valueOf(dstIp, 128));
            }

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(nextHopCp.port())
                    .build();

            FlowRule rule = DefaultFlowRule.builder()
                    .forDevice(curr)
                    .withSelector(selector.build())
                    .withTreatment(treatment)
                    .withPriority(50)
                    .makeTemporary(30)
                    .fromApp(appId)
                    .build();

            flowRuleService.applyFlowRules(rule);
            log.info("[Routing] Install path on {} for dstIp: {}", curr, dstIp);
        }
    }

    private List<DeviceId> getPath(DeviceId start, DeviceId end) {
        int startIdx = switchOrder.indexOf(start);
        int endIdx = switchOrder.indexOf(end);
        if (startIdx == -1 || endIdx == -1) {
            return null;
        }
        if (startIdx <= endIdx) {
            return new ArrayList<>(switchOrder.subList(startIdx, endIdx + 1));
        } else {
            // Reverse path
            List<DeviceId> path = new ArrayList<>(switchOrder.subList(endIdx, startIdx + 1));
            java.util.Collections.reverse(path);
            return path;
        }
    }

    private PortNumber getConnectPort(DeviceId from, DeviceId to) {
        if (from.equals(ovs1) && to.equals(ovs2)) {
            return PortNumber.portNumber(2);
        } else if (from.equals(ovs2) && to.equals(ovs1)) {
            return PortNumber.portNumber(2);
        } else if (from.equals(ovs2) && to.equals(ovs3)) {
            return PortNumber.portNumber(3);
        } else if (from.equals(ovs3) && to.equals(ovs2)) {
            return PortNumber.portNumber(1);
        }
        return null;
    }
}
