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

import java.util.HashMap;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;

import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;

// import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;

import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IPv6;
// import org.onlab.packet.ICMP6;
// import org.onlab.packet.TpPort;
import org.onlab.packet.IPv4;

import org.onosproject.net.PortNumber;
import org.onosproject.net.DeviceId;

import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.FlowRule;

import org.onosproject.net.ConnectPoint;
import org.onosproject.net.FilteredConnectPoint;

import org.onosproject.net.intent.IntentService;
// import org.onosproject.net.intent.PointToPointIntent;
import org.onosproject.net.intent.MultiPointToSinglePointIntent;
import org.onosproject.net.intent.SinglePointToMultiPointIntent;

import org.onosproject.net.intf.InterfaceService;

// import org.onosproject.net.flowobjective.FlowObjectiveService;
// import org.onosproject.net.flowobjective.DefaultForwardingObjective;
// import org.onosproject.net.flowobjective.ForwardingObjective;
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

    // @Reference(cardinality = ReferenceCardinality.MANDATORY)
    // protected FlowObjectiveService flowObjectiveService;

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
    private Map<DeviceId, Map<MacAddress, PortNumber>> bridgeTable = new HashMap<>();

    @Activate
    protected void activate() {

        // register your app
        appId = coreService.registerApplication("nycu.winlab.vrouter");

        // add a packet processor to packetService
        // packetService.addProcessor(processor, PacketProcessor.director(2));

        // install a flowrule for packet-in
        // TrafficSelector.Builder selBgp4 = DefaultTrafficSelector.builder();
        // selBgp4.matchEthType(Ethernet.TYPE_LLDP);
        // packetService.requestPackets(selBgp4.build(), PacketPriority.REACTIVE, appId);

        // TrafficSelector.Builder selBgp6 = DefaultTrafficSelector.builder();
        // selBgp6.matchEthType(Ethernet.TYPE_IPV6);
        // packetService.requestPackets(selBgp6.build(), PacketPriority.REACTIVE, appId);

        installBGPIntent();

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {

        // remove flowrule installed by your app
        flowRuleService.removeFlowRulesById(appId);

        // remove your packet processor
        // packetService.removeProcessor(processor);
        // processor = null;

        // remove flowrule you installed for packet-in
        // TrafficSelector.Builder selLldp = DefaultTrafficSelector.builder();
        // selLldp.matchEthType(Ethernet.TYPE_LLDP);
        // packetService.cancelPackets(selLldp.build(), PacketPriority.REACTIVE, appId);

        // TrafficSelector.Builder selBgp6 = DefaultTrafficSelector.builder();
        // selBgp6.matchEthType(Ethernet.TYPE_IPV6);
        // packetService.cancelPackets(selBgp6.build(), PacketPriority.REACTIVE, appId);

        log.info("Stopped");
    }

    private void installBGPIntent() {
        FilteredConnectPoint bgpSpeaker = new FilteredConnectPoint(
            interfaceService.getMatchingInterface(IpAddress.valueOf("192.168.70.10")).connectPoint()
        );

        log.info("BGP Speaker CP: {}",
             interfaceService.getMatchingInterface(IpAddress.valueOf("192.168.70.10")).connectPoint()
        );

        Set<FilteredConnectPoint> wanCps = new HashSet<>();
        FilteredConnectPoint wan1 = new FilteredConnectPoint(ConnectPoint.deviceConnectPoint("of:0000011155014201/4"));
        FilteredConnectPoint wan2 = new FilteredConnectPoint(ConnectPoint.deviceConnectPoint("of:0000226f63cd0340/3"));
        wanCps.add(wan1);
        wanCps.add(wan2);

        // 1) wan to speaker (ipv4)
        TrafficSelector bgpIpv4Selector = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4)
            .matchIPProtocol(IPv4.PROTOCOL_TCP)
            .build();

        TrafficSelector bgpIpv6Selector = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV6)
            .matchIPProtocol(IPv6.PROTOCOL_TCP)
            .build();

        MultiPointToSinglePointIntent wan2SpeakerIpv4Intent = MultiPointToSinglePointIntent.builder()
            .appId(appId)
            .filteredIngressPoints(wanCps)
            .filteredEgressPoint(bgpSpeaker)
            .selector(bgpIpv4Selector)
            .treatment(DefaultTrafficTreatment.builder().build())
            .build();

        MultiPointToSinglePointIntent wan2SpeakerIpv6Intent = MultiPointToSinglePointIntent.builder()
            .appId(appId)
            .filteredIngressPoints(wanCps)
            .filteredEgressPoint(bgpSpeaker)
            .selector(bgpIpv6Selector)
            .treatment(DefaultTrafficTreatment.builder().build())
            .build();

        intentService.submit(wan2SpeakerIpv4Intent);
        intentService.submit(wan2SpeakerIpv6Intent);

        SinglePointToMultiPointIntent speaker2WanIpv4Intent = SinglePointToMultiPointIntent.builder()
            .appId(appId)
            .filteredIngressPoint(bgpSpeaker)
            .filteredEgressPoints(wanCps)
            .selector(bgpIpv4Selector)
            .treatment(DefaultTrafficTreatment.builder().build())
            .build();

        SinglePointToMultiPointIntent speaker2WanIpv6Intent = SinglePointToMultiPointIntent.builder()
            .appId(appId)
            .filteredIngressPoint(bgpSpeaker)
            .filteredEgressPoints(wanCps)
            .selector(bgpIpv6Selector)
            .treatment(DefaultTrafficTreatment.builder().build())
            .build();

        intentService.submit(speaker2WanIpv4Intent);
        intentService.submit(speaker2WanIpv6Intent);

        // PointToPointIntent wan1Ipv4Intent = PointToPointIntent.builder()
        //     .appId(appId)
        //     .filteredIngressPoint(bgpSpeaker)   // ingress
        //     .filteredEgressPoint(wan1)          // egress
        //     .selector(bgpIpv4SelectorSrc)
        //     .treatment(DefaultTrafficTreatment.builder().build())
        //     .build();

        // PointToPointIntent wan2Ipv4Intent = PointToPointIntent.builder()
        //     .appId(appId)
        //     .filteredIngressPoint(bgpSpeaker)   // ingress
        //     .filteredEgressPoint(wan2)          // egress
        //     .selector(bgpIpv4SelectorSrc)
        //     .treatment(DefaultTrafficTreatment.builder().build())
        //     .build();

        // PointToPointIntent wan1Ipv6Intent = PointToPointIntent.builder()
        //     .appId(appId)
        //     .filteredIngressPoint(bgpSpeaker)   // ingress
        //     .filteredEgressPoint(wan1)          // egress
        //     .selector(bgpIpv6SelectorSrc)
        //     .treatment(DefaultTrafficTreatment.builder().build())
        //     .build();

        // PointToPointIntent wan2Ipv6Intent = PointToPointIntent.builder()
        //     .appId(appId)
        //     .filteredIngressPoint(bgpSpeaker)   // ingress
        //     .filteredEgressPoint(wan2)          // egress
        //     .selector(bgpIpv6SelectorSrc)
        //     .treatment(DefaultTrafficTreatment.builder().build())
        //     .build();

        // intentService.submit(wan1Ipv4Intent);
        // intentService.submit(wan2Ipv4Intent);
        // intentService.submit(wan1Ipv6Intent);
        // intentService.submit(wan2Ipv6Intent);
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

            if (ethPkt.getEtherType() != Ethernet.TYPE_LLDP) {
                return;
            }

            DeviceId recDevId = pkt.receivedFrom().deviceId();
            PortNumber recPort = pkt.receivedFrom().port();
            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();

            // rec packet-in from new device, create new table for it
            if (bridgeTable.get(recDevId) == null) {
                bridgeTable.put(recDevId, new HashMap<>());
            }

            if (bridgeTable.get(recDevId).get(srcMac) == null) {
                // the mapping of pkt's src mac and receivedfrom port wasn't store in the table of the rec device
                bridgeTable.get(recDevId).put(srcMac, recPort);
                log.info("Add an entry to the port table of `{}`. MAC address: `{}` => Port: `{}`.",
                        recDevId, srcMac, recPort);
            }

            // if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
            //     IPv6 ipv6 = (IPv6) ethPkt.getPayload();
            //     if (ipv6.getNextHeader() == IPv6.PROTOCOL_ICMP6) {
            //         ICMP6 icmp6 = (ICMP6) ipv6.getPayload();
            //         byte icmpType = icmp6.getIcmpType();
            //         if (icmpType == ICMP6.ROUTER_SOLICITATION) {
            //             return;
            //         }
            //     }
            // }

            if (bridgeTable.get(recDevId).get(dstMac) == null) {
                // the mapping of dst mac and forwarding port wasn't store in the table of the rec device
                flood(context);
                log.info("MAC address `{}` is missed on `{}`. Flood the packet.", dstMac, recDevId);
            } else if (bridgeTable.get(recDevId).get(dstMac) != null) {
                // there is a entry store the mapping of dst mac and forwarding port
                PortNumber dstPort = bridgeTable.get(recDevId).get(dstMac);
                installRule(context, dstPort);
                log.info("MAC address `{}` is matched on `{}`. Install a flow rule.", dstMac, recDevId);
            }

        }
    }

    private void flood(PacketContext context) {
        packetOut(context, PortNumber.FLOOD);
    }

    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private void installRule(PacketContext context, PortNumber dstPortNumber) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        DeviceId recDevId = pkt.receivedFrom().deviceId();
        MacAddress srcMac = ethPkt.getSourceMAC();
        MacAddress dstMac = ethPkt.getDestinationMAC();

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthSrc(srcMac)
                .matchEthDst(dstMac)
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(dstPortNumber)
                .build();

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(recDevId)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(30)
                .makeTemporary(30) // 30 seconds timeout
                .fromApp(appId)
                .build();

        flowRuleService.applyFlowRules(flowRule);

        // ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
        //         .withSelector(selector)
        //         .withTreatment(treatment)
        //         .withPriority(30)
        //         .withFlag(ForwardingObjective.Flag.VERSATILE)
        //         .makeTemporary(30)
        //         .fromApp(appId)
        //         .add();

        // flowObjectiveService.forward(recDevId, forwardingObjective);

        packetOut(context, dstPortNumber);
    }
}
