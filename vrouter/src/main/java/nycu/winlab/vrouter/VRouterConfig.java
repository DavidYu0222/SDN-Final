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
// package nycu.winlab.vrouter;

// import org.onosproject.core.ApplicationId;
// import org.onosproject.net.config.Config;
// import com.fasterxml.jackson.databind.JsonNode;

// public class ProxyNdpConfig extends Config<ApplicationId> {

//   public static final String VIRTUAL_ROUTER = "virtual-router";
//     private static final String IPV4 = "ipv4";
//     private static final String IPV6 = "ipv6";
//     private static final String MAC = "mac";

//     @Override
//     public boolean isValid() {
//         if (!object.has(VIRTUAL_ROUTER)) {
//             return false;
//         }

//         JsonNode vr = object.get(VIRTUAL_ROUTER);
//         return vr.hasNonNull(IPV4) &&
//                vr.hasNonNull(IPV6) &&
//                vr.hasNonNull(MAC);
//     }

//     public String getVrouterIpv4() {
//         JsonNode vr = object.get(VIRTUAL_ROUTER);
//         return vr != null && vr.has(IPV4) ? vr.get(IPV4).asText() : null;
//     }

//     public String getVrouterIpv6() {
//         JsonNode vr = object.get(VIRTUAL_ROUTER);
//         return vr != null && vr.has(IPV6) ? vr.get(IPV6).asText() : null;
//     }

//     public String getVrouterMac() {
//         JsonNode vr = object.get(VIRTUAL_ROUTER);
//         return vr != null && vr.has(MAC) ? vr.get(MAC).asText() : null;
//     }
// }