/* Extra mechanism walkthroughs for lecture topics formerly present only in notes. */
add('m02','encapsulation','OSI / TCP-IP: wrap and unwrap a request',['Application','Protocol stack','Receiving app','Network link'],
 'Data → segment → packet → frame → bits.','Different layers answer different delivery questions.',
 [S('Application data','An HTTPS application produces data; TLS protects its content. OSI layers 5–7 map to TCP/IP Application.',0,1,'Application data'),S('Transport and network','TCP adds application ports; IP adds source and destination addresses. TCP is protocol 6, not port 6.',1,3,'IP [ TCP [ data ] ]'),S('Link and physical','Ethernet adds local MAC addresses and an FCS; bits cross the link. FCS detects errors, not cryptographic forgery.',1,3,'Ethernet [ IP [ TCP [ data ] ] ]')],
 'Decode the wrapper at the matching layer',
 [S('Read the frame','At the receiver, Ethernet checks the frame and exposes its IP packet.',3,1,'IP packet'),S('Read the packet and segment','IP passes the payload to TCP. TCP uses the destination port to deliver bytes to the correct application.',1,2,'TCP segment'),S('Use the application data','The application receives data after transport and any TLS processing. OSI is a reasoning model, not seven literal Internet headers.',1,2,'Application data')],
 'A router replaces the local-link wrapper at each hop. NAT is a separate function that may change IP addresses/ports.',
 Q('Which wrapper identifies applications using port numbers?',['Ethernet','TCP or UDP','IPv4 TTL'],1,'TCP and UDP carry transport-layer port numbers.'),'Correct delivery');

add('m02','domains','VLANs, broadcast domains and collision domains',['VLAN 10 PC','Access switch','VLAN 10 printer','VLAN 20 PC'],
 'Same VLAN = same broadcast boundary.','Without VLAN separation, broadcasts reach devices that may not need them.',
 [S('Send a broadcast','The PC broadcasts an ARP request in VLAN 10.',0,1,'Destination ff:ff:ff:ff:ff:ff'),S('Flood within the VLAN','The switch copies it to eligible VLAN 10 ports, excluding ingress.',1,2,'VLAN 10 broadcast'),S('Keep VLAN 20 separate','Ordinary Layer 2 flooding does not deliver this VLAN 10 broadcast to VLAN 20.',1,3,'No cross-VLAN copy')],
 'Separate broadcast domains and apply routed policy',
 [S('Assign access VLANs','User and printer ports are explicitly assigned to their intended VLAN.',0,1,'Access membership'),S('Understand collision scope','Each switch port is a separate collision domain in the teaching model; full-duplex Ethernet avoids normal collisions.',1,2,'Point-to-point full duplex'),S('Route deliberately','A router can connect VLANs, with ACL/firewall policy controlling access. VLAN tagging does not encrypt the data.',1,3,'Permitted routed traffic')],
 'VLAN separation alone does not stop incorrectly allowed inter-VLAN routing or trunk abuse.',
 Q('What does adding a VLAN create?',['Another broadcast domain','Automatic encryption','A larger collision domain'],0,'VLANs separate Layer 2 broadcast domains.'),'Segmentation');

add('m02','ports-transport','TCP, UDP, ports and protocol numbers',['Client app','Transport layer','Server app','Lost packet'],
 'IP = host; port = application.','A correct host address is not enough to identify a service.',
 [S('Identify the service','HTTPS commonly uses TCP port 443; SSH TCP 22; DNS TCP/UDP 53. A source ephemeral port distinguishes the client endpoint.',0,1,'Source 51514 → destination 443'),S('Compare transport','TCP establishes a connection and provides ordered delivery with retransmission. UDP itself does not provide these guarantees.',1,2,'TCP segment / UDP datagram'),S('Observe loss','TCP can retransmit missing data, but persistent network failure can still make the application fail. UDP applications decide how to handle loss.',3,1,'Lost data')],
 'Choose the transport and inspect the correct field',
 [S('Name the protocol','The IP protocol field is 6 for TCP, 17 for UDP and 1 for ICMP. These are not application port numbers.',0,1,'IP protocol'),S('Name the socket','An endpoint combines an IP address and transport port. The protocol and both endpoints distinguish a flow.',1,2,'Socket / flow'),S('Apply appropriate policy','A DNS policy may need both UDP and TCP. An ICMP packet does not have TCP/UDP service ports.',1,2,'Service-aware policy')],
 'UDP is not automatically insecure, and TCP does not automatically encrypt or guarantee eventual success.',
 Q('TCP protocol number 6 and HTTPS port 443 are…',['Two names for the same field','Different header fields','Ethernet VLAN identifiers'],1,'Protocol 6 selects TCP inside IP; port 443 selects an application endpoint inside TCP.'),'Correct service selection');

add('m02','ipv6','IPv4 versus IPv6 without the security myths',['IPv4 host','Router','IPv6 host','Observer'],
 '128 bits does not mean automatically encrypted.','Changing the address family does not establish confidentiality.',
 [S('Compare addresses','IPv4 addresses contain 32 bits; IPv6 addresses contain 128 bits. Documentation examples include 192.0.2.20 and 2001:db8::20.',0,1,'IP address'),S('Compare local discovery','IPv4 commonly uses ARP for local neighbor resolution. IPv6 uses Neighbor Discovery with ICMPv6.',1,2,'ARP / Neighbor Discovery'),S('Check confidentiality','Plaintext application data can still be read where observed. IPv6 support for IPsec does not mean IPsec is automatically active.',3,2,'Unencrypted application data')],
 'Protect traffic explicitly and filter each address family',
 [S('Deploy explicit protection','Use authenticated TLS or properly configured IPsec where required.',0,1,'Protected traffic'),S('Apply both policies','A dual-stack network needs IPv4 and IPv6 security policy; an IPv4-only rule does not automatically cover IPv6.',1,2,'Dual-stack rules'),S('Preserve essential control traffic','IPv6 relies on ICMPv6 for functions such as neighbor discovery. Do not treat all control messages as unwanted.',1,2,'Required ICMPv6')],
 'Neighbor Discovery and dual-stack filtering are explanatory extensions of the Week 1 address comparison, not an extra supplied IPv6-security lecture.',
 Q('Does IPv6 encrypt every packet automatically?',['Yes, because its addresses are longer','No, protection must be configured','Only on Wi-Fi'],1,'Address size is independent of whether traffic is encrypted.'),'Confidentiality / correct configuration');

add('m04','port-modes','Port security: protect, restrict or shutdown',['Phone + PC','Access switch','Office network','Third MAC'],
 'Drop the new identity, or disable the whole port?','A phone and PC already use the allowed two MAC identities on one access port.',
 [S('Reach the expected limit','The switch learns the phone and PC. A third distinct source exceeds the configured maximum of two.',0,1,'Two secure MACs'),S('Observe a violation','An extra identity sends a frame. The configured violation mode determines the response.',3,1,'Third source MAC'),S('Consider availability','Disabling the port affects the legitimate phone and PC as well as the violating device.',1,2,'Availability trade-off')],
 'Select the action for the port’s operational requirements',
 [S('Protect','Drop traffic from the violating source; keep the port up. Protect mode does not provide the same violation reporting as restrict.',3,1,'Violating frame dropped'),S('Restrict','Drop violating traffic, count/report the violation and keep the port operational.',3,1,'Drop + report'),S('Shutdown','Place the port in err-disabled state. Remove the cause and follow the recovery procedure before restoring service.',1,2,'Port disabled')],
 'MAC limits do not prove identity; a copied permitted MAC still needs stronger admission controls such as 802.1X.',
 Q('Which mode drops violations, reports them and keeps the port up?',['Restrict','Shutdown','No port security'],0,'Restrict rejects violating sources while preserving the port for allowed devices.'),'Availability / admission control');

add('m04','vlan-protocols','802.1Q, DTP and VTP: three different jobs',['User port','Switch A','Switch B','VLAN configuration'],
 'Tag frames. Negotiate trunks. Distribute VLAN configuration.','Confusing the three protocols leads to the wrong control.',
 [S('Tag traffic with 802.1Q','A trunk carries multiple VLANs. Tags identify the VLAN of each tagged frame.',1,2,'802.1Q VLAN tag'),S('Negotiate with DTP','DTP can negotiate whether a link becomes a trunk. That is dangerous on an untrusted user port.',0,1,'DTP negotiation'),S('Distribute with VTP','VTP distributes VLAN configuration between participating switches. It is not the tag on each user frame.',3,2,'VLAN database information')],
 'Make each boundary intentional',
 [S('Fix the user port role','Set access mode and disable DTP on user ports.',0,1,'Fixed access port'),S('Constrain the real trunk','Carry only the intended VLANs on an explicitly configured inter-switch trunk.',1,2,'Allowed VLAN list'),S('Control configuration changes','Treat VLAN database changes as administrative configuration; check participating switches before introducing them.',3,2,'Reviewed VLAN configuration')],
 'The supplied deck introduces VTP’s purpose, not a detailed VTP attack lab. DTP hardening alone does not address native-VLAN double tagging.',
 Q('Which protocol distributes VLAN configuration?',['VTP','DTP','802.1Q'],0,'VTP distributes VLAN configuration; DTP negotiates trunks; 802.1Q tags frames.'),'Correct configuration');

add('m06','stp-states','Watch STP states and RSTP recovery',['Newly linked switch','STP state machine','Forwarding network','Alternate path'],
 'Listening: listen. Learning: learn. Forwarding: forward.','A redundant link must not start forwarding before the topology is safe.',
 [S('Blocking, then listening','Classic STP processes BPDUs. Neither state learns user MACs or forwards ordinary user traffic.',0,1,'BPDU processing'),S('Learning','The port learns source MACs but still does not forward ordinary user frames.',1,2,'Learning without forwarding'),S('Forwarding','The port learns and forwards when permitted by the spanning tree.',1,2,'User traffic')],
 'Use the right convergence and edge features',
 [S('RSTP states','RSTP uses discarding, learning and forwarding states. Discarding combines classic non-learning/non-forwarding states.',0,1,'Discarding → learning → forwarding'),S('Use the alternate path','An alternate port provides another path to the root. Rapid convergence depends on link and protocol conditions, not a fixed universal timer.',3,1,'Alternate path'),S('Use edge ports carefully','PortFast is for end-host edges. Pair it with BPDU Guard; it does not authenticate attached devices.',1,2,'Edge forwarding + BPDU Guard')],
 'Role (root/designated/alternate) and state (discarding/learning/forwarding) describe different things.',
 Q('Does a port in Learning forward ordinary data frames?',['Yes','No; it only learns MACs','Only encrypted frames'],1,'Learning builds the MAC table while user-data forwarding remains disabled.'),'Loop-free availability');

add('m10','acl-direction','Inbound and outbound are interface-relative',['Staff LAN','Router','Server network','Return traffic'],
 'Draw the packet arrow first; then say in or out.','An ACL only affects packets crossing its attached interface in its configured direction.',
 [S('Enter from staff','A staff request enters router Gi0/1: it is inbound on Gi0/1.',0,1,'Gi0/1 in'),S('Leave toward server','The same request exits Gi0/2: it is outbound on Gi0/2.',1,2,'Gi0/2 out'),S('Return in the other direction','A response enters Gi0/2 and exits Gi0/1. The interface directions are reversed for that response.',3,1,'Gi0/2 in → Gi0/1 out')],
 'Choose the placement using what the ACL can match',
 [S('Extended ACL near source','Match source, destination, protocol and port precisely; reject unwanted traffic before it traverses the network.',0,1,'Precise ingress rule'),S('Standard ACL near destination','Because it matches only source address, putting it too early may block access to other destinations unintentionally.',1,2,'Source-only rule at destination boundary'),S('Keep the rest of the policy explicit','First match wins; an unmatched packet reaches implicit deny. A required final permit must actually appear.',1,2,'Ordered ACL evaluation')],
 '“Near source” and “near destination” are placement guidelines, not substitutes for drawing the real path and checking return traffic.',
 Q('A staff request enters Gi0/1 and exits Gi0/2. Which attachment sees it?',['Gi0/1 out','Gi0/1 in','Neither'],1,'Inbound on Gi0/1 processes traffic entering the router from staff.'),'Correct filtering');

const EXTRA_REFS={encapsulation:['src02',6,8],domains:['src02',10,11],'ports-transport':['src02',41,46],ipv6:['src02',24,25],'port-modes':['src05',18,40],'vlan-protocols':['src05',7,8],'stp-states':['src10',11,14],'acl-direction':['src18',15,24]};
for(const s of SCENARIOS){const r=EXTRA_REFS[s.id];if(r)s.refs=[{sourceId:r[0],from:r[1],to:r[2]}];}
