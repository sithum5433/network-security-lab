/* Guided conceptual simulations, grounded in the supplied IE3122 material. */
const TOPICS = [
 ['m02','Networking foundations','01','Week 1','Packet ekata letter ekak wage layers ekathu wenawa.','subnet'],
 ['m03','Security & threat thinking','02','Week 2','Watina de → durwalakama → attack → balapema → control.','risk'],
 ['m04','Layer 2 attacks','03','Week 3','MAC eka identity card ekak newei. Switch ekata kiyapu de verify karanna.','cam'],
 ['m06','STP & switching loops','04','Week 4','Lowest ID = root. Lowest total cost = root port.','stp'],
 ['m05','Layer 3 attacks','05','Week 4','IP address eka claim ekak; ICMP eka message ekak. Dekama verify/limit karanna.','amplification'],
 ['m07','Routing attacks','06','Week 5','Trusted neighbour kenek kiwwath route eka hari kiyala guarantee ne.','routing'],
 ['m08','TCP & UDP attacks','07','Week 6','SYN = seat reserve. ACK enakan seat eka hold wenawa.','syn'],
 ['m09','Firewalls, IDS & IPS','08','Week 7','Gatekeeper, CCTV, security guard — roles thunak.','firewall'],
 ['m10','ACLs, zones & DMZ','09','Week 7','Top to bottom. First match. No match = deny.','acl'],
 ['m11','VPN foundations','10','Week 9','Tunnel = envelope. Secure VPN = locked, verified envelope.','vpn'],
 ['m12','IPsec & TLS VPN','11','Week 9','AH verifies. ESP can encrypt. IKE agrees protection.','ipsec'],
 ['m13','AAA foundations','12','Week 10','Who are you? What can you do? What did you do?','aaa'],
 ['m14','AAA deployment','13','Week 10','Server unavailable nam fallback. Wrong password nam reject.','fallback'],
 ['m15','Cryptography','14','Week 12','Public method + secret key. Fast data encryption + trusted key exchange.','caesar'],
 ['m16','Integrity, signatures & PKI','15','Week 12','Hash = fingerprint. HMAC = shared stamp. Signature = personal proof.','hash']
].map(([id,title,number,week,hook,calculator])=>({id,title,number,week,hook,calculator}));

const SCENARIOS=[];
// Every tuple is a visible packet/state transition, not a live network action.
function add(topic,id,title,labels,hook,weak,attack,defence,protectedSteps,limit,quiz,impact='C / I / A'){
 SCENARIOS.push({topic,id,title,labels,hook,weak,attack,defence,protected:protectedSteps,limit,quiz,impact});
}
const S=(title,text,from=0,to=1,packet='Packet',state='')=>({title,text,from,to,packet,state});
const Q=(prompt,options,answer,explanation)=>({prompt,options,answer,explanation});

add('m02','packet','Follow a packet to a remote network',['Your PC','Gateway','Remote server','Wrong next hop'],
 'IP eka final address; MAC eka next bus stop.','A host must distinguish local delivery from routing.',
 [S('Compare the destination','The destination is outside the local subnet. The PC must use its default gateway.',0,1,'Subnet check','Destination: remote'),S('Resolve the next hop','ARP resolves the gateway IP to its MAC. Do not ARP for a remote Internet host.',0,1,'ARP request','ARP entry: gateway IP → gateway MAC'),S('Forward to the server','The Ethernet destination changes at each routed hop; the remote destination IP remains the same, absent translation.',1,2,'IP packet','L2 changes; L3 destination remains')],
 'Choose the correct next hop',
 [S('Local or remote?','Use IP AND mask to compare network addresses.',0,1,'Subnet check'),S('Use the gateway MAC','Send a frame to the gateway while retaining the remote destination IP.',0,1,'Frame'),S('Deliver and decapsulate','The receiver removes Ethernet, IP and transport wrappers.',1,2,'Application data')],
 'ARP is a local IPv4 resolution mechanism. NAT can change IP addresses at a translating boundary.',
 Q('For a remote server, whose MAC goes in the first Ethernet frame?',['Remote server MAC','Default gateway MAC','DNS server MAC'],1,'The frame reaches the local gateway; the IP packet still names the remote server.'),'Correct delivery');

add('m02','dora','DHCP: DORA in four steps',['New laptop','DHCP server','Configured laptop','Rogue server'],
 'Discover → Offer → Request → ACK. D-O-R-A.','A new client needs an address, mask, gateway and DNS settings.',
 [S('Discover','Client broadcasts to discover available DHCP servers.',0,1,'Discover'),S('Offer','Server offers a lease and network settings.',1,0,'Offer'),S('Request','Client requests the chosen offer.',0,1,'Request'),S('Acknowledge','Server confirms the lease; the client can use the configuration.',1,2,'ACK','Lease: IP + mask + gateway + DNS')],
 'DHCP snooping trust boundary',
 [S('Client asks normally','Client requests are permitted on an untrusted user port, subject to limits.',0,1,'Discover'),S('Rogue reply arrives','An Offer from a user-facing untrusted port is rejected.',3,1,'Blocked Offer','Untrusted server reply: DROP'),S('Real server replies','A legitimate Offer/ACK arrives from the trusted server path.',1,2,'Valid lease','Trusted server reply: ALLOW')],
 'Snooping trust must follow the legitimate server path. Rate limits, not trust flags alone, address request floods.',
 Q('What does the final A stand for?',['Authentication','Acknowledgement','Address translation'],1,'ACK confirms the chosen lease.'),'Availability / integrity');

add('m02','switch','Switch learning and ARP',['Host A','Switch','Host B','Other VLAN'],
 'Learn SOURCE; look up DESTINATION.','A switch learns addresses from source fields; ARP learns local IP-to-MAC mappings.',
 [S('Learn the sender','The switch learns Host A source MAC on the ingress port.',0,1,'Ethernet frame','CAM: A → port 1'),S('Unknown destination','If B is unknown, flood eligible ports in this VLAN, excluding ingress.',1,2,'Unknown unicast','Flood boundary: this VLAN'),S('Learn the reply','B replies; the switch learns B and future A→B frames use that port.',2,1,'Reply','CAM: A → p1; B → p2')],
 'VLAN boundaries and verified identities',
 [S('Keep broadcasts local','VLAN boundaries prevent ordinary L2 flooding into other VLANs.',0,1,'Broadcast','Same VLAN only'),S('Route between VLANs','Cross-VLAN access requires a router and its policy.',1,2,'Permitted route'),S('Authenticate devices','802.1X strengthens admission beyond a spoofable MAC address.',3,1,'Credential check','Address ≠ identity')],
 'A VLAN is neither encryption nor complete access control without correct trunks and routing policy.',
 Q('Which address is learned from a received frame?',['Source MAC','Destination MAC','Remote IP'],0,'The switch associates the frame source MAC with its incoming port.'),'Correct delivery');

add('m03','threat-model','Threat model: protect student records',['Records server','Access boundary','Student records','Threat actor'],
 'Asset → threat → weakness → risk → controls.','An exposed, unpatched server stores valuable records.',
 [S('Identify the asset','Student records require confidentiality, integrity and availability.',0,2,'Asset','Value: sensitive records'),S('Find the weakness','A known unpatched service is exposed to an attacker.',3,1,'Exploit attempt','Vulnerability: unpatched service'),S('Connect the impact','Successful exploitation can steal records, modify them or interrupt service.',1,2,'Unauthorised access','Impact: C + I + A')],
 'Patch + least privilege + MFA + monitoring + backup',
 [S('Reduce entry risk','Patch the weakness and restrict the exposed service.',3,1,'Blocked attempt','Likelihood reduced'),S('Limit the damage','Separate privileges and protect administrator login.',1,2,'Authorised access','Blast radius reduced'),S('Detect and recover','Monitor activity and restore from tested protected backups if needed.',0,2,'Recovery','Impact reduced')],
 'Risk ratings depend on actual exposure and business impact; this is a qualitative decision walkthrough.',
 Q('Which is the vulnerability?',['Student records','Unpatched software','Financial loss'],1,'The asset is the records; the weakness is unpatched software; loss is an impact.'));

add('m03','malware','Virus, worm, Trojan & ransomware',['User/device','Execution boundary','Other systems','Malware'],
 'Virus attaches. Worm spreads itself. Trojan pretends. Ransomware is the damage.',
 'Different propagation methods need different controls.',
 [S('Entry','A Trojan disguises itself as useful software; a virus attaches to a host file.',3,0,'Untrusted file'),S('Spread','A worm can self-propagate through vulnerable services, without users copying infected files.',0,2,'Self-spread','Propagation ≠ payload'),S('Payload','Ransomware encrypts/extorts; spyware/keyloggers collect data; bots receive remote commands; rootkits hide.',3,2,'Malicious action','Categories can overlap')],
 'Patch, segment, allowlist and keep isolated backups',
 [S('Block unsafe execution','Trusted sources, allowlisting and endpoint controls reduce initial execution.',3,1,'Blocked file'),S('Limit propagation','Patch network services and segment systems.',1,2,'Contained traffic'),S('Recover','Restore verified clean data from protected backups after containment.',0,2,'Clean recovery')],
 'Backups address recovery, not theft of data. A single malware sample can belong to multiple categories.',
 Q('Which can spread itself across a network?',['Worm','Only a virus','Only adware'],0,'Self-propagation is the distinguishing worm behaviour.'));

add('m03','social','Phishing, pretexting and baiting',['Employee','Verification desk','Account/data','Impersonator'],
 'Urgent kiyala verification skip karanna epa.','People may trust an urgent message, identity claim or attractive offer.',
 [S('Create a story','A caller pretends to be a manager needing an urgent password reset: pretexting/vishing.',3,0,'Urgent request'),S('Exploit trust','Phishing uses deceptive messages; spear phishing targets someone; whaling targets leaders; baiting offers a lure.',0,1,'Verification skipped'),S('Gain access','A reset or credential disclosure gives the attacker control.',3,2,'Stolen credentials')],
 'Independent verification + MFA + training',
 [S('Pause the request','Do not let urgency override the reset policy.',3,0,'Unverified claim'),S('Verify independently','Call an established contact number, not one supplied by the caller.',0,1,'Known contact'),S('Enforce access controls','Reject unverified resets and use appropriate MFA.',1,2,'Verified identity','No unauthorised reset')],
 'SMS and ordinary OTP can still be phished; MFA does not replace careful recovery procedures.',
 Q('An invented executive story is primarily what?',['Pretexting','ARP poisoning','Packet fragmentation'],0,'The attacker manufactures a plausible identity and situation.'));

add('m03','ddos','Reconnaissance, DoS and DDoS',['Legitimate user','Service boundary','Server','Botnet'],
 'One tap overload = DoS; many taps together = DDoS.','Bandwidth, CPU and connection state are finite.',
 [S('Reconnaissance','An attacker discovers live services before selecting an attack.',3,1,'Probes'),S('Overload','Many distributed bots send traffic at the same service.',3,2,'Distributed flood','Demand exceeds capacity'),S('Legitimate user loses access','The user competes for already exhausted resources.',0,2,'Timeout','Availability lost')],
 'Layered limits + upstream filtering + resilience',
 [S('Reduce exposed services','Close unnecessary services and limit costly operations.',3,1,'Filtered requests'),S('Filter upstream','Upstream scrubbing can reduce volume before the access link fills.',3,1,'Scrubbed flood'),S('Preserve service','Monitor, distribute load and plan recovery.',0,2,'Valid request','Availability improved')],
 'Blocking one source is insufficient for DDoS. A local firewall cannot restore an already saturated upstream link.',
 Q('Why is DDoS harder to block than one-source DoS?',['It always encrypts packets','It uses distributed sources','It needs no network'],1,'Many sources defeat a simple single-address block.'),'Availability');

add('m04','mac-spoof','MAC spoofing',['Real PC','Access switch','Protected LAN','Cloned MAC'],
 'Same number plate ≠ same driver.','A MAC address is a changeable claim, not proof of identity.',
 [S('Copy an allowed address','The attacker learns or copies a permitted device MAC.',3,0,'Copied MAC'),S('Impersonate','When the legitimate device is absent, the copied MAC passes a MAC-only rule.',3,1,'Allowed MAC','Sticky MAC matches'),S('Gain access','The switch cannot distinguish the device using only that address.',1,2,'Unauthorised device')],
 '802.1X credentials/certificates plus port security',
 [S('Claim the MAC','The attacker presents the allowed address.',3,1,'Copied MAC'),S('Demand identity proof','802.1X requires valid credentials or a certificate.',3,1,'Failed authentication','Admission denied'),S('Allow the real user','The genuine endpoint proves its identity.',0,2,'Authenticated access')],
 'Sticky learning still helps manage ports, but it does not defeat copying an allowed MAC.',
 Q('Why can sticky MAC fail here?',['MAC addresses are spoofable','It checks public-key signatures','It encrypts all frames'],0,'An attacker can copy the allowed address.'),'Confidentiality / integrity');

add('m04','cam-flood','CAM table flooding',['Legitimate PC','Switch CAM','Other same-VLAN PC','Fake MAC sources'],
 'Address book eka fake names walin pirunama unknown letters flood wenawa.','The MAC learning table has finite capacity.',
 [S('Learn many fake sources','Frames arrive with many distinct fabricated source MACs.',3,1,'Fake source MACs','CAM occupancy ↑'),S('Table capacity is reached','New destinations may no longer be learned normally.',3,1,'More identities','CAM: full'),S('Unknown traffic floods','Unknown unicast can be sent to other ports in the same VLAN, enabling exposure or disruption.',1,2,'Unknown unicast','Known unicast need not flood')],
 'Limit learned MACs with port security',
 [S('Admit expected devices','A port permits only the expected number of learned MACs.',0,1,'Expected MAC','Limit: e.g. 2'),S('Reject excess identities','Restrict mode drops violating sources and counts/logs violations.',3,1,'Dropped fake MAC','CAM preserved'),S('Retain forwarding','Legitimate learned traffic follows its correct destination port.',1,2,'Known unicast')],
 'Choose the limit for phones/PCs; flooding remains bounded by VLAN and implementation.',
 Q('Which field fills the table?',['Destination IP','Source MAC','TCP sequence'],1,'The switch learns source MAC addresses.'),'Confidentiality / availability');

add('m04','dtp','Switch spoofing via DTP',['User device','Access switch','Allowed VLANs','Fake switch'],
 'User port ekata switch role eka denna epa.','Dynamic trunk negotiation can accept an attacker pretending to be a switch.',
 [S('Negotiate a trunk','An attacker sends trunk-negotiation messages.',3,1,'DTP'),S('Port becomes trunk','The port can carry multiple allowed VLANs.',1,3,'Trunk formed','Access boundary widened'),S('Reach additional VLANs','The attacker injects tagged traffic on the unauthorised trunk.',3,2,'Tagged frames')],
 'Force access mode; disable DTP; restrict trunk VLANs',
 [S('Fix the port role','Configure a user port as access with switchport mode access.',0,1,'Access port'),S('Do not negotiate','switchport nonegotiate suppresses DTP negotiation.',3,1,'Rejected negotiation'),S('Restrict real trunks','Only intended uplinks carry explicitly allowed VLANs.',1,2,'Authorised VLANs')],
 'Disabling DTP alone does not solve double tagging.',
 Q('The appropriate user-port setting is…',['Dynamic desirable','Access + nonegotiate','Trust every trunk'],1,'A fixed access role cannot be negotiated into a trunk.'),'Confidentiality / integrity');

add('m04','double-tag','VLAN double tagging',['Native-VLAN user','First switch','Victim VLAN','Crafted double tag'],
 'Envelope dekak: outer eka galawunama inner destination eka penawa.','The attacker occupies the native VLAN and exploits untagged native forwarding.',
 [S('Add two tags','Outer tag names the native VLAN; inner tag names the victim VLAN.',3,1,'[native][victim]'),S('Strip the outer tag','The first switch forwards native traffic without its outer tag.',1,2,'[victim] remains'),S('Interpret the inner tag','The next switch treats the exposed tag as the destination VLAN.',1,2,'Injected frame','Usually one-way')],
 'Unused native VLAN; no users in it; native tagging where supported',
 [S('Remove the precondition','Keep user access ports out of the native VLAN.',0,1,'Separate user VLAN'),S('Harden trunk tagging','Use an unused native VLAN and supported native tagging.',3,1,'Unexpected tagging','Attack condition removed'),S('Enforce inter-VLAN policy','Allow cross-VLAN access only through controlled routing.',1,2,'Authorised route')],
 'Simply renaming the native VLAN is insufficient if attackers still have access to it.',
 Q('Why is the attack usually one-way?',['No matching return path is created','TCP is disabled','Every VLAN is encrypted'],0,'The tag trick injects forward traffic without creating a symmetric return trunk.'),'Integrity / confidentiality');

add('m04','dhcp-starve','DHCP starvation',['New client','DHCP server','Lease pool','Fake clients'],
 'Hotel rooms okkoma fake bookings walin reserve karanawa.','The lease pool and request-processing capacity are finite.',
 [S('Invent clients','The attacker requests leases under many client identities.',3,1,'Many requests'),S('Consume leases','Available addresses are allocated to fake clients.',1,2,'Lease reservations','Free leases → 0'),S('Deny new users','A genuine client cannot obtain an address.',0,1,'No lease','Availability lost')],
 'DHCP request rate limits and appropriate port-security limits',
 [S('Limit request rate','Drop excessive DHCP activity at user-facing access ports.',3,1,'Rate-limited'),S('Limit learned identities','Port security limits excessive MAC identities where appropriate.',3,1,'Excess MAC dropped'),S('Preserve leases','Normal client requests can still receive leases.',0,2,'Valid lease')],
 'Snooping server-trust rules alone do not guarantee starvation prevention; tune request and identity limits.',
 Q('What resource is exhausted?',['DHCP leases','Certificate roots','OSPF areas'],0,'Fake clients consume the finite pool of addresses.'),'Availability');

add('m04','dhcp-rogue','DHCP spoofing',['Client','Access switch','Legitimate DHCP','Rogue DHCP'],
 'Address eka hari wage; gateway eka attacker ge.','Clients may accept an unauthenticated server offer.',
 [S('Client discovers servers','A DHCP Discover reaches the local network.',0,1,'Discover'),S('Rogue answers','The attacker advertises a malicious gateway or DNS server.',3,0,'Forged Offer','Gateway → attacker'),S('Traffic is redirected','The victim follows the supplied configuration.',0,3,'Victim traffic','MITM or DoS')],
 'DHCP snooping: trust only legitimate server paths',
 [S('Receive rogue reply','The switch receives an Offer on an untrusted user port.',3,1,'Forged Offer'),S('Drop it','Snooping rejects server messages from this path.',3,1,'DROP','Untrusted server'),S('Accept legitimate reply','The real server reply traverses the trusted uplink.',2,0,'Valid ACK','Correct gateway/DNS')],
 'Trusting user ports defeats the control; confirm legitimate server reachability.',
 Q('Which port should be trusted?',['Every user port','Only legitimate server/uplink paths','Only the attacker port'],1,'Trust designates the authorised path for DHCP server messages.'));

add('m04','arp-poison','ARP poisoning and DAI',['Victim PC','DAI switch','Real gateway','Attacker MAC'],
 'Gateway ge nama dala attacker ge address eka denna try karanawa.','Unsolicited ARP claims can overwrite an unauthenticated cache.',
 [S('Forge the gateway mapping','Attacker claims: gateway IP is at attacker MAC.',3,0,'Forged ARP','Victim cache poisoned'),S('Poison the other side','Attacker claims the victim IP to the gateway as well.',3,2,'Forged ARP','Gateway cache poisoned'),S('Intercept both directions','Frames pass through the attacker, who can relay, alter or drop them.',0,3,'Intercepted traffic','MITM / DoS')],
 'DAI validates ARP against snooping/static bindings',
 [S('Build trusted bindings','Snooping learns valid IP–MAC–VLAN–port bindings.',0,1,'Valid binding'),S('Compare the ARP claim','DAI sees a mismatch between the claimed IP/MAC and binding.',3,1,'Mismatch','ARP validation: FAIL'),S('Drop and preserve','Forged ARP is discarded; the legitimate mapping remains.',1,2,'Valid ARP','Correct gateway MAC')],
 'Static-IP hosts need an appropriate static binding/ARP ACL. Missing bindings can block valid traffic.',
 Q('What must DAI have to validate static-IP devices?',['Appropriate static bindings or ARP ACLs','Only a larger CAM table','A new TCP port'],0,'DAI needs a trusted binding source; DHCP snooping is not enough for every static host.'));

add('m06','stp-tree','Build a loop-free spanning tree',['Switch A','Switch B','Switch C','Redundant link'],
 'Root ID aduma. Root path cost aduma. Ithuru loop path block.','Redundant Ethernet paths can circulate broadcasts indefinitely.',
 [S('Broadcast enters','A switch floods a broadcast on active links.',0,1,'Broadcast'),S('Multiple paths copy it','A redundant link returns another copy through the loop.',1,2,'Duplicate'),S('No Ethernet TTL stops it','Copies circulate, causing storms and MAC flapping.',2,0,'Circulating copies','Broadcast load ↑')],
 'STP elections and blocking',
 [S('Elect the root','Lowest Bridge ID wins: priority first, MAC tie-break.',0,1,'BPDUs','Lowest BID → root'),S('Choose root ports','Each non-root switch selects its lowest summed path cost.',1,2,'Path comparison','19 beats 19 + 4 = 23'),S('Block the redundant path','Choose designated ports per segment; other redundant paths stop forwarding user data.',2,0,'Standby link','Loop-free forwarding')],
 'RSTP improves convergence; it does not authenticate BPDUs. Use the STP calculator to change all three switch priorities/costs.',
 Q('A root port is chosen using…',['The fastest individual link only','Lowest total root path cost','Highest MAC address'],1,'Add all path costs to the root before comparing.'),'Availability');

add('m06','root-spoof','STP root manipulation',['Intended root','Distribution','Access switch','Rogue bridge'],
 'Low ID dala boss wenna try karanawa. Root Guard boundary ekak.','STP BPDUs do not inherently authenticate the bridge claim.',
 [S('Advertise a superior root','The rogue bridge sends a BPDU with a lower Bridge ID.',3,2,'Superior BPDU'),S('Re-elect paths','Switches may accept the attacker as root and alter port roles.',2,1,'New root claim','Root changed'),S('Traffic paths change','The new topology may expose traffic or disrupt service.',1,3,'Redirected path')],
 'Root Guard downstream; BPDU Guard at PC edges',
 [S('Superior claim reaches a protected boundary','Root Guard is on a downstream designated port that must never become a root port.',3,1,'Superior BPDU'),S('Block that port','The port enters root-inconsistent state.',3,1,'BLOCK','Intended root preserved'),S('Recover automatically','The condition clears after superior BPDUs stop.',0,2,'Stable topology')],
 'Root Guard is not a defence against every topology-change flood. Becoming root does not force all traffic through the attacker.',
 Q('What triggers Root Guard?',['Any lost data packet','A superior BPDU','A DHCP request'],1,'Root Guard stops an unexpected superior-root claim.'),'Confidentiality / availability');

add('m06','tc-flood','Topology-change flooding & BPDU DoS',['PC','Switch CPU/CAM','Other switches','BPDU flooder'],
 'CAM flood fills; TC flood flushes. Dekama unknown traffic wadi karanawa.','Unauthenticated control messages can trigger repeated topology work.',
 [S('Send repeated changes','Attacker injects topology-change indications or floods BPDUs.',3,1,'TC / BPDU flood'),S('Expire or flush entries','Topology-change processing removes/ages learned MAC entries.',1,2,'Topology updates','CAM knowledge ↓'),S('Flood and recalculate','Unknown traffic floods; repeated control work consumes processing.',0,1,'Unknown traffic','CPU ↑; throughput ↓')],
 'BPDU Guard on host ports; protect the control plane',
 [S('Unexpected BPDU arrives at an edge','A PC-facing port should not receive bridge control traffic.',3,1,'BPDU'),S('Err-disable the edge port','BPDU Guard stops the source at that boundary.',3,1,'Port disabled'),S('Retain legitimate topology','Proper inter-switch links continue exchanging BPDUs.',1,2,'Authorised BPDUs')],
 'An attack originating inside legitimate switch links needs additional hardening/monitoring; edge Guard alone is not a universal solution.',
 Q('TC flooding resembles CAM flooding because both can cause…',['Unknown-unicast flooding','RSA signatures','DHCP renewal'],0,'One flushes entries; the other exhausts learning capacity.'),'Availability / confidentiality');

add('m06','guards','BPDU Guard, Filter, Loop Guard & failover',['PC-facing port','Access switch','Root/uplink','Unexpected bridge'],
 'Any BPDU → Guard. Better root → Root Guard. Missing BPDU → Loop Guard.','PortFast changes startup timing; BPDU Filter can suppress loop information.',
 [S('A bridged connection reaches a host port','An unexpected switch creates a possible redundant path.',3,0,'BPDU'),S('Interface Filter hides BPDUs','The port stays up and STP cannot use the suppressed messages.',0,1,'Suppressed BPDU','No automatic err-disable'),S('A loop may remain active','A physically bridged topology can now forward in a loop.',1,2,'Loop risk')],
 'Use each guard for its port role',
 [S('Protect the edge','BPDU Guard err-disables a PC port receiving any BPDU.',3,0,'Guard: disable'),S('Protect inter-switch links','Loop Guard blocks a root/alternate port if expected BPDUs disappear.',2,1,'Missing BPDU','Loop-inconsistent'),S('Recover through a standby path','RSTP activates a valid alternate after failure; legacy UplinkFast/BackboneFast address direct/indirect recovery.',1,2,'Valid alternate')],
 'Loop Guard does not stop superior-root claims. Interface Filter is not a safe equivalent of BPDU Guard.',
 Q('Which responds to missing expected BPDUs?',['Loop Guard','Root Guard','PortFast'],0,'Loop Guard prevents unsafe forwarding when expected BPDUs disappear.'),'Availability');

const L3 = [
 ['icmp-sweep','ICMP sweep','Doorbell ekin eka ring karala gedara kawda inne balanawa.','Unauthenticated echo requests can reveal live hosts.','Send echo probes to many IPs.','Responses identify candidates for later attacks.','Restrict exposed echo requests and detect sequential probes.','Keep needed diagnostic errors; a silent host is not proof that it is absent.','Reconnaissance'],
 ['ping-death','Ping of Death','Packet size eka illegal wenna fragments join wenawa.','A vulnerable legacy stack mishandles an oversized reassembled packet.','Send fragments that produce an invalid oversized IP datagram.','Reassembly can crash the vulnerable target.','Patch and validate packet lengths/reassembly.','This is mainly a legacy implementation weakness, not every large ping.','Availability'],
 ['ping-flood','Ping flood','Valid request unath godak awama service eka hira wenawa.','Bandwidth/CPU are finite.','Send many ordinary valid echo requests.','Handling requests/replies consumes the victim resources.','Rate-limit selectively and filter large floods upstream.','Local limits cannot recover an already saturated upstream link.','Availability'],
 ['smurf','Smurf reflection','Victim ge return address dala group ekakata letter yawanna.','Spoofed-source directed broadcasts can make many systems reply.','Send echo to a directed broadcast with victim source IP.','Many hosts send replies to the victim: reflection plus amplification.','Disable directed broadcasts and validate ingress/egress source addresses.','Do not confuse a direct ping flood with amplification.','Availability'],
 ['ip-spoof','IP source spoofing','Return address eka boru.','IP itself does not prove ownership of its source address.','Forge an internal or victim source IP.','Bypass naive address trust or cause replies to reach a victim.','Ingress/egress source filtering and appropriate uRPF.','Strict uRPF may reject legitimate asymmetric routing.','Integrity / availability'],
 ['ttl-expiry','TTL expiry attack','Router ekata error reply hadanna weda wadi karanawa.','Routers spend resources generating ICMP expiry errors.','Send many packets that expire at the chosen router.','ICMP error generation consumes control-plane CPU.','Control-plane policing and ICMP generation limits.','The target is router resources, not normal application payload.','Availability'],
 ['ttl-evasion','TTL-based IDS evasion','CCTV eka dekka packet eka target ekata yanne ne.','The IDS and host can receive different packet streams.','Send selected packets with a TTL that expires after the IDS.','The IDS reconstructs a different stream from the target.','TTL-aware normalisation and appropriate sensor placement.','A simple signature alone may miss the inconsistent network view.','Detection bypass'],
 ['teardrop','Teardrop fragmentation','Puzzle pieces overlap wela old parser eka crash wenawa.','A vulnerable legacy reassembler mishandles inconsistent fragment offsets.','Send malformed or overlapping fragments.','Reassembly may fail or crash on vulnerable implementations.','Patch and validate/reassemble fragments at the security boundary.','Blocking every fragment can disrupt legitimate traffic; use appropriate validation.','Availability']
];
for(const [id,title,hook,weak,send,result,control,limit,impact] of L3){
 add('m05',id,title,['Legitimate user','Router / filter','Target','Attacker'],hook,weak,
 [S('Exploit the assumption',weak,3,1,'Probe/packet'),S('Send the attack traffic',send,3,2,title),S('Observe the consequence',result,1,2,'Consequence',impact)],control,
 [S('Place the control',control,0,1,'Configured boundary'),S('Check or limit the attack',`Apply the selected control: ${control}`,3,1,'Validated / limited'),S('Preserve legitimate service','Allow required traffic and inspect counters/logs to confirm the control.',0,2,'Legitimate traffic')],limit,
 Q(`Which control fits ${title}?`,[control,'Disable all security logging','Trust every source address'],0,`${control} ${limit}`),impact);
}

const ROUTING=[
 ['route-poison','Routing-table poisoning','Fake shortcut ekak pennala wrong road ekata yawanna.','A route update is accepted without adequate neighbour or prefix checks.','A false RIP metric or OSPF advertisement makes a bad path attractive.','Neighbour authentication plus accepted-prefix filtering','Authentication proves a key holder, not the truth of an authorised peer route.'],
 ['route-inject','Unauthorised route injection','Neighbour wenna puluwan unoth fake directions denawa.','An attacker gains a path to introduce routes, often as a rogue neighbour.','Injected routes enter the routing information and affect forwarding.','Authenticate neighbours; passive host-facing interfaces; restrict physical access','RIP has no adjacency requirement; OSPF distribute-lists normally do not stop intra-area LSA flooding.'],
 ['hijack','BGP prefix hijacking','More-specific signboard eka traffic eka gannawa.','A BGP announcement does not inherently prove prefix ownership.','An unauthorised more-specific prefix attracts traffic via longest-prefix matching.','Prefix filters and RPKI origin validation','BGP session authentication does not prove prefix ownership; RPKI checks origin, not every path hop.'],
 ['blackhole','Blackhole versus sinkhole','Blackhole drops. Sinkhole collects, samahara welawata forwards.','A malicious advertised route can redirect traffic.','A blackhole drops redirected packets; a sinkhole receives/analyses them and may forward.','Route/prefix controls plus monitoring of path and delivery changes','These are outcomes of redirection, not necessarily separate packet formats.'],
 ['route-flap','Route flapping and update floods','Map eka repeatedly change unama router weda karanawa.','Repeated route changes trigger recalculation.','SPF/DUAL work and unstable forwarding consume resources and disrupt traffic.','Authentication, control-plane limits and appropriate dampening','Dampening can delay genuine recovery; authenticated peers can still misbehave.']
];
for(const [id,title,hook,weak,effect,control,limit] of ROUTING){
 add('m07',id,title,['Sender','Routing policy','Destination network','Rogue advertiser'],hook,weak,
 [S('Advertise a claim',weak,3,1,'Route update'),S('Install/use the route',effect,1,3,'Selected route'),S('Traffic follows the choice','The sender follows the resulting forwarding table.',0,3,'Redirected packet')],control,
 [S('Authenticate the neighbour','Accept protocol exchanges only from intended peers.',3,1,'Peer check'),S('Validate route policy',control,3,1,'Prefix/policy check'),S('Forward on valid routes','Verify adjacencies, routes and permitted reachability.',0,2,'Legitimate path')],limit,
 Q('Does neighbour authentication prove every advertised route is truthful?',['Yes, always','No; route policy is also needed','Only when the route is shorter'],1,limit));
}

add('m07','rpki','RPKI: Valid, Invalid, NotFound',['Prefix owner','ROA validator','BGP router','Announcement'],
 'ROA = me prefix eka announce karanna me AS ekata permission.','An advertised origin AS and length need to match an applicable ROA.',
 [S('Receive a route','A BGP update names a prefix and origin AS.',3,2,'BGP UPDATE'),S('Trust it without origin checks','A wrong AS or too-specific route may be accepted.',2,1,'Unchecked claim'),S('Traffic is diverted','A more-specific accepted route can attract traffic.',0,3,'Wrong origin')],
 'Validate origin and maxLength; apply a rejection policy',
 [S('Look for covering ROAs','A ROA authorises a prefix, origin AS and maximum announced prefix length.',0,1,'Signed ROA'),S('Classify','Matching AS and allowed length → Valid; covered but not authorised → Invalid; no covering ROA → NotFound.',3,1,'Origin validation'),S('Apply router policy','Reject Invalid according to policy. NotFound is distinct from Invalid.',1,2,'Policy result')],
 'A route can be Valid if any covering ROA authorises it. This does not validate the full AS path.',
 Q('No covering ROA means…',['Invalid automatically','NotFound','Valid automatically'],1,'NotFound means there is no covering ROA; it is a separate state.'),'Routing integrity');

add('m08','handshake','TCP handshake and TIME_WAIT',['Client','Connection state','Server','Delayed packets'],
 'SYN → SYN-ACK → ACK. Close unath duplicate packets enna puluwan.',
 'TCP reliability requires sequence numbers, state and orderly close.',
 [S('SYN reserves half-open state','Client sends SYN seq=x. A conventional server reserves connection state.',0,2,'SYN x','Half-open backlog +1'),S('SYN-ACK','Server sends seq=y, ack=x+1.',2,0,'SYN-ACK','Await final ACK'),S('ACK establishes','Client acknowledges y+1; the connection is established.',0,2,'ACK y+1','Established'),S('Close and TIME_WAIT','FIN/ACK exchange closes directions. The active closer retains state to handle delayed duplicates.',0,1,'FIN / ACK','TIME_WAIT')],
 'Validate transport state and authenticate application data',
 [S('Validate sequences','TCP checks connection/sequence conditions.',0,1,'Sequence check'),S('Use TLS or SSH','Authenticate protected application data; TCP reliability alone is not security.',0,2,'Protected data'),S('Retain close state correctly','TIME_WAIT helps avoid old duplicates being confused with new connections.',3,1,'Old duplicate','Handled by TCP state')],
 'TLS does not authenticate the TCP header or RST flag.',
 Q('When is normal half-open state initially allocated?',['After the final ACK only','After receiving SYN, before proof of reachability','After FIN'],1,'This early allocation is the resource targeted by SYN floods.'),'Reliable delivery');

const TRANSPORT=[
 ['tcp-scans','SYN, connect, FIN, NULL & Xmas scans','Knock patterns wenas karala open doors hoyanawa.','Port responses and flag-handling behaviour reveal exposed services.','SYN: SYN-ACK suggests open, RST suggests closed. Connect scan completes the handshake. FIN/NULL/Xmas use unusual flags.','Restrict services; stateful flag validation and scan detection','Silence is inconclusive. Unusual-flag responses vary by OS; they do not universally bypass firewalls.'],
 ['udp-scan','UDP scanning and sweeps','No reply kiyanne closed kiyala newei.','UDP has no handshake, so scanning depends on application/ICMP responses.','Application reply suggests open; ICMP port-unreachable suggests closed; silence is open/filtered/loss.','Limit UDP exposure and detect sequential probes','Blocking ICMP reduces scanner certainty but does not prevent all reconnaissance.'],
 ['os-fingerprint','OS fingerprinting','Stack behaviour eken operating system eka guess karanawa.','Implementations differ in protocol responses and header choices.','Probe responses let the attacker infer OS/stack details and choose likely exploits.','Reduce unnecessary exposed services and patch systems','An OS guess is not proof that a specific vulnerability exists.'],
 ['tcp-hijack','TCP session hijacking','Right sequence number ekka wena kenek wage data denna.','Unauthenticated TCP data can be forged by an attacker able to spoof acceptable sequence information.','Spoof a participant and inject acceptable data to take over or alter the stream.','TLS/SSH authenticated data; unpredictable initial sequence numbers','Data authentication limits content forgery, but does not prevent every transport denial of service.'],
 ['tcp-reset','TCP RST injection','Fake hang-up signal ekak.','TCP reset packets are not protected by application TLS authentication.','Forge an acceptable RST to terminate the connection, harming availability.','Strong TCP reset validation; suitable IPsec; monitoring/reconnect','TLS protects records, not the TCP RST header. Hijacking seeks control; reset seeks disruption.'],
 ['syn-flood','SYN flood and SYN cookies','Seat reserve karala final confirmation eka denne ne.','Normal initial SYN handling allocates finite half-open state.','Many incomplete handshakes fill the backlog and exclude legitimate new connections.','SYN cookies/proxy; request limits and upstream mitigation','Cookies avoid ordinary initial per-SYN state, but CPU and bandwidth limits remain.'],
 ['udp-flood','UDP floods and reflection','Handshake ekak nathi nisa requests cheap.','UDP sends without connection setup and can drive application or ICMP work.','Many packets consume bandwidth/CPU; spoofed queries may amplify replies at a victim.','Rate limits, source validation, restricted reflectors and upstream filtering','Closing a service does not remove all bandwidth costs; closed ports may generate ICMP errors.'],
 ['udp-bomb','Malformed UDP length attack','Header size eka payload ekata match wenne ne.','A vulnerable parser mishandles invalid UDP lengths/headers.','Malformed datagrams crash or disrupt the vulnerable stack.','Patch parsers and validate packet lengths','A malformed-packet bug differs from a flood of otherwise valid UDP packets.']
];
for(const [id,title,hook,weak,effect,control,limit] of TRANSPORT){
 add('m08',id,title,['Legitimate client','State / filter','Service','Attacker'],hook,weak,
 [S('Exploit the assumption',weak,3,1,'Probe / forged packet'),S('Observe the mechanism',effect,3,2,title),S('Observe the user impact','The attacker learns information, injects data, or disrupts availability depending on this technique.',0,2,'Service result')],control,
 [S('Apply the relevant control',control,0,1,'Configured defence'),S('Inspect/limit the traffic','The selected defence validates the relevant field, state or resource demand.',3,1,'Validation / limit'),S('Verify intended service','Check legitimate connections and denial/detection counters.',0,2,'Legitimate traffic')],limit,
 Q(`Which response fits ${title}?`,[control,'Trust unusual flags without checking','Remove all monitoring'],0,limit));
}

add('m09','firewall-state','Stateless versus stateful inspection',['Client','Firewall','Web server','Unsolicited sender'],
 'Stateless = eka packet eka. Stateful = conversation eka mathakai.','Headers alone do not prove that a packet belongs to an allowed connection.',
 [S('Allow a request','A basic filter allows the outbound header pattern.',0,1,'Request'),S('Create a broad reply rule','Without connection state, return traffic needs explicit rules.',2,1,'Reply header'),S('Forge a matching header','An unsolicited sender may match a broad header-only rule.',3,1,'Pretend reply','No session memory')],
 'Track connection state',
 [S('Record an allowed connection','Store its endpoints and relevant protocol state.',0,1,'New session','State table entry'),S('Recognise the real reply','The server reply belongs to the tracked connection.',2,0,'Tracked reply','ALLOW'),S('Reject unrelated traffic','An unsolicited packet has no appropriate state/policy.',3,1,'Unrelated packet','DROP')],
 'State consumes memory and can be exhausted. An allowed encrypted connection may still carry an application attack.',
 Q('Does TCP established in a basic ACL prove connection state?',['Yes','No, it checks ACK/RST flags','Only for UDP'],1,'It is a flag test, not a connection table.'),'Access control');

add('m09','waf','Web attacks, proxy, NGFW & UTM',['Web client','Security gateway','Web application','Malicious request'],
 'Port 443 open kiyala request eke content eka safe wenne ne.','An allowed connection can contain SQL injection or other application abuse.',
 [S('Pass the network rule','A TCP/443 connection is allowed by the perimeter.',3,1,'Allowed HTTPS'),S('Reach the application','The request contains malicious application input.',1,2,'Malicious request'),S('Exploit unsafe processing','Vulnerable application logic processes the request.',3,2,'Application exploit')],
 'Secure code + appropriately configured application inspection',
 [S('Choose the inspection role','A WAF specialises in HTTP; a proxy terminates and mediates a protocol; a circuit gateway only validates sessions.',0,1,'Choose inspection'),S('Inspect permitted content','A WAF can reject matching web attacks when it can inspect the relevant plaintext.',3,1,'Application rejection'),S('Select broader products by needs','NGFW adds app/user-aware control; UTM bundles services for simpler administration.',0,2,'Allowed application')],
 'TLS inspection needs appropriate termination/trust and policy. WAFs need tuning and do not replace secure application code.',
 Q('A stateful firewall allows HTTPS but misses SQL injection. What helps?',['A WAF plus secure input handling','A bigger MAC table','Disabling ARP'],0,'Web inspection and safe application processing address the application-layer weakness.'));

add('m09','ids-ips','Firewall, IDS and IPS roles',['User','Policy firewall','Application','Suspicious traffic'],
 'Firewall gatekeeper. IDS CCTV. IPS stop karana guard.','Detection and enforcement are different responsibilities.',
 [S('Apply permitted traffic policy','A firewall permits a connection under its rules.',0,1,'Policy allowed'),S('Observe suspicious content','A passive IDS sees a signature or anomaly.',3,2,'Suspicious traffic','IDS: ALERT'),S('Traffic may continue','An alert alone does not physically stop the packet.',3,2,'Still delivered')],
 'Inline IPS with tuned policy and monitoring',
 [S('Inspect inline','Traffic traverses the IPS enforcement path.',3,1,'Inspection'),S('Block a matching threat','The IPS can discard traffic that violates detection policy.',3,1,'DROP + ALERT'),S('Monitor false positives','Allow legitimate requests and investigate erroneous blocking.',0,2,'Legitimate request')],
 'Signatures miss unknown variants; anomalies can produce false alarms. Inline devices can add latency and failure risk.',
 Q('Which normally alerts without inline blocking?',['IDS','IPS','A deny ACL'],0,'A passive IDS reports suspicious activity rather than dropping traffic itself.'),'Detection / prevention');

add('m10','acl-order','ACL first match and implicit deny',['Source subnet','Ordered ACL','Server','Other traffic'],
 'Queue eke palaweni match eka decision eka.','An ACL runs in order and stops at its first matching entry.',
 [S('Broad permit first','If permit ip any any is first, every IP packet matches it.',3,1,'Rule 1: permit all','ALLOW'),S('Specific deny is never reached','A later Telnet deny cannot override an earlier match.',1,2,'Later deny skipped'),S('Missing final permits','Conversely, unmatched traffic meets the implicit deny at the end.',0,1,'No matching rule','DENY')],
 'Specific rules first; permits reflect the policy',
 [S('Match the precise condition','Check source, destination, protocol and port for an extended ACL.',0,1,'Specific rule'),S('Take the first decision','A match immediately determines permit or deny.',1,2,'Policy decision'),S('Apply and test','Attach the ACL to the correct interface/direction and test both allowed and denied cases.',0,1,'Interface policy')],
 'Permit-all belongs only in a block-only policy. An allow-only policy must retain denial of other traffic.',
 Q('An ACL is defined but never attached. Does it filter interface traffic?',['Yes','No','Only at midnight'],1,'It must be applied to the required interface and direction.'),'Policy correctness');

add('m10','dmz','DMZ containment and directional zones',['Internet','DMZ web server','Internal database','Compromised DMZ host'],
 'Public reception ekata awata private room walata permission ne.','A public server is exposed; compromise must not grant unrestricted internal access.',
 [S('Publish the web service','Internet users reach the DMZ server on required ports.',0,1,'Web request'),S('Assume compromise','A web flaw gives the attacker control of the DMZ machine.',3,1,'Server compromised'),S('Attempt lateral movement','A flat policy permits movement toward internal systems.',1,2,'Unrestricted lateral access')],
 'Separate zones and tightly scoped DMZ-to-inside policy',
 [S('Permit only public services','Outside→DMZ permits only needed services.',0,1,'Allowed service'),S('Block broad inward access','DMZ→inside denies unrelated connections.',3,2,'Blocked lateral access'),S('Allow narrowly required flows','Explicit service dependencies can be permitted; replies may use state.',1,2,'Approved dependency')],
 'A zone-pair is directional. Two firewalls do not automatically mean high availability or safe rules.',
 Q('Must inside→outside and outside→inside permit the same new connections?',['Yes','No; policies are directional','Only with IPv6'],1,'A return packet can be allowed by state without allowing new reverse initiation.'),'Containment');

add('m11','vpn-tunnel','Tunnel versus protected VPN',['Private sender','Public Internet','Remote peer','Eavesdropper'],
 'Plain envelope ekak lock ekak newei. GRE tunnel ekata secrecy ne.','Encapsulation alone hides neither content nor sender authenticity.',
 [S('Wrap a packet','GRE puts the inner packet inside another packet.',0,1,'GRE wrapper'),S('Cross an untrusted network','The payload remains readable without encryption.',1,3,'Visible payload'),S('Arrive at the peer','The peer decapsulates; tunnelling alone gave no secure identity proof.',1,2,'Decapsulated data')],
 'Authenticated encryption and peer authentication',
 [S('Authenticate and agree keys','Verify the peer and establish suitable session protection.',0,2,'Authenticated exchange'),S('Protect in transit','Encrypt and authenticate packets across the untrusted path.',0,1,'Protected packet','Outer routing metadata still visible'),S('Verify then decrypt','The peer checks integrity/replay and recovers the inner traffic.',1,2,'Verified data')],
 'VPN protection ends at tunnel endpoints. Compromised endpoints and onward plaintext remain risks.',
 Q('Does GRE alone provide confidentiality?',['Yes','No','Only for TCP'],1,'GRE encapsulates; IPsec can add cryptographic protection.'),'Confidentiality / integrity');

add('m11','vpn-purpose','Pick a VPN by purpose',['Remote worker','VPN gateway','Company/cloud LAN','Untrusted network'],
 'Person → remote access. Office → site-to-site. Moving person → mobile.','Deployment form and connection purpose answer different questions.',
 [S('Remote user','A person connects to an organisation: remote access.',0,1,'User tunnel'),S('Whole branch','Gateways connect whole networks: site-to-site. A managed cloud gateway is a cloud variant.',1,2,'Network tunnel'),S('Moving or personal user','Mobile preserves sessions across network changes; personal VPN routes via a provider for Internet access.',0,3,'Changed network')],
 'Match access scope, continuity and capacity',
 [S('Identify the need','Driver changing WiFi/cellular → mobile; always-on branches → site-to-site.',0,1,'Purpose choice'),S('Size the gateway','Choose software/hardware capacity independently of purpose.',1,2,'Capacity choice'),S('Restrict access','Apply authentication and least privilege even inside a VPN.',0,2,'Permitted resources')],
 'A personal VPN moves trust to its provider; it does not replace HTTPS or guarantee anonymity.',
 Q('Three permanent branches with no per-user client management need…',['Site-to-site VPN','Only a personal VPN','Only an HTTP proxy'],0,'Gateway-to-gateway connections carry whole-site traffic.'),'Secure connectivity');

add('m12','ah-esp','AH, ESP and transport/tunnel modes',['Original packet','IPsec boundary','Peer','Observer'],
 'AH seal ekak; encryption ne. ESP locked envelope ekak wenna puluwan.',
 'Integrity protection and confidentiality are separate properties.',
 [S('Choose AH only','AH authenticates relevant packet data but does not encrypt it.',0,1,'AH packet','Payload readable'),S('Observer reads content','An observer can read protected-but-unencrypted data.',1,3,'Visible plaintext'),S('NAT changes a field','Address translation changes header fields protected by AH.',1,2,'Changed address','AH validation can fail')],
 'Use suitable ESP authenticated encryption and NAT-T',
 [S('Transport mode','Protect the original IP payload; original IP header remains outside encryption.',0,1,'Transport ESP'),S('Tunnel mode','Protect the entire original inner packet with a new outer IP header.',1,2,'Tunnel ESP','Inner addresses hidden'),S('Traverse NAT when required','ESP NAT-T uses UDP 4500; IKE commonly uses UDP 500.',0,2,'NAT-T')],
 'ESP guarantees depend on configuration. Outer headers remain visible; AH never gains encryption from tunnel mode.',
 Q('A site-to-site VPN usually uses which packet mode?',['Tunnel','Only AH','No outer header'],0,'Tunnel mode encapsulates the whole inner IP packet.'),'Confidentiality / integrity');

add('m12','ike','IKE, crypto ACL and GRE over IPsec',['Router A','IKE negotiation','Router B','Unselected traffic'],
 'First agree protection; then protect selected data. Crypto ACL deny ≠ packet drop.',
 'Peers need compatible algorithms, identities, keys and traffic selectors.',
 [S('Phase 1: protected negotiation','In the taught IKEv1 model, authenticate peers and create the IKE/ISAKMP SA.',0,1,'IKE Phase 1'),S('Phase 2: data SAs','Negotiate directional IPsec SAs for selected traffic.',1,2,'IKE Phase 2','Two-way data: paired SAs'),S('Select interesting traffic','A crypto ACL selects what to encrypt; non-matching traffic follows ordinary routing/policy.',3,1,'Non-matching traffic','Not automatically dropped')],
 'Match selectors, protect GRE, verify counters',
 [S('Configure four parts','IKE policy/key → transform set → traffic ACL → crypto map/interface.',0,1,'Configuration'),S('Protect the correct wrapper','For GRE over IPsec, select the outer GRE between tunnel endpoints.',0,2,'Encrypted GRE'),S('Verify both directions','Generate matching traffic and inspect SA and encaps/decaps counters.',1,2,'Counter check')],
 'These phases describe IKEv1. IKEv2 differs. Routing, reachability, NAT and firewall rules must also fit.',
 Q('A crypto ACL permit means…',['Encrypt/select this traffic','Always permit it through every firewall','Block it'],0,'It selects interesting traffic for the associated IPsec policy.'),'Correct protection');

add('m12','tls-vpn','TLS VPN portal versus full tunnel',['Contractor','TLS VPN gateway','Internal app/network','Excessive access'],
 'Timesheet ekata witharak nam whole office key denna epa.',
 'Access scope should reflect the task, not simply whether a tunnel exists.',
 [S('Give broad access','A contractor receives full network access for one occasional web task.',0,1,'Broad tunnel'),S('Expose unnecessary services','The connection can reach more internal resources than needed.',1,3,'Excess permissions'),S('Increase compromise impact','Stolen contractor credentials have a larger attack surface.',3,2,'Unnecessary reach')],
 'TLS portal for narrow web access; full tunnel when needed',
 [S('Choose a portal','Expose only the internal timesheet application.',0,1,'Clientless portal'),S('Authenticate and authorise','Require identity verification and application-specific access.',1,2,'Timesheet access'),S('Use full clients deliberately','Employees needing broad resources can use controlled full TLS/IPsec tunnels.',0,2,'Scoped employee access')],
 'TLS normally traverses NAT using HTTPS-style transport, but a full TLS client can still give broad network access.',
 Q('A contractor needs one website twice a month. Best starting fit?',['Clientless portal','Unrestricted whole-network access','Unauthenticated GRE'],0,'A portal can keep access limited to the needed application.'),'Least privilege');

add('m13','aaa-functions','The three AAA gates',['User','Authentication','Protected action','Audit log'],
 'Who? → Can do what? → Did what?',
 'A valid login does not imply permission to perform every action.',
 [S('Authenticate identity','A technician supplies valid credentials.',0,1,'Login accepted'),S('Skip permission checks','If identity alone grants all privileges, the technician can alter critical configuration.',1,2,'Unrestricted command'),S('Log only the session','Login/logout records cannot reveal exactly which command changed the device.',2,3,'Session only','Action unknown')],
 'Separate identity, permissions and accounting',
 [S('Authentication','Prove the user identity with suitable factors.',0,1,'Verified user'),S('Authorisation','Permit show commands but deny unauthorised configuration.',1,2,'Command decision'),S('Accounting','Record identity, command, result and time in protected logs.',2,3,'Action record')],
 'Logs support accountability; strong non-repudiation also needs trustworthy identity and tamper-resistant evidence.',
 Q('Which function answers “May this user run configure?”',['Authentication','Authorisation','Accounting'],1,'Authentication identifies; authorisation grants specific permissions.'),'Access / accountability');

add('m13','mfa','MFA, biometrics and access models',['Employee','Identity checks','Role permissions','Stolen password'],
 'Passwords dekak = same factor. Know + have = different factors.',
 'One compromised factor or inconsistent per-user permissions can expose resources.',
 [S('Steal a password','A phished password defeats password-only access.',3,1,'Stolen secret'),S('Ask for another password','Two knowledge secrets remain the same factor category.',3,1,'Second knowledge secret'),S('Over-grant permissions','Manual per-user permission growth can leave excess access.',1,2,'Privilege creep')],
 'Distinct factors + least-privilege roles',
 [S('Use different categories','Combine knowledge with possession or appropriate biometrics.',0,1,'Independent factors'),S('Choose continuous assurance','Behavioural patterns can help detect a different user during a hospital session.',0,1,'Behaviour check'),S('Assign suitable policy','RBAC follows job roles; DAC follows owners; MAC follows labels; RuBAC follows conditions.',1,2,'Permission decision')],
 'Behavioural patterns drift; physical biometrics are hard to reissue. OTP can be phished and SMS has additional SIM-swap risks.',
 Q('Which is genuinely different-factor MFA?',['Password + PIN','Password + possession token','Two passwords'],1,'Knowledge and possession are different categories.'),'Authentication / authorisation');

add('m14','aaa-fallback','Server error versus credential rejection',['Administrator','TACACS+ server','Local account DB','Denied identity'],
 'Server down ≠ wrong password. Down unoth next method.',
 'An ordered AAA list must distinguish unavailable service from an explicit rejection.',
 [S('Try the central server','group tacacs+ local sends the request to the server first.',0,1,'Login request'),S('Server rejects credentials','An explicit reject is an authentication failure.',1,3,'REJECT','Stop: deny'),S('Do not try another password database','Normal fallback is not an opportunity to bypass the rejection.',3,2,'No fallback')],
 'Fallback only on service error/unavailability',
 [S('Try the central server','The server does not respond or returns a service error.',0,1,'ERROR / unavailable'),S('Advance to local','The local method checks an existing local account.',0,2,'Local authentication'),S('Accept only valid local credentials','Fallback preserves access during outage; it is still authentication.',2,0,'Accept or reject')],
 'Reverse order makes local authoritative first. Keep recovery access and test success, reject and outage separately.',
 Q('Central server replies “bad password”. What happens next?',['Try local automatically','Deny; no normal local fallback','Permit without authentication'],1,'Fallback normally follows error/unavailability, not explicit rejection.'),'Availability / access');

add('m14','radius-tacacs','RADIUS or TACACS+?',['WiFi user','AAA service','Router administrator','Unprotected attributes'],
 'Network admission → RADIUS. CLI command control → TACACS+.',
 'The protocol must fit network admission or device administration.',
 [S('RADIUS network access','RADIUS commonly serves 802.1X/WiFi/VPN admission using UDP 1812/1813.',0,1,'RADIUS'),S('TACACS+ administration','TACACS+ uses TCP 49 and separates authentication, authorisation and accounting.',2,1,'TACACS+'),S('Understand legacy protection','Classic RADIUS conceals the password field; classic TACACS+ protects its body, leaving the header visible.',1,3,'Visible metadata')],
 'Use fit-for-purpose AAA over protected management paths',
 [S('Authenticate many WiFi users','Use RADIUS/EAP interoperability for network admission.',0,1,'Access policy'),S('Authorise commands','Use appropriate TACACS+ per-command policies for administrators.',2,1,'Command policy'),S('Make central service resilient','Protect transport/logs and provide redundancy and controlled fallback.',1,2,'Resilient AAA')],
 'Legacy TACACS+ body protection is not modern transport encryption. Neither choice is universally best for every use.',
 Q('Thousands of university WiFi users normally fit…',['RADIUS / 802.1X','TACACS+ for every client','A MAC-only list'],0,'RADIUS/EAP is designed for broad network-access interoperability.'),'AAA selection');

const CRYPTO=[
 ['classical','Caesar and Vigenere','Letters shift karala pattern eka hide karanawa; key space eka podi.','Classical ciphers retain exploitable structure.','Caesar has only 25 nontrivial shifts; repeated Vigenere keys allow period/frequency analysis.','Use the calculators to learn the arithmetic; use vetted modern cryptography for real protection.','These are educational ciphers, not secure alternatives to AES or modern stream ciphers.'],
 ['ecb','ECB, CBC, CTR, GCM & XTS','Same blocks same picture → ECB leak.','The mode controls how a block cipher protects more than one block.','ECB repeats reveal patterns. CBC chains blocks; CTR creates a keystream; GCM adds authentication; XTS suits storage sectors.','Choose a mode appropriate to the data and authenticate it where required.','CBC needs an appropriate IV and secure authentication; CTR/GCM require nonce uniqueness. XTS does not authenticate data.'],
 ['keystream','Keystream reuse and WEP','Same mask eka twice use kalama mask eka cancel wenawa.','XOR with the same keystream twice leaks plaintext relationships.','C1=P1 XOR K; C2=P2 XOR K; C1 XOR C2=P1 XOR P2. Known P1 reveals P2.','Never reuse a nonce/keystream with a key; use suitable AEAD.','WEP has short-IV and RC4-design problems. A truly random one-time pad must be message-length and used only once.'],
 ['dh-mitm','Diffie–Hellman and MITM','Secret agree karanna puluwan; opposite side kawda kiyala DH thaniyama danne ne.','Unauthenticated public key shares can be substituted.','An attacker agrees one secret with Alice and another with Bob, relaying messages between them.','Authenticate ephemeral DH/ECDH shares using trusted signatures/certificates or a PSK.','Ephemeral exchange plus erased secrets can provide forward secrecy; DH itself is key agreement, not encryption.'],
 ['hybrid','Symmetric, asymmetric and hybrid','Asymmetric key eka arrange karanawa; symmetric data eka carry karanawa.','Symmetric key distribution is hard; asymmetric operations are too costly for bulk traffic.','A pairwise symmetric network needs n(n−1)/2 secrets; public keys still need identity binding.','Use authenticated asymmetric agreement, then symmetric AEAD for bulk data.','RSA has message-size and performance limits; ECC offers smaller keys for comparable classical security.']
];
for(const [id,title,hook,weak,effect,control,limit] of CRYPTO){
 add('m15',id,title,['Alice','Cipher / key exchange','Bob','Observer / MITM'],hook,weak,
 [S('Start with the design',weak,0,1,'Input / key'),S('See the weakness',effect,1,3,'Observable result'),S('Consider what leaks','A strong primitive does not repair an inappropriate mode, reused nonce or untrusted identity.',3,2,'Lost assurance')],control,
 [S('Match the requirement',control,0,1,'Chosen construction'),S('Protect keys and identity','Use appropriate keys, authenticated identity and correct nonce/IV handling.',0,2,'Authenticated exchange'),S('Protect the data','Use the selected construction and reject invalid authentication tags.',1,2,'Protected data')],limit,
 Q('Which statement is correct?',[control,'Hiding the algorithm is enough','Any repeated nonce is safe'],0,limit),'Cryptographic assurance');
}

const INTEGRITY=[
 ['plain-hash','Hash, HMAC and digital signature','Fingerprint copy karanna puluwan; secret stamp eka forge karanna be.','An unkeyed digest can be recomputed by anyone.','An attacker changes the message and replaces its plain hash; an HMAC needs the shared secret and a signature needs the private signing key.','Use a trusted digest, shared-key HMAC, or trusted public-key signature according to the required guarantee.','HMAC has no public non-repudiation because either key holder can generate it. A signature provides no confidentiality.'],
 ['passwords','Password salts and slow KDFs','Salt stops reused tables; slow KDF slows each guess.','Fast unsalted password hashes make guessing cheap and reveal equal passwords.','An attacker tries dictionary/brute-force or precomputed hashes against many accounts.','Use a unique random salt per password plus a deliberately expensive password KDF.','Salts are public and do not make weak passwords unguessable. A plain SHA-256 digest is not a password KDF.'],
 ['certificate','Certificates and key substitution','Public key eka kawurunge da? CA binding eka check karanna.','Encryption or signature verification with an attacker-substituted public key does not authenticate the intended party.','A MITM presents its own key and claims the server name.','Validate trusted chain, signatures, hostname, dates, permitted usage and applicable revocation status; verify private-key possession.','A copied public certificate is not possession of its private key. DV validates domain control, not merchant honesty.'],
 ['revocation','PKI trust and revocation','Trusted root → intermediate → leaf. Revoked nam stop.','A correctly signed certificate may have been revoked or issued by a compromised CA.','A stolen private key or compromised issuer can support impersonation even while dates look valid.','Protect roots, validate chains and check appropriate CRL/OCSP status; use transparency monitoring.','CRLs can be stale; OCSP has availability/privacy limits. Transparency logs expose suspicious issuance rather than automatically preventing it.']
];
for(const [id,title,hook,weak,effect,control,limit] of INTEGRITY){
 add('m16',id,title,['Sender / site','Verification','Receiver','Tamperer'],hook,weak,
 [S('Identify the missing assurance',weak,0,1,'Message / identity'),S('Attempt substitution',effect,3,1,'Changed claim'),S('Accept the wrong claim','Without the appropriate trusted check, the receiver cannot distinguish the intended origin.',1,2,'Unverified data')],control,
 [S('Establish the trust source',control,0,1,'Trusted verification'),S('Check the received evidence','Reject invalid tags, signatures, identities or status as appropriate.',3,1,'Invalid evidence','REJECT'),S('Accept only verified material','State precisely what the successful check proves.',1,2,'Verified result')],limit,
 Q('Which limitation still matters?',[limit,'Verification proves every statement is true','Encryption authenticates every public key'],0,limit),'Integrity / authenticity');
}

add('m16','tls-handshake','TLS 1.3: put the primitives together',['Browser','Handshake','Web server','Impersonator'],
 'ECDHE secret. Certificate identity. Signature possession. Finished transcript. AEAD data.',
 'A secure session needs both key establishment and authenticated identity.',
 [S('Exchange key shares','ClientHello and ServerHello include ephemeral shares and chosen parameters.',0,2,'ECDHE shares'),S('Skip identity validation','If the client trusts any certificate/key, a MITM can establish separate sessions.',3,1,'Untrusted identity'),S('Encrypt to the wrong peer','Encryption alone can protect a connection to the attacker.',0,3,'Wrong encrypted session')],
 'Validate each TLS handshake responsibility',
 [S('Agree a secret','ECDHE establishes key material; session keys are derived, not sent as plaintext.',0,2,'Key agreement'),S('Authenticate identity and possession','Validate the certificate chain/name; CertificateVerify signs the transcript using the server private key.',2,0,'Certificate + signature'),S('Confirm the transcript','Finished uses keyed transcript authentication and key confirmation.',0,2,'Finished'),S('Protect application data','AES-GCM or ChaCha20-Poly1305 provides authenticated encryption.',0,2,'AEAD records')],
 'This describes the normal certificate-authenticated TLS 1.3 handshake. It does not use RSA key transport.',
 Q('Which proves the server holds the certificate private key?',['CertificateVerify signature','The public certificate file alone','An unkeyed hash'],0,'The server signs the transcript; the client checks it with the validated public key.'),'Confidentiality / integrity / identity');

const CALCULATORS = [
 ['subnet','Subnet & wildcard','m02'],['cam','CAM capacity & port security','m04'],
 ['stp','STP root and path costs','m06'],['amplification','Reflection amplification','m05'],
 ['routing','Longest prefix & RPKI','m07'],['ospf','OSPF path cost','m07'],
 ['syn','SYN backlog versus cookies','m08'],['acl','Trace tutorial ACL policies','m10'],
 ['fallback','AAA method-list decisions','m14'],['caesar','Caesar letter-by-letter','m15'],
 ['vigenere','Vigenere letter-by-letter','m15'],['keys','Pairwise key count','m15'],
 ['dh','Diffie–Hellman arithmetic','m15'],['xor','XOR and reused keystream','m15'],
 ['hash','SHA-256 avalanche','m16'],['hashwork','Hash attack work factors','m16']
].map(([id,title,topic])=>({id,title,topic}));
