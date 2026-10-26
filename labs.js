/* Deterministic classroom models. No sockets, probes or attack traffic. */
'use strict';
const NSLabs = (() => {
 const option = (name,label,values,value) => ({name,label,values,value});
 const check = (name,label,value=false) => ({name,label,type:'checkbox',value});
 const event = (title,why,from,to,packet,state=[],headers=['Field','Value'],rows=[]) => ({title,why,from,to,packet,state,headers,rows});
 const result = (ok,headline,explanation,events) => ({ok,headline,explanation,events});
 const refs = (sourceId,from,to=from) => [{sourceId,from,to}];
 const cases = [
 {
  id:'packet-trip',topic:'m02',title:'Follow an office request, layer by layer',minutes:4,
  story:'A staff laptop opens the company portal on another network. Follow the addresses and wrappers that carry the request through its router.',
  goal:'Deliver the request to the remote server and identify what changes at the router.',
  nodes:['Staff laptop','Office router','Portal server'],
  fields:[option('family','IP version',[['v4','IPv4'],['v6','IPv6']],'v4'),option('service','Application',[['https','HTTPS over TCP · 443'],['dns','DNS query over UDP · 53']],'https'),option('nextHop','First frame destination',[['server','Remote server MAC (mistake)'],['gateway','Local gateway MAC']],'server')],
  fix:{nextHop:'gateway'},refs:refs('src02',6,47),
  terms:[['Encapsulation','Adding each layer’s addressing and control information around data.'],['Next hop','The directly reachable device that receives the next frame.'],['Port','An application endpoint number, not an IP protocol number.']],
  limitation:'One routed hop, already resolved neighbor addresses, no NAT. HTTPS here uses TCP; this example does not model HTTP/3. IPv6 uses Neighbor Discovery, not ARP.',
  run(v){const v6=v.family==='v6',tcp=v.service==='https',src=v6?'2001:db8:10::20':'192.168.10.20',dst=v6?'2001:db8:20::10':'192.168.20.10',ok=v.nextHop==='gateway',transport=tcp?'TCP':'UDP',port=tcp?'443':'53';return result(ok,ok?'Request delivered to the portal network':'Request cannot reach its first hop',ok?'The router replaces the link-layer envelope, not the destination IP. The server removes the wrappers and delivers the payload to the chosen service.':'A remote server’s MAC is not reachable on this LAN. Resolve and use the local gateway’s MAC.',[
   event('1 · Start with application data',tcp?'The browser prepares an HTTPS request. TLS protects the HTTP content; TCP provides an ordered byte stream.':'The DNS client prepares a lookup. This example uses UDP; DNS also supports TCP.',0,0,tcp?'Encrypted HTTP data':'DNS query',[['OSI 5–7 / TCP-IP application','Application payload'],['Payload visible without decryption',tcp?'No · TLS protects it':'Yes · ordinary DNS in this example']]),
   event('2 · Add transport and IP headers','Ports identify application endpoints. The IP header identifies the source and final destination across networks.',0,1,`${transport} inside ${v6?'IPv6':'IPv4'}`,[['Source socket',`${src} · port 51514`],['Destination socket',`${dst} · port ${port}`],['IP protocol / next-header number',tcp?'6 = TCP':'17 = UDP'],['Address size',v6?'128 bits':'32 bits']]),
   event('3 · Wrap for the local link',ok?`${v6?'Neighbor Discovery':'ARP'} supplies the gateway MAC. Ethernet carries the IP packet to that local gateway.`:'The chosen remote MAC is not a neighbor. The first-hop addressing is wrong, so this model stops here.',0,1,'Ethernet frame',[['Source MAC','02:00:00:00:10:20'],['Destination MAC',ok?'02:00:00:00:10:01 (gateway)':'Remote MAC · not locally reachable'],['IP destination remains',dst],['Link outcome',ok?'Gateway receives frame':'Delivery fails']]),
   event('4 · Route, then decapsulate',ok?'The router removes the incoming Ethernet header, decrements TTL/Hop Limit, and creates an outgoing frame. The destination strips Ethernet, IP and transport headers.':'No routed packet is produced. Correct the first-hop choice and run again.',1,2,ok?'New Ethernet frame':'No packet',[['Outgoing source MAC',ok?'Router’s server-facing MAC':'—'],['Outgoing destination MAC',ok?'Portal server MAC':'—'],[v6?'Hop Limit':'TTL',ok?'64 → 63':'64 · not forwarded'],['Destination IP',dst],['Delivered to service',ok?`${transport}/${port}`:'No']])
  ]);}
 },
 {
  id:'clinic-risk',topic:'m03',title:'Keep a clinic running after phishing',minutes:3,
  story:'A receptionist receives a fake password-reset message. The clinic needs to protect records and recover appointments if an endpoint is compromised.',
  goal:'Prevent this credential-phishing route, limit access, and retain a tested recovery path.',nodes:['Receptionist','Identity service','Patient records','Phishing sender'],
  fields:[check('verify','Verify reset requests through a known contact'),check('least','Limit the receptionist to necessary records'),check('backup','Keep an isolated, tested backup')],fix:{verify:true,least:true,backup:true},refs:refs('src03',8,38),
  terms:[['Asset','Something valuable: patient records and appointment availability.'],['Vulnerability','A weakness: an unverified reset process or excessive access.'],['Residual risk','Risk remaining after the selected controls.']],
  limitation:'A qualitative decision model, not a numeric risk score. This verified-reset control addresses the illustrated credential route, not every form of malware.',
  run(v){return result(v.verify&&v.least&&v.backup,v.verify&&v.least&&v.backup?'Layered protection in place':'Important controls are still missing','A prevention control, an access limit and a recovery measure solve different parts of the incident.',[
   event('Verify the request',v.verify?'The receptionist calls the known help-desk number. The impersonator cannot authorise a reset.':'The reset proceeds using the caller’s claim. The attacker obtains the account.',3,0,'Urgent reset request',[['Identity check',v.verify?'Independently verified':'Caller trusted'],['Credential route',v.verify?'Stopped':'Account compromised']]),
   event('Limit the impact','Even with prevention, plan for a compromised account. Least privilege limits what that account can read or change.',0,2,'Account permissions',[['Record access',v.least?'Only required records':'All clinic records'],['If account compromised',v.least?'Damage constrained':'Broad exposure']]),
   event('Recover the service','Tested isolated backups can restore damaged data. They cannot undo disclosure of stolen records.',1,2,'Recovery decision',[['Restore capability',v.backup?'Tested isolated copy':'No verified recovery'],['Data theft reversed by backup','No']])
  ]);}
 },
 {
  id:'switch-trust',topic:'m04',title:'Stop a rogue device on an office switch',minutes:5,
  story:'An unfamiliar device appears on user port Gi0/3. A legitimate PC has a DHCP lease at 192.168.10.20 on Gi0/2. Inspect both server replies and ARP claims.',
  goal:'Keep the legitimate PC working while stopping rogue DHCP replies and a forged ARP claim.',nodes:['Staff PC · Gi0/2','Access switch','DHCP server · Gi0/24','Rogue device · Gi0/3'],
  fields:[check('snooping','Enable DHCP snooping'),check('trustedUser','Trust the rogue device’s user port (misconfiguration)'),check('dai','Enable Dynamic ARP Inspection'),option('binding','Legitimate PC binding',[['dhcp','Learned DHCP binding'],['missing','Static IP with no binding'],['static','Approved static ARP entry']],'dhcp')],fix:{snooping:true,trustedUser:false,dai:true,binding:'dhcp'},refs:refs('src05',24,33),
  terms:[['Snooping','The switch accepts DHCP server replies only along trusted server paths.'],['Binding','A verified association between IP, MAC, VLAN and switch port.'],['DAI','Dynamic ARP Inspection checks address claims before forwarding them.']],
  limitation:'The legitimate server uplink is trusted. The user-port checkbox deliberately sets both snooping and DAI trust; on real devices those are separate settings. ARP ACLs/static bindings must match the deployment.',
  run(v){const rogueLease=!v.snooping||v.trustedUser,binding=v.binding==='static'||(v.binding==='dhcp'&&v.snooping),forged=!v.dai||v.trustedUser,legit=!v.dai||binding;return result(!rogueLease&&!forged&&legit,!rogueLease&&!forged&&legit?'Rogue traffic stopped; staff PC still works':'Trust or binding problem detected',!legit?'DAI also drops the legitimate PC because it lacks an allowed binding. Restore the binding; do not trust user ports as a workaround.':rogueLease||forged?'User ports must remain untrusted. Snooping protects DHCP; DAI separately protects ARP.':'The switch learns trusted lease information and uses it to check ARP claims.',[
   event('Learn the real lease',binding?'The switch has verified information for the legitimate PC.':'No usable binding exists for the legitimate PC.',2,1,'DHCP ACK / approved static entry',[['Binding available',binding?'Yes':'No']],['IP address','MAC','VLAN','Port'],binding?[['192.168.10.20','02:00:00:00:00:20','10','Gi0/2']]:[]),
   event('Inspect a rogue DHCP Offer',rogueLease?'The reply passes because snooping is off or its arrival port is trusted. The client could accept malicious gateway/DNS settings.':'Snooping drops a server reply received on an untrusted user port.',3,1,'Offer · gateway 192.168.10.99',[['Ingress','Gi0/3'],['Decision',rogueLease?'FORWARD rogue offer':'DROP rogue offer']]),
   event('Inspect an impersonated ARP claim',forged?'The forged claim is not checked. It can overwrite the peer’s cached mapping.':'DAI rejects the claim: 192.168.10.20 does not belong to the rogue MAC on Gi0/3.',3,1,'ARP · .20 is at rogue MAC',[['Claimed IP','192.168.10.20'],['Claimed MAC','02:00:00:00:00:99'],['Decision',forged?'FORWARD forged ARP':'DROP forged ARP']]),
   event('Check legitimate ARP too',legit?'The legitimate PC can use the LAN.':'The legitimate PC is blocked too: configure an appropriate static ARP entry or restore its DHCP binding.',0,1,'ARP · .20 is at staff MAC',[['Decision',legit?'FORWARD legitimate ARP':'DROP · missing binding'],['Staff connectivity',legit?'Available':'Broken']])
  ]);}
 },
 {
  id:'stp-incident',topic:'m06',title:'Choose the right STP guard',minutes:4,
  story:'You support a campus network. A rogue switch on a wall port, a downstream superior root claim, and lost BPDUs on an alternate link need different responses.',
  goal:'Match the guard to the port and incident without introducing a forwarding loop.',nodes:['Access switch','Distribution switch','Intended root','Rogue switch / failed link'],
  fields:[option('incident','Incident',[['edge','A PC-facing port receives a BPDU'],['root','A downstream switch claims a better root'],['loss','An alternate inter-switch port stops receiving BPDUs']],'edge'),option('guard','Configured feature',[['none','None / PortFast alone'],['bpdu','BPDU Guard'],['root','Root Guard'],['loop','Loop Guard']],'none')],fix:{incident:'edge',guard:'bpdu'},refs:refs('src10',12,27),
  terms:[['BPDU','A switch message used to calculate a loop-free tree.'],['Err-disabled','A port is taken out of service after a violation.'],['Inconsistent','STP keeps a port non-forwarding while an unsafe condition persists.']],
  limitation:'This lab isolates each guard’s trigger. Loop Guard’s case assumes a physical link still up with one-way BPDU loss. It does not treat ordinary link-down as that failure.',
  run(v){const expected={edge:'bpdu',root:'root',loss:'loop'}[v.incident],ok=v.guard===expected;let state='Unprotected for this incident';if(v.guard==='bpdu'&&v.incident!=='loss')state='Err-disabled';else if(v.guard==='root'&&v.incident==='root')state='Root-inconsistent';else if(v.guard==='loop'&&v.incident==='loss')state='Loop-inconsistent';return result(ok,ok?'Correct guard for this incident':'Guard does not fit the intended port role',ok?'The affected port stops forwarding while the network keeps the intended safety boundary.':v.guard==='bpdu'&&v.incident==='root'?'BPDU Guard shuts this inter-switch link on any BPDU, including legitimate ones. Use Root Guard where ordinary BPDUs are expected but superior roots are not.':'Match the trigger: any BPDU at an edge, superior BPDU downstream, or missing expected BPDUs on a non-designated link.',[
   event('Identify the port role','Do not select a guard just because the incident mentions STP. First identify what the port is supposed to connect to.',0,1,'Port-role check',[['Incident',v.incident],['Correct feature',{edge:'BPDU Guard',root:'Root Guard',loss:'Loop Guard'}[v.incident]]]),
   event('Process the control-plane event','The switch evaluates the configured guard. PortFast only changes startup behavior; it does not authenticate a BPDU.',3,1,v.incident==='loss'?'Expected BPDUs missing':'BPDU received',[['Configured feature',v.guard],['Port state',state]]),
   event('Plan recovery',state==='Err-disabled'?'Remove the cause, then recover the port using the configured recovery procedure.':state.includes('inconsistent')?'The guard can recover automatically once the triggering condition clears.':'The intended guard did not trigger; correct the configuration first.',1,2,'Recovery',[['Desired root preserved',ok?'Yes':'Not assured by this choice'],['Ordinary data learning states','Listening: no learn; learning: learn only; forwarding: learn + forward']])
  ]);}
 },
 {
  id:'source-check',topic:'m05',title:'Filter spoofed traffic at the correct edge',minutes:3,
  story:'A branch router receives packets from its directly connected staff subnet, 192.168.10.0/24. A compromised device sends a packet claiming to be an unrelated Internet host.',
  goal:'Reject the forged source while allowing the real staff address.',nodes:['Staff LAN','Branch router','Internet','Compromised laptop'],
  fields:[option('source','Source address arriving from the staff LAN',[['real','192.168.10.20 · legitimate'],['forged','203.0.113.50 · forged']],'forged'),check('filter','Validate source prefix on the staff-facing ingress interface')],fix:{filter:true},refs:refs('src07',20,21),
  terms:[['Spoofing','Putting a false source address in a packet.'],['Ingress','Traffic entering the named interface.'],['Egress','Traffic leaving the named interface.']],
  limitation:'A single-homed branch with only this /24 behind that interface. Complex multihomed networks need policies appropriate to their valid routes.',
  run(v){const allowed=!v.filter||v.source==='real',ok=v.source==='real'?allowed:!allowed;return result(ok,allowed?'Packet forwarded':'Spoofed source dropped',allowed&&v.source==='forged'?'Destination-based routing alone does not establish whether the source address is legitimate.':'At this boundary the router knows which source prefix can legitimately arrive from the staff network.',[
   event('Receive the packet','The packet is entering from the staff network, not from the Internet interface.',v.source==='real'?0:3,1,'IP packet',[['Ingress interface','Staff LAN'],['Claimed source',v.source==='real'?'192.168.10.20':'203.0.113.50'],['Expected source','192.168.10.0/24']]),
   event('Evaluate source validation',v.filter?'Compare the source against the prefix assigned behind this interface.':'No source validation is configured, so a routable destination can still be forwarded.',1,1,'Prefix check',[['Source validation',v.filter?'Enabled':'Off'],['Source belongs to staff subnet',v.source==='real'?'Yes':'No']]),
   event('Observe the boundary',allowed?'The packet crosses the branch edge.':'The packet is discarded before it can be used for source-spoofed reflection.',1,2,allowed?'Forwarded packet':'No outbound packet',[['Decision',allowed?'FORWARD':'DROP']])
  ]);}
 },
 {
  id:'routing-incident',topic:'m07',title:'Investigate a more-specific route',minutes:4,
  story:'Your edge router has a legitimate /22 route, but a second network announces a more-specific /24 containing the service address.',
  goal:'Reject an invalid origin announcement while preserving the legitimate route.',nodes:['Office user','Edge router','Legitimate AS 36561','Candidate origin'],
  fields:[option('origin','Candidate origin',[['17557','AS 17557 · not authorised'],['36561','AS 36561 · authorised']],'17557'),check('roa','A covering ROA authorises AS 36561 up to /24',true),check('enforce','Reject RPKI Invalid routes')],fix:{origin:'17557',roa:true,enforce:true},refs:refs('src12',20,39),
  terms:[['Prefix','An address block, such as /22 or /24.'],['Longest match','For forwarding, the matching route with the most network bits wins.'],['ROA','A signed statement authorising an AS to originate a prefix.']],
  limitation:'One ROA and two routes. RPKI validates origins, not the entire path. NotFound is allowed by the policy here and is not proof of legitimacy.',
  run(v){const valid=v.origin==='36561',status=!v.roa?'NotFound':valid?'Valid':'Invalid',rejected=v.enforce&&status==='Invalid',ok=valid||rejected;return result(ok,rejected?'Invalid /24 rejected; legitimate /22 selected':`Candidate /24 selected · ${status}`,rejected?'Rejecting the invalid candidate leaves the legitimate aggregate as the longest accepted match.':valid?'The candidate origin matches the ROA when present; this check alone cannot authenticate the AS path.':'The router prefers the /24. An absent ROA or an unenforced Invalid result cannot stop this candidate.',[
   event('Inspect matching routes','Both routes contain destination 208.65.153.20. More-specific forwarding wins before considering this validation policy.',0,1,'208.65.153.20',[['Destination','208.65.153.20']],['Prefix','Origin'],[['208.65.152.0/22','AS 36561'],['208.65.153.0/24',`AS ${v.origin}`]]),
   event('Validate the origin',v.roa?'Check the origin AS and the permitted maximum prefix length.':'No covering ROA means NotFound, not Invalid.',3,1,'Candidate /24',[['Validation',status],['Reject Invalid policy',v.enforce?'On':'Off']]),
   event('Install and forward','Forwarding uses the longest match among accepted routes.',1,rejected?2:3,'Selected route',[['Selected prefix',rejected?'208.65.152.0/22':'208.65.153.0/24'],['Origin',rejected?'AS 36561':`AS ${v.origin}`]])
  ]);}
 },
 {
  id:'server-backlog',topic:'m08',title:'Keep a portal reachable during incomplete handshakes',minutes:3,
  story:'The portal has 16 half-open connection slots. Many clients send SYNs but never finish the handshake. Five genuine clients are trying to log in.',
  goal:'Admit the five legitimate clients without keeping half-open state for the unfinished attacker handshakes.',nodes:['Genuine clients','Portal TCP stack','Application','Incomplete SYN sources'],
  fields:[option('load','Incomplete SYNs',[['8','8 · below capacity'],['40','40 · above capacity']],'40'),check('cookies','Use SYN cookies when under pressure')],fix:{load:'40',cookies:true},refs:refs('src14',25,26),
  terms:[['SYN','The request to begin a TCP connection.'],['Half-open','A handshake has started, but the final valid ACK has not arrived.'],['SYN cookie','A way to encode initial state in the reply instead of reserving a normal backlog entry.']],
  limitation:'One snapshot, no expirations, and sufficient CPU, bandwidth and established-session capacity. Real implementations have thresholds and additional queue behavior.',
  run(v){const reserved=v.cookies?0:Math.min(16,Number(v.load)),admitted=Math.min(5,16-reserved);return result(admitted===5,`${admitted}/5 genuine clients admitted`,v.cookies?'Returning valid ACKs allow connection allocation. Cookies address half-open state, not every resource a flood can exhaust.':'Incomplete handshakes occupy the limited backlog until completion or timeout.',[
   event('Receive incomplete handshakes','Attack clients do not return a valid completing ACK.',3,1,`${v.load} SYNs`,[['Half-open capacity','16'],['State reserved',String(reserved)]]),
   event('Send SYN-ACKs',v.cookies?'The server encodes enough state in the response sequence rather than retaining ordinary half-open entries.':'The server retains state for admitted half-open connections.',1,3,'SYN-ACK',[['Cookie protection',v.cookies?'Active in this example':'Off'],['Remaining slots',String(16-reserved)]]),
   event('Accept valid final ACKs','A genuine client completes SYN → SYN-ACK → ACK. Only then does the connection become established.',0,2,'Valid final ACK',[['Genuine clients admitted',`${admitted}/5`],['Bandwidth flood solved','No']])
  ]);}
 },
 {
  id:'firewall-return',topic:'m09',title:'Distinguish a reply from a forged ACK',minutes:4,
  story:'An office PC is allowed to open HTTPS connections. A packet arriving from outside claims to be reply traffic. Decide whether the firewall should trust it.',
  goal:'Allow the genuine response and reject a packet that only claims to be part of a connection.',nodes:['Office PC','Perimeter firewall','Web server','Unsolicited sender'],
  fields:[option('mode','Inspection',[['flags','Stateless ACL: ACK/RST flag check'],['state','Stateful connection tracking']],'flags'),option('traffic','Inbound traffic',[['forged','Unsolicited ACK · no connection'],['reply','Genuine response to an allowed connection']],'forged')],fix:{mode:'state'},refs:refs('src16',10,18),
  terms:[['State table','Records of permitted connections and their protocol state.'],['Five-tuple','Source IP, source port, destination IP, destination port and protocol.'],['Established keyword','An ACL flag test, not a full TCP connection-state check.']],
  limitation:'The outside policy otherwise denies new inbound traffic. This is a simplified connection model, not a TCP sequence-window implementation.',
  run(v){const genuine=v.traffic==='reply',allow=v.mode==='flags'||genuine,ok=allow===genuine;return result(ok,allow?'Inbound packet allowed':'Unsolicited ACK rejected',ok?'A matching permitted connection, not just an ACK bit, supplies the context for this decision.':'An ACK flag is attacker-controlled. An ACL established match does not prove a connection exists.',[
   event('Check prior connection state',genuine?'An allowed outbound handshake created a connection entry.':'No matching outbound connection was established.',0,1,'Connection history',[['Matching connection',genuine?'Present':'Absent']],['Client','Server','State'],genuine?[['192.168.10.20:51514','198.51.100.10:443','ESTABLISHED']]:[]),
   event('Inspect the outside packet','Both sample packets carry ACK. Only the genuine reply belongs to a permitted connection.',genuine?2:3,1,'TCP ACK',[['TCP ACK flag','Set'],['Matching state',genuine?'Yes':'No'],['Policy',v.mode==='flags'?'ACK/RST test only':'Connection-state check']]),
   event('Apply the policy',allow?'This packet reaches the inside PC.':'The firewall discards the unsolicited packet.',1,0,allow?'Forwarded ACK':'Dropped ACK',[['Decision',allow?'ALLOW':'DROP']])
  ]);}
 },
 {
  id:'acl-placement',topic:'m10',title:'Apply a Telnet rule in the right direction',minutes:4,
  story:'Block staff Telnet to 192.168.20.5, but keep HTTPS working. Staff traffic enters the router on Gi0/1 and leaves toward the server on Gi0/2.',
  goal:'Block only TCP/23 from the staff network to the server.',nodes:['Staff · 192.168.10.20','Router · Gi0/1 → Gi0/2','Server · 192.168.20.5'],
  fields:[option('placement','Apply ACL',[['out','Gi0/1 out · wrong for staff requests'],['in','Gi0/1 in · staff requests enter here'],['server','Gi0/2 out · server-bound traffic']],'out'),option('order','Rule ordering',[['specific','Specific deny, then permit all other traffic'],['broad','Permit all first (mistake)'],['missing','Only the deny; forget the final permit']],'specific'),option('service','Test traffic',[['telnet','Telnet · TCP/23'],['https','HTTPS · TCP/443']],'telnet')],fix:{placement:'in',order:'specific'},refs:refs('src18',15,24),
  terms:[['Inbound','Entering the particular interface where the ACL is attached.'],['First match','Stop at the first matching rule, whether permit or deny.'],['Implicit deny','Unmatched traffic is dropped after the last rule.']],
  limitation:'Single forward path with no NAT. The two interfaces and their directions are explicit; the model does not apply this ACL globally.',
  run(v){const traversed=v.placement!=='out',telnet=v.service==='telnet';const decision=!traversed||v.order==='broad'?'PERMIT':telnet||v.order==='missing'?'DENY':'PERMIT';const ok=decision===(telnet?'DENY':'PERMIT');let rules=[['10','deny tcp 192.168.10.0 0.0.0.255 host 192.168.20.5 eq 23'],['20','permit ip any any']];if(v.order==='broad')rules.reverse();if(v.order==='missing')rules=rules.slice(0,1);return result(ok,`${decision} · ${telnet?'Telnet':'HTTPS'}`,!traversed?'The request never crosses Gi0/1 outbound, so this ACL is not evaluated.':v.order==='broad'?'The broad permit matches first. The later specific deny is unreachable.':v.order==='missing'&&!telnet?'HTTPS misses the Telnet rule, then hits implicit deny.':'The source-side inbound extended ACL can stop only the unwanted service early.',[
   event('Map the actual path','Directions are relative to each router interface. Staff requests enter Gi0/1 and exit Gi0/2.',0,1,'Staff → server request',[['Ingress','Gi0/1 in'],['Egress','Gi0/2 out'],['Chosen attachment on path',traversed?'Yes':'No']]),
   event('Evaluate the ordered rules',traversed?'Process entries top to bottom; stop at the first match.':'This ACL is skipped because it is attached to the opposite traffic direction.',1,1,`TCP/${telnet?'23':'443'}`,[['Packet destination','192.168.20.5']],['Order','Rule'],rules.concat([['last','implicit deny all']])),
   event('Observe application access',decision==='DENY'?'The router drops this request.':'The request reaches the server network.',1,2,decision==='DENY'?'Dropped request':'Forwarded request',[['Decision',decision],['Expected policy',telnet?'DENY Telnet':'PERMIT HTTPS']])
  ]);}
 },
 {
  id:'vpn-choice',topic:'m11',title:'Connect a branch or a remote colleague',minutes:3,
  story:'The company needs private access over an untrusted Internet connection. The design differs for an entire branch and for one person working from home.',
  goal:'Choose a topology that covers the intended users and protects their traffic.',nodes:['Branch / remote user','Public Internet','HQ gateway','Observer'],
  fields:[option('need','Who needs access?',[['branch','All branch devices to HQ'],['person','One person working remotely']],'branch'),option('design','Connection design',[['gre','GRE tunnel only'],['site','Authenticated site-to-site IPsec'],['remote','Authenticated remote-access VPN']],'gre')],fix:{need:'branch',design:'site'},refs:refs('src20',9,22),
  terms:[['Site-to-site','Gateways connect entire networks.'],['Remote access','An individual device/user connects to a private service or network.'],['Tunnel','An outer wrapper that carries another packet; it is not inherently encryption.']],
  limitation:'Assumes modern authenticated encryption for the secure VPN choices. Access to internal services still requires least-privilege policy.',
  run(v){const secure=v.design!=='gre',fit=v.need==='branch'?v.design==='site':v.design==='remote';return result(secure&&fit,secure&&fit?'VPN fits the requirement':secure?'Secure transport, wrong scope':'Tunnel is not confidential',!secure?'GRE provides encapsulation but no encryption or peer authentication by itself.':!fit?'Select gateway-to-gateway coverage for a branch or individual authentication for a remote worker.':'The topology matches the access scope; restrict which internal services become reachable.',[
   event('Define the endpoints','Identify whether the endpoints represent complete networks or one authenticated user.',0,1,'Access requirement',[['Scope',v.need==='branch'?'Branch subnet ↔ HQ subnet':'Individual user ↔ permitted company services']]),
   event('Cross the Internet',secure?'Authenticated encryption hides the protected content from an observer.':'An observer can read unencrypted inner content carried by this tunnel.',0,2,secure?'Protected tunnel traffic':'GRE-encapsulated traffic',[['Confidentiality',secure?'Yes, under stated configuration':'No'],['Peer identity',secure?'Authenticated':'Not supplied by GRE alone']]),
   event('Apply internal access policy','Being connected through a VPN is not permission to access every internal system.',2,2,'Access boundary',[['Topology fits',fit?'Yes':'No'],['Internal policy still required','Yes']])
  ]);}
 },
 {
  id:'ipsec-envelope',topic:'m12',title:'Inspect a branch-to-HQ IPsec packet',minutes:4,
  story:'A branch PC at 10.10.1.20 sends payroll data to 10.20.1.10 at HQ. Observe what an Internet observer can see and whether peer authentication succeeds.',
  goal:'Authenticate the gateways and hide both the payroll data and original private IP header in transit.',nodes:['Branch PC','Branch VPN gateway','HQ VPN gateway','Internet observer'],
  fields:[option('protection','IPsec protection',[['ah','AH · integrity, no encryption'],['esp','ESP with authenticated encryption']],'ah'),option('mode','IPsec mode',[['transport','Transport · original IP header retained'],['tunnel','Tunnel · new outer IP header']],'transport'),check('auth','Peers have matching, valid authentication',true)],fix:{protection:'esp',mode:'tunnel',auth:true},refs:refs('src22',5,11),
  terms:[['AH','Authentication Header: integrity/authentication without confidentiality.'],['ESP','Encapsulating Security Payload; here configured with authenticated encryption.'],['SA','Security Association: the agreed parameters for one direction of protected traffic.']],
  limitation:'Packet-envelope comparison, not a complete IKE implementation. The lecture’s Phase 1/Phase 2 terms describe IKEv1. Mode selection does not itself turn AH into encryption.',
  run(v){const encrypt=v.protection==='esp',hidden=encrypt&&v.mode==='tunnel',ok=v.auth&&hidden;return result(ok,!v.auth?'Peer authentication failed':ok?'Private packet protected end to end between gateways':'Observer still sees part of the private packet',!v.auth?'No protected data SA is established in this fail-closed example.':!encrypt?'AH does not encrypt. Tunnel wrapping alone cannot conceal the original packet.':!hidden?'ESP transport encrypts payload, but retains the original IP header.':'ESP tunnel mode protects the inner IP packet; the outer gateway addresses remain visible.',[
   event('Authenticate the peer','The gateways establish an authenticated negotiation channel before installing data-protection parameters.',1,2,'IKE authentication',[['Authentication',v.auth?'Succeeded':'Failed'],['Data SA',v.auth?'Available':'Not established']]),
   event('Build the envelope',v.mode==='tunnel'?'Add an outer IP header for gateway-to-gateway delivery.':'Retain the original IP header and protect the selected transport payload.',1,2,v.auth?'IPsec packet':'No protected packet',[['Original source','10.10.1.20'],['Original destination','10.20.1.10'],['Outer addresses',v.mode==='tunnel'?'192.0.2.1 → 198.51.100.1':'Original header retained']]),
   event('Inspect the observer’s view','Encryption hides selected contents, not the existence or timing of traffic.',1,3,v.auth?'Observable packet fields':'No data sent',[['Payload readable',!v.auth?'No data':encrypt?'No':'Yes'],['Original private IPs visible',!v.auth?'No data':hidden?'No':'Yes'],['Outer routing header visible',v.auth?'Yes':'No data']])
  ]);}
 },
 {
  id:'aaa-permission',topic:'m13',title:'Let support inspect a router, not reconfigure it',minutes:3,
  story:'A help-desk engineer should inspect router status but must not change its configuration. Track identity, command permission and the audit trail separately.',
  goal:'Require two different authentication factors, enforce the support role, and record allowed commands.',nodes:['Support engineer','AAA service','Router command','Audit log'],
  fields:[option('factors','Login factors',[['two-passwords','Password + PIN'],['mfa','Password + security key']],'two-passwords'),option('command','Requested command',[['show','show interfaces'],['configure','configure terminal']],'configure'),check('authorize','Enforce read-only support authorization'),check('account','Record command accounting')],fix:{factors:'mfa',authorize:true,account:true},refs:refs('src26',5,26),
  terms:[['Authentication','Prove who is requesting access.'],['Authorization','Check which action that identity is allowed to perform.'],['Accounting','Record the action, identity and time.']],
  limitation:'Both sample credentials validate; this exercise distinguishes factor categories and role permissions. Password plus PIN is two knowledge secrets, not two-factor authentication.',
  run(v){const allowed=!v.authorize||v.command==='show',ok=v.factors==='mfa'&&v.authorize&&v.account;return result(ok,allowed?'Command allowed':'Configuration command denied',ok?'The support role, multiple factor categories and command logging meet the stated requirement.':'Successful login is not enough: check factor categories, action permissions and logging independently.',[
   event('Authenticate the engineer','Two factors must come from different categories, not just two different secret strings.',0,1,'Login proof',[['Credentials valid','Yes · scenario assumption'],['Factor categories',v.factors==='mfa'?'Knowledge + possession':'Knowledge + knowledge'],['Meets two-factor policy',v.factors==='mfa'?'Yes':'No']]),
   event('Authorize the requested action',allowed?'The command is allowed by the current policy.':'The read-only support role is not allowed to enter configuration mode.',1,2,v.command==='show'?'show interfaces':'configure terminal',[['Role','Support · read-only'],['Authorization enforced',v.authorize?'Yes':'No'],['Command decision',allowed?'PERMIT':'DENY']]),
   event('Record what happened',v.account?'The configured accounting logs permitted command activity. Denied commands should also be captured by suitable AAA/security logging.':'No command accounting record is configured.',2,3,'Audit event',[['Permitted activity recorded',v.account?'Yes':'No'],['Accounting prevents a forbidden action','No · authorization does that']])
  ]);}
 },
 {
  id:'aaa-outage',topic:'m14',title:'Test administrator access during an AAA outage',minutes:3,
  story:'A router uses “group tacacs+ local”. A local emergency account should help when the central service is unavailable, not bypass a deliberate central rejection.',
  goal:'Differentiate a server error from an authentication rejection.',nodes:['Administrator','TACACS+ server','Local database','Router session'],
  fields:[option('server','Central result',[['reject','Explicit credential rejection'],['error','Timeout / service error'],['accept','Accept']],'reject'),check('local','Emergency local credentials are correct',true),option('order','Method order',[['central','TACACS+ then local'],['local','Local then TACACS+']],'central')],fix:{server:'error',local:true,order:'central'},refs:refs('src24',9,20),
  terms:[['Reject','A definitive decision: the submitted identity is not accepted.'],['Error','The method could not provide an authentication decision.'],['Fallback','Try the next method after error/unavailability, not after rejection.']],
  limitation:'Local lookup here always returns a definitive accept or reject. Detailed vendor error classes and authorization fallback are outside this authentication example.',
  run(v){const localUsed=v.order==='local'||v.server==='error',accepted=localUsed?v.local:v.server==='accept';return result(true,accepted?'Login accepted':'Login rejected',v.order==='local'?'Local authentication gave a definitive result; the central method was not tried.':v.server==='reject'?'The explicit rejection stops the method list, even if the local password is correct.':v.server==='error'?'The central service returned no decision, so the next method is consulted.':'The server accepted the credentials; no local lookup is needed.',[
   event('Try the first method','Authentication methods run in order.',0,v.order==='local'?2:1,'Credentials',[['First method',v.order==='local'?'Local database':'TACACS+'],['Result',v.order==='local'?(v.local?'Accept':'Reject'):v.server]]),
   event('Decide whether to advance','Only an error from the first method advances this model. A definitive accept or reject stops it.',1,2,localUsed?'Local check':'Local not consulted',[['Local checked',localUsed?'Yes':'No'],['Reason',v.order==='local'?'Local was first':v.server==='error'?'Central error':'Definitive central decision']]),
   event('Open or refuse the session','Authentication is one AAA stage. Command permissions still require authorization.',2,3,accepted?'Authenticated session':'No session',[['Login',accepted?'ACCEPT':'REJECT']])
  ]);}
 },
 {
  id:'cipher-choice',topic:'m15',title:'Protect a payroll file and its integrity',minutes:3,
  story:'A payroll service encrypts files. An observer looks for repeated blocks; another party tries to alter the protected data. Compare the selected mode’s properties.',
  goal:'Hide repeated plaintext patterns, detect tampering, and avoid nonce reuse.',nodes:['Payroll service','Encryption mode','Finance team','Observer / modifier'],
  fields:[option('mode','Protection mode',[['ecb','AES-ECB'],['ctr','AES-CTR without a MAC'],['gcm','AES-GCM']],'ecb'),check('reuse','Reuse a nonce/counter with the same key (mistake)')],fix:{mode:'gcm',reuse:false},refs:refs('src28',23,26),
  terms:[['Block','A fixed-size piece of input processed by a block cipher.'],['Nonce','A per-operation value that must meet the selected mode’s uniqueness requirements.'],['AEAD','Authenticated encryption that protects secrecy and detects unauthorized changes.']],
  limitation:'This is a property model, not an AES implementation. For ECB the nonce switch is not applicable; real GCM decryption must reject a failed authentication tag.',
  run(v){const repeated=v.mode==='ecb',misuse=v.mode!=='ecb'&&v.reuse,auth=v.mode==='gcm'&&!misuse,ok=auth;return result(ok,ok?'Confidentiality and tamper detection configured':'Protection requirement not met',repeated?'Identical plaintext blocks under the same key produce identical ECB ciphertext blocks.':misuse?'Reusing a nonce/counter under one key breaks the security assumptions. GCM reuse can also undermine authentication.':v.mode==='ctr'?'CTR hides patterns with a correctly used counter, but without a MAC it does not reject intentional modifications.':'GCM with correct nonce management protects the content and checks an authentication tag.',[
   event('Look at repeated payroll blocks','Mode choice affects whether equality of blocks becomes visible.',0,1,'Repeated plaintext blocks',[['Mode',v.mode.toUpperCase()],['Equal-block patterns visible',repeated?'Yes':'Not via ECB-style equality under proper use']]),
   event('Check key/nonce use','A secret key does not make nonce reuse safe.',1,2,'Encryption operation',[['Nonce rule',repeated?'Not applicable to ECB':misuse?'Violated · reused with key':'Unique for this key']]),
   event('Receive a modified ciphertext','The receiver must verify authentication before using plaintext.',3,2,'Tampered ciphertext',[['Reliable tamper detection',auth?'Yes · reject failed tag':'Not provided by this configuration'],['Ready for the stated policy',ok?'Yes':'No']])
  ]);}
 },
 {
  id:'certificate-check',topic:'m16',title:'Validate the payroll portal’s identity',minutes:4,
  story:'A browser connects to payroll.example. A certificate may be genuine but expired, issued for another name, revoked, or copied by a server without its private key.',
  goal:'Accept only the valid intended server and reject a failed identity check.',nodes:['Employee browser','Certificate checks','Payroll portal','Impersonating server'],
  fields:[option('certificate','Server evidence',[['wrong-name','Trusted certificate for another hostname'],['expired','Expired certificate'],['untrusted','Untrusted issuer'],['revoked','Certificate known to be revoked'],['no-key','Copied certificate, no matching private key'],['valid','Valid chain, hostname, dates and key proof']],'wrong-name'),check('validate','Enforce all modeled validation checks')],fix:{validate:true},refs:refs('src30',23,35),
  terms:[['SAN','Subject Alternative Name: the hostnames a certificate covers.'],['Trust anchor','A root key the client already trusts.'],['Key possession','The server proves it holds the private key, not just a public certificate file.']],
  limitation:'Simulated validation results, not parsing real certificates. Revocation is explicitly known here; browser behavior for unavailable revocation services varies.',
  run(v){const checks=[['Hostname / SAN',v.certificate!=='wrong-name'],['Validity dates',v.certificate!=='expired'],['Issuer signatures and trusted chain',v.certificate!=='untrusted'],['Known revocation status',v.certificate!=='revoked'],['Matching private-key proof',v.certificate!=='no-key']],valid=checks.every(x=>x[1]),accept=!v.validate||valid;return result(accept===valid,accept?'Connection accepted':'Connection rejected',!v.validate&&!valid?'Skipping identity checks can create an encrypted connection to the wrong party.':valid?'All modeled checks pass. A separate handshake transcript check and authenticated record protection complete the session.':'A single failed required identity check is enough to reject this server.',[
   event('Receive the certificate','A public certificate is evidence to verify; merely receiving it does not establish trust.',2,0,'Certificate + handshake proof',[['Intended hostname','payroll.example'],['Checks enforced',v.validate?'Yes':'No']]),
   event('Evaluate every required check','Separate name, time, trust, revocation and private-key proof. Encryption by itself cannot replace these checks.',0,1,'Verification results',[],['Check','Result'],checks.map(([name,pass])=>[name,pass?'PASS':'FAIL'])),
   event('Make the identity decision','Do not override a failed required identity check to make a warning disappear.',1,valid?2:3,accept?'Connection continues':'Handshake stopped',[['Decision',accept?'ACCEPT':'REJECT'],['Identity actually verified',valid&&v.validate?'Yes':'No']])
  ]);}
 }
 ];
 const byId=id=>cases.find(c=>c.id===id);
 function defaults(id){return Object.fromEntries(byId(id).fields.map(f=>[f.name,f.value]));}
 function run(id,values){const lab=byId(id);if(!lab)throw Error('Unknown real-world lab');const v={...defaults(id),...values};for(const f of lab.fields){if(f.type==='checkbox'){if(typeof v[f.name]!=='boolean')throw Error(`Invalid ${f.name}`);}else if(!f.values.some(([key])=>key===v[f.name]))throw Error(`Invalid ${f.name}`);}return lab.run(v);}
 return {cases,byId,defaults,run};
})();
if(typeof module!=='undefined')module.exports=NSLabs;
