const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const M=require('./math.js');

test('subnet arithmetic handles ordinary, /0, /31 and /32 networks',()=>{
 const r=M.subnet('192.168.1.77',26);
 assert.equal(r.network,'192.168.1.64');assert.equal(r.broadcast,'192.168.1.127');assert.equal(r.hosts,62);assert.equal(r.wildcard,'0.0.0.63');
 assert.equal(M.subnet('255.255.255.255',0).size,4294967296);
 assert.equal(M.subnet('10.0.0.3',31).hosts,2);assert.equal(M.subnet('10.0.0.3',31).first,'10.0.0.2');
 assert.equal(M.subnet('10.0.0.3',32).hosts,1);assert.equal(M.subnet('10.0.0.3',32).first,'10.0.0.3');
 for(const bad of ['10.0.0.256','10.0.0','1..2.3','1e1.0.0.1','-1.0.0.0'])assert.throws(()=>M.subnet(bad,24));
 assert.throws(()=>M.subnet('10.0.0.1',''));assert.throws(()=>M.subnet('10.0.0.1',33));
});
test('wildcard matches bits, including high unsigned IPv4 addresses',()=>{
 assert.ok(M.match('192.168.50.15','192.168.50.0','0.0.0.15'));assert.ok(!M.match('192.168.50.16','192.168.50.0','0.0.0.15'));
 assert.ok(M.match('255.255.255.255','0.0.0.0','255.255.255.255'));
});
test('classical ciphers match tutorial vectors and preserve punctuation',()=>{
 assert.equal(M.caesar('NETWORK',5).result,'SJYBTWP');assert.equal(M.caesar('SJYBTWP',-5).result,'NETWORK');assert.equal(M.caesar('Z!',1).result,'A!');
 assert.equal(M.vigenere('ATTACKATDAWN','LEMON').result,'LXFOPVEFRNHR');assert.equal(M.vigenere('ATTACK AT DAWN','LEMON').result,'LXFOPV EF RNHR');assert.throws(()=>M.vigenere('HELLO',''));
});
test('DH uses exact modular arithmetic and validates toy parameters',()=>{
 const r=M.dh(13,6,5,4);assert.equal(r.A,'2');assert.equal(r.B,'9');assert.equal(r.ka,'3');assert.equal(r.kb,'3');
 assert.throws(()=>M.dh(15,6,5,4));assert.throws(()=>M.dh(13,3,5,4));
 assert.equal(M.dh(23,5,6,15).ka,M.dh(23,5,6,15).kb);
});
test('pairwise keys and XOR cancellation are exact',()=>{
 assert.equal(M.keys(200).pairs,'19900');assert.equal(M.keys(2).pairs,'1');assert.equal(M.keys(1000000).pairs,'499999500000');
 const r=M.xor('01000001','01000010','10101010');assert.equal(r.cx,'00000011');assert.equal(r.recovered,'01000010');assert.throws(()=>M.xor('2','01000010','10101010'));
});
test('STP elects root, sums costs, and blocks exactly one triangle endpoint',()=>{
 const macs=['000000000001','000000000002','000000000003'];const r=M.stp([4096,32768,32768],macs,[19,4,19]);
 assert.equal(r.root,0);assert.deepEqual(r.dist,[0,19,4]);assert.deepEqual(r.rootPort,[null,0,0]);assert.equal(r.roles[2].designated,2);assert.equal(r.roles[2].roles[0],'Alternate / blocking');
 const tie=M.stp([32768,32768,32768],['000000000003','000000000002','000000000001'],[4,4,4]);assert.equal(tie.root,2);
 const indirect=M.stp([4096,32768,32768],macs,[50,4,19]);assert.equal(indirect.dist[1],23);assert.equal(indirect.rootPort[1],2);
 for(let ab=1;ab<=6;ab++)for(let ac=1;ac<=6;ac++)for(let bc=1;bc<=6;bc++){
  const t=M.stp([4096,32768,32768],macs,[ab,ac,bc]);assert.equal(t.roles.flatMap(e=>e.roles).filter(x=>x.includes('blocking')).length,1);
 }
 assert.throws(()=>M.stp([4097,32768,32768],macs,[19,4,19]));
});
test('CAM and SYN models preserve capacity and distinguish the defences',()=>{
 assert.equal(M.cam(30,16,2,false).occupied,16);assert.equal(M.cam(30,16,2,true).occupied,4);assert.ok(M.cam(30,16,16,true).occupied<=16);
 assert.equal(M.syn(40,16,5,false).admitted,0);assert.equal(M.syn(40,16,5,true).admitted,5);assert.equal(M.syn(2,16,5,false).admitted,5);
});
test('amplification and OSPF costs show explicit arithmetic',()=>{
 const r=M.amplification(64,512,10,1000);assert.equal(r.factor,80);assert.equal(r.input,.512);assert.equal(r.output,40.96);
 assert.deepEqual(M.ospf(100,'100,1000,10').costs,[1,1,10]);assert.equal(M.ospf(100,'100,1000,10').total,12);
});
test('RPKI distinguishes invalid origin, excessive length and no ROA',()=>{
 let r=M.routing('208.65.153.20',17557,24,24,true);assert.equal(r.selected.as,17557);assert.equal(r.status,'Invalid');assert.equal(r.protectedSelected.as,36561);
 assert.equal(M.routing('208.65.153.20',36561,24,24,true).status,'Valid');assert.equal(M.routing('208.65.153.20',36561,22,24,true).status,'Invalid');assert.equal(M.routing('208.65.153.20',17557,24,24,false).status,'NotFound');
 assert.equal(M.routing('1.1.1.1',17557,24,24,true).selected,null);
});
test('ACL first-match, implicit deny, and ACK/RST flag semantics',()=>{
 const packet={source:'10.10.30.8',destination:'172.16.5.10',protocol:'tcp',port:23,ack:false};
 assert.equal(M.acl('telnet',packet).decision,'deny');assert.equal(M.acl('telnet',{...packet,port:443}).decision,'permit');assert.equal(M.acl('telnet',packet,true).decision,'permit');
 assert.equal(M.acl('management',{...packet,source:'192.168.50.15'}).decision,'permit');assert.equal(M.acl('management',{...packet,source:'192.168.50.16'}).decision,'deny');
 const reply={...packet,source:'192.168.77.8',destination:'10.1.1.100',port:443};assert.equal(M.acl('established',reply).decision,'deny');assert.equal(M.acl('established',{...reply,ack:true}).decision,'permit');
});
test('AAA fallback never turns an explicit central reject into local success',()=>{
 assert.equal(M.fallback('reject',true).decision,'REJECT');assert.equal(M.fallback('error',true).decision,'ACCEPT');assert.equal(M.fallback('error',false).decision,'REJECT');assert.equal(M.fallback('accept',false).decision,'ACCEPT');assert.equal(M.fallback('accept',false,'local-first').decision,'REJECT');
});
test('every lesson has complete, uniquely identified simulations and valid quiz options',()=>{
 const ctx=vm.createContext({});vm.runInContext(fs.readFileSync(__dirname+'/content.js','utf8')+'\n'+fs.readFileSync(__dirname+'/lessons.js','utf8')+';globalThis.result={TOPICS,SCENARIOS,CALCULATORS}',ctx);const {TOPICS,SCENARIOS,CALCULATORS}=ctx.result;
 assert.equal(TOPICS.length,15);assert.equal(CALCULATORS.length,16);assert.equal(new Set(SCENARIOS.map(s=>s.id)).size,SCENARIOS.length);
 for(const t of TOPICS)assert.ok(SCENARIOS.some(s=>s.topic===t.id),t.id);
 for(const s of SCENARIOS){assert.equal(s.labels.length,4);assert.ok(s.attack.length>=3&&s.protected.length>=3);assert.ok(s.hook&&s.weak&&s.defence&&s.limit);assert.ok(Number.isInteger(s.quiz.answer)&&s.quiz.answer<s.quiz.options.length);for(const step of [...s.attack,...s.protected]){assert.ok(step.from>=0&&step.from<4&&step.to>=0&&step.to<4);assert.ok(step.title&&step.text)}}
 console.log(`Content checked: ${SCENARIOS.length} walkthroughs across ${TOPICS.length} lessons.`);
});
