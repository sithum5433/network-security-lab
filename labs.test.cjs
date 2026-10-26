const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const L=require('./labs.js');
const run=(id,changes)=>L.run(id,{...L.defaults(id),...changes});
test('every lesson has a complete lab and a successful comparison',()=>{
 const ctx=vm.createContext({});
 vm.runInContext(fs.readFileSync(__dirname+'/content.js','utf8')+'\n'+fs.readFileSync(__dirname+'/lessons.js','utf8')+';globalThis.catalog={TOPICS,SCENARIOS};',ctx);
 assert.equal(L.cases.length,15);
 assert.equal(new Set(L.cases.map(c=>c.id)).size,L.cases.length);
 for(const topic of ctx.catalog.TOPICS)assert.ok(L.cases.some(c=>c.topic===topic.id));
 assert.equal(ctx.catalog.SCENARIOS.length,73);
 for(const lab of L.cases){
  const r=run(lab.id,lab.fix);assert.ok(r.ok,lab.id);assert.ok(lab.refs.length);
  for(const e of r.events){assert.ok(e.title&&e.why&&e.packet);assert.ok(e.from>=0&&e.from<lab.nodes.length);assert.ok(e.to>=0&&e.to<lab.nodes.length);}
 }
});
test('local first hop matters for both address families and services',()=>{
 for(const family of ['v4','v6'])for(const service of ['https','dns']){
  assert.equal(run('packet-trip',{family,service,nextHop:'server'}).ok,false);
  assert.equal(run('packet-trip',{family,service,nextHop:'gateway'}).ok,true);
 }
});
test('DAI must preserve valid users, not merely drop everything',()=>{
 const config={snooping:true,dai:true,trustedUser:false};
 assert.equal(run('switch-trust',config).ok,true);
 assert.equal(run('switch-trust',{...config,binding:'missing'}).ok,false);
 assert.equal(run('switch-trust',{...config,binding:'static'}).ok,true);
 assert.equal(run('switch-trust',{...config,trustedUser:true}).ok,false);
 assert.equal(run('switch-trust',{...config,snooping:false}).ok,false);
});
test('guard choice depends on trigger and port role',()=>{
 for(const [incident,guard] of [['edge','bpdu'],['root','root'],['loss','loop']]){
  for(const candidate of ['none','bpdu','root','loop'])assert.equal(run('stp-incident',{incident,guard:candidate}).ok,candidate===guard);
 }
});
test('source filter and stateful firewall allow real traffic as well as rejecting forged traffic',()=>{
 assert.ok(run('source-check',{source:'real',filter:true}).ok);
 assert.ok(run('source-check',{source:'forged',filter:true}).ok);
 assert.equal(run('source-check',{source:'forged',filter:false}).ok,false);
 for(const traffic of ['forged','reply'])assert.ok(run('firewall-return',{mode:'state',traffic}).ok);
 assert.equal(run('firewall-return',{mode:'flags',traffic:'forged'}).ok,false);
});
test('a missing ROA is not equivalent to a rejected invalid route',()=>{
 assert.ok(run('routing-incident',{roa:true,enforce:true}).ok);
 assert.equal(run('routing-incident',{roa:false,enforce:true}).ok,false);
 assert.equal(run('routing-incident',{roa:true,enforce:false}).ok,false);
});
test('ACL direction, first match and implicit deny affect different traffic',()=>{
 for(const placement of ['in','server'])for(const service of ['telnet','https'])assert.ok(run('acl-placement',{placement,service,order:'specific'}).ok);
 assert.equal(run('acl-placement',{placement:'out'}).ok,false);
 assert.equal(run('acl-placement',{placement:'in',order:'broad'}).ok,false);
 assert.equal(run('acl-placement',{placement:'in',order:'missing',service:'https'}).ok,false);
});
test('IPsec confidentiality requires encryption, appropriate mode and authentication',()=>{
 for(const protection of ['ah','esp'])for(const mode of ['transport','tunnel'])for(const auth of [true,false])assert.equal(run('ipsec-envelope',{protection,mode,auth}).ok,protection==='esp'&&mode==='tunnel'&&auth);
});
test('AAA reject never falls through to valid emergency credentials',()=>{
 assert.equal(run('aaa-outage',{server:'reject',local:true}).headline,'Login rejected');
 assert.equal(run('aaa-outage',{server:'error',local:true}).headline,'Login accepted');
 assert.equal(run('aaa-outage',{server:'accept',order:'local',local:false}).headline,'Login rejected');
 assert.equal(run('aaa-permission',{factors:'two-passwords',authorize:true,account:true}).ok,false);
});
test('nonce reuse and omitted identity checks cannot satisfy the protection goals',()=>{
 assert.ok(run('cipher-choice',{mode:'gcm',reuse:false}).ok);
 assert.equal(run('cipher-choice',{mode:'gcm',reuse:true}).ok,false);
 for(const certificate of ['wrong-name','expired','untrusted','revoked','no-key']){
  assert.equal(run('certificate-check',{certificate,validate:false}).ok,false);
  assert.equal(run('certificate-check',{certificate,validate:true}).headline,'Connection rejected');
 }
 assert.equal(run('certificate-check',{certificate:'valid',validate:true}).headline,'Connection accepted');
});
