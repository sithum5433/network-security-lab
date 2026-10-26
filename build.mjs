import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {Script} from 'node:vm';
const dir=path.dirname(fileURLToPath(import.meta.url)),root=path.dirname(dir);
// Export only the study content needed by this app, never original Office/PDF binaries.
let data,course;
try {data=JSON.parse(await readFile(path.join(root,'study_build/study-data.json'),'utf8'));}
catch(error){if(error.code!=='ENOENT')throw error;course=JSON.parse(await readFile(path.join(dir,'course.json'),'utf8'));}
if(data) course={modules:Object.fromEntries(data.modules.filter(m=>m.id!=='m01').map(m=>[m.id,{id:m.id,title:m.title,sections:m.sections,quiz:m.quiz,tutorialAnswers:m.tutorialAnswers}])),sources:Object.fromEntries(data.sources.map(s=>[s.id,{filename:s.filename,type:s.type,label:s.filename.replace(/^IE3122_/,'').replace(/_(Slides|Tutorial|Lab)(_1)?\.(pptx|docx)$/,' $1').replaceAll('_',' ')}])),calculationQuestions:{
 m02:[{id:'calc-subnet',prompt:'For 192.168.1.77/26, what is the network address?',options:['192.168.1.64','192.168.1.0','192.168.1.128'],answer:0,explanation:'A /26 has blocks of 64. Address 77 is in the 64–127 block; its network is .64.'}],
 m06:[{id:'calc-stp',prompt:'Direct path costs 19; an indirect path costs 4 + 19. Which wins?',options:['Direct, cost 19','Indirect, because one link is faster','Both must forward'],answer:0,explanation:'Compare summed path costs: 19 < 23.'}],
 m15:[{id:'calc-keys',prompt:'How many unique symmetric pairwise keys do 200 users need?',options:['200','39,800','19,900'],answer:2,explanation:'200 × 199 counts each pair twice; divide by 2 to obtain 19,900.'},{id:'calc-dh',prompt:'For p=13, g=6, a=5 and b=4, what shared DH value results?',options:['2','9','3'],answer:2,explanation:'A=2, B=9; 9^5 mod 13 = 2^4 mod 13 = 3.'},{id:'calc-caesar',prompt:'NETWORK encrypted with Caesar shift +5 is…',options:['SJYBTWP','QHWZRUN','NETWORK'],answer:0,explanation:'N→S, E→J, T→Y, W→B, O→T, R→W, K→P.'}],
 m16:[{id:'calc-hash',prompt:'What is the approximate generic collision work for ideal SHA-256?',options:['2^256','2^128','256 operations'],answer:1,explanation:'The birthday bound gives about 2^(n/2) = 2^128 for any-pair collisions.'}]
}};
if(data) await writeFile(path.join(dir,'course.json'),JSON.stringify(course));
let html=await readFile(path.join(dir,'template.html'),'utf8');
for(const [key,file] of [['CSS','style.css'],['CONTENT','content.js'],['LESSONS','lessons.js'],['LABS','labs.js'],['MATH','math.js'],['CALC','calculators.js'],['LABUI','lab-ui.js'],['APP','app.js']]){
 const content=await readFile(path.join(dir,file),'utf8');
 if(key!=='CSS'&&/<\/script/i.test(content))throw Error(`Unsafe closing script tag in ${file}`);
 if(key!=='CSS')new Script(content,{filename:file});
 html=html.replace(`__${key}__`,()=>content);
}
html=html.replace('__COURSE__',()=>JSON.stringify(course).replace(/</g,'\\u003c'));
if(/__(CSS|COURSE|CONTENT|LESSONS|LABS|MATH|CALC|LABUI|APP)__/.test(html))throw Error('Unresolved template marker.');
await mkdir(path.join(dir,'dist'),{recursive:true});
await writeFile(path.join(dir,'dist/index.html'),html);
if(data) await writeFile(path.join(root,'NS_Simulation_Lab.html'),html);
console.log(`Built self-contained HTML: ${(Buffer.byteLength(html)/1024).toFixed(0)} KiB; ${Object.keys(course.modules).length} lessons; ${Object.values(course.modules).reduce((n,m)=>n+m.tutorialAnswers.length,0)} tutorial/lab answers.`);
