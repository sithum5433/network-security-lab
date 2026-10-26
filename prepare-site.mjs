// Stage this standalone project for Sites without copying original lecture files.
import {cp,mkdir,readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const source=path.dirname(fileURLToPath(import.meta.url));
const target=path.resolve(source,'../sites/network-security-lab');
const manifest=JSON.parse(await readFile(path.join(target,'.openai/hosting.json'),'utf8'));
if(!manifest.project_id||manifest.static?.directory!=='dist')throw Error('Register the Site before staging it.');
await mkdir(target,{recursive:true});
for(const file of ['app.js','build.mjs','calculators.js','content.js','course.json','labs.js','lab-ui.js','lessons.js','math.js','math.test.cjs','labs.test.cjs','style.css','template.html','preview.mjs','README.md','.gitignore','.github','dist','qa/real-world-report.json']){
 await cp(path.join(source,file),path.join(target,file),{recursive:true});
}
console.log('Staged the standalone Site source and build.');
