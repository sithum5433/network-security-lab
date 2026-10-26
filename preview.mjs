import http from 'node:http';
import {readFile} from 'node:fs/promises';
const port=Number(process.env.PORT||4173);
const file=new URL('./dist/index.html',import.meta.url);
const server=http.createServer(async(req,res)=>{
 if(!['GET','HEAD'].includes(req.method)){res.writeHead(405);res.end();return;}
 if(!['/','/index.html'].includes(new URL(req.url,'http://localhost').pathname)){res.writeHead(404);res.end('Not found');return;}
 try{const body=await readFile(file);res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});res.end(req.method==='HEAD'?undefined:body);}
 catch{res.writeHead(503);res.end('Build first: node build.mjs');}
});
server.listen(port,'127.0.0.1',()=>console.log(`Network Security Lab: http://127.0.0.1:${port}`));
