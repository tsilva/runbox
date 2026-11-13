import fs from 'node:fs';
import {syncBuiltinESMExports} from 'node:module';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';

const MARKER='sentry_read_public_placeholder';
function installSession(value) {
 const env=process.env;
 const project=value.profile.environment.SENTRY_PROJECT;
 const organization=value.profile.environment.SENTRY_ORG;
 if(!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(project)||!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(organization))throw new Error('Invalid project binding');
 const base='https://sentry.io';
 const proxies=['HTTP_PROXY','HTTPS_PROXY'].map(k=>new URL(env[k]));
 if(env.SENTRY_VAULT_TRANSPORT!=='agent-vault'||env.SENTRY_AUTH_TOKEN!==MARKER||env.SENTRY_ORG!==organization||env.SENTRY_PROJECT!==project
  ||env.SENTRY_BASE_URL!==base||env.NO_PROXY||env.no_proxy||env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||env.NODE_USE_ENV_PROXY!=='1'
  ||proxies[0].href!==proxies[1].href||proxies.some(p=>p.protocol!=='http:'||p.host!==value.profile.session.proxy||!p.username||!p.password)
  ||['http_proxy','https_proxy'].some(k=>env[k]&&new URL(env[k]).href!==proxies[0].href))throw new Error('Expected reviewed session');
 const prefix=`/api/0/projects/${organization}/${project}/`;
 const original=globalThis.fetch; let projectId;
 const exists=fs.existsSync.bind(fs);
 fs.existsSync=file=>/(^|\/)[.]env(?:$|[.\/])/.test(String(file))?false:exists(file);
 syncBuiltinESMExports();
 globalThis.fetch=async(input,init)=>{
  const url=new URL(typeof input==='string'||input instanceof URL?input:input.url);
  const headers=new Headers(init?.headers??input.headers);
  if(url.origin!==base||url.username||url.password||url.hash||(init?.method??input.method??'GET')!=='GET'
    ||headers.get('Authorization')!==`Bearer ${MARKER}`||['cookie','api-key','x-api-key'].some(k=>headers.has(k)))throw new Error('Unreviewed request');
  let array=false;
  if(url.pathname===`/api/0/organizations/${organization}/projects/`&&!url.search){url.pathname=prefix;array=true;}
  else if(url.pathname===`/api/0/organizations/${organization}/issues/`){
   if(!projectId||url.searchParams.getAll('project').length!==1||url.searchParams.get('project')!==projectId)throw new Error('Project filter mismatch');
   url.pathname=prefix+'issues/';url.searchParams.delete('project');
  }
  if(![prefix,prefix+'issues/'].includes(url.pathname)||[...url.searchParams.keys()].some(k=>!['limit','query','statsPeriod','cursor','sort'].includes(k))
   ||(url.pathname===prefix&&url.search)||[...url.searchParams.keys()].some(k=>url.searchParams.getAll(k).length!==1)
   ||(url.searchParams.has('limit')&&(!/^[0-9]{1,3}$/.test(url.searchParams.get('limit'))||Number(url.searchParams.get('limit'))<1||Number(url.searchParams.get('limit'))>100)))throw new Error('Unreviewed endpoint');
  let response;
  try{response=await original(url,{...init,method:'GET',headers,redirect:'error',signal:AbortSignal.timeout(20000)});}
  catch{throw new Error('Transport failed');}
  if(!response.ok){await response.body?.cancel();return Response.json({error:'Sentry request rejected; details withheld'},{status:response.status});}
  if(url.pathname===prefix){
   const item=await response.json();if(item.slug!==project||!/^\d+$/.test(String(item.id)))throw new Error('Unexpected project binding');
   projectId=String(item.id);const safe={id:projectId,slug:project,name:typeof item.name==='string'?item.name:project};
   return Response.json(array?[safe]:safe);
  }
  return response;
 };
 return prefix;
}
try {
 const value=JSON.parse(Buffer.from(process.env.RUNBOX_POLICY,'base64url').toString());
 const prefix=installSession(value);const mode=process.argv[2];
 if(mode==='check'&&process.argv.length===3) {
  const response=await fetch('https://sentry.io'+prefix,{headers:{Authorization:`Bearer ${MARKER}`}});
  if(!response.ok)throw new Error();await response.body?.cancel();
  console.log(JSON.stringify({ok:true,read_only:true,credential_mode:'public-placeholder'}));
 } else if(mode==='issues') {
  if(process.argv.slice(3).some(arg=>arg==='--env-file'||arg.startsWith('--env-file=')))throw new Error('Environment-file overrides are unsupported');
  const relative=value.profile.environment.SENTRY_READER_SCRIPT??'scripts/sentry-issues.mjs';
  if(relative.startsWith('/')||relative.split('/').some(part=>!part||part==='.'||part==='..')
    ||!value.profile.execution.integrity.files.includes(relative))throw new Error('Unreviewed reader entrypoint');
  const script=join(value.root,relative);
  process.argv=[process.execPath,script,...process.argv.slice(3)];
  await import(pathToFileURL(script).href);
 } else throw new Error();
} catch { console.error('Sentry reader failed; private diagnostics withheld.');process.exitCode=1; }
