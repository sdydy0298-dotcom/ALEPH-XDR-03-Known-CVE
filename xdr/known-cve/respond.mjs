import {appendFile,mkdir,readFile,writeFile} from 'node:fs/promises';
import {dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {isIP} from 'node:net';
import {decide} from './decide.mjs';
import {checkAccess} from '../../ztna/check.mjs';
const denyFile=new URL('../temporary-deny.json',import.meta.url);
const alertsFile=new URL('../alerts.log',import.meta.url);
const safeId=value=>/^[A-Za-z0-9_.:-]{1,96}$/.test(String(value??''))?String(value):null;
const safeIp=value=>typeof value==='string' && isIP(value.trim())?value.trim():null;
async function load() {
  try{
    const result=JSON.parse(await readFile(denyFile,'utf8'));
    if(!Array.isArray(result))throw new Error('Malformed deny policy');
    return result;
  }catch(error){if(error.code==='ENOENT')return [];throw error;}
}
export async function respond(alert,verdict,{now=new Date(),persist=true}={}) {
  if(!verdict || !['block','alert','record'].includes(verdict.action)
      || !Number.isFinite(verdict.confidence) || verdict.confidence<0 || verdict.confidence>1)
    throw new TypeError('Invalid XDR decision');
  if(!(now instanceof Date) || Number.isNaN(now.getTime()))throw new TypeError('Invalid clock');
  const data=alert?.data??{}, id=safeId(alert?.id??alert?.alertId);
  const source=safeIp(data.srcip??data.src_ip??data.source_ip??alert?.srcip??alert?.source_ip);
  const current=(persist?await load():[]).filter(rule=>
    rule?.action==='deny' && Number.isFinite(Date.parse(rule.expiresAt))
    && Date.parse(rule.expiresAt)>now.getTime());
  const checked=decide(alert);
  if(verdict.action==='block' && verdict.confidence>=.85 && checked.action==='block'
    && source && id) {
    const rule={id:'xdr03-'+id,action:'deny',source,alertId:id,
      reason:checked.reason,createdAt:now.toISOString(),
      expiresAt:new Date(now.getTime()+15*60*1000).toISOString()};
    if(!current.some(existing=>existing.id===rule.id))current.push(rule);
  }
  const notification={alertId:id??'unknown',action:checked.action,
    confidence:checked.confidence,reason:checked.reason,at:now.toISOString()};
  if(persist){
    await mkdir(dirname(fileURLToPath(denyFile)),{recursive:true});
    await writeFile(denyFile,JSON.stringify(current,null,2)+'\n');
    if(checked.action!=='record')
      await appendFile(alertsFile,JSON.stringify(notification)+'\n');
  }
  return {notification:checked.action==='record'?null:notification,
    rules:current,access:source?checkAccess(source,current,now.getTime()):
      {action:'allow',reason:'유효한 출발 IP 없음'}};
}
