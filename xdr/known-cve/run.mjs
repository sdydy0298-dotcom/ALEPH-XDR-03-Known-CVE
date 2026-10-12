import {readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {runXdr} from '../../scripts/xdr-run.mjs';
import {respond} from './respond.mjs';
import {evaluateAccess} from '../../ztna/evaluate.mjs';
if(process.argv[2]!=='known-cve')throw new Error('Usage: npm run xdr:run -- known-cve');
const fixed=new Date('2026-10-13T00:00:00.000Z');
const origin=new URL('../fixtures/known-cve.json',import.meta.url);
const fixture=JSON.parse(await readFile(origin,'utf8'));
const root=fileURLToPath(new URL('../../',import.meta.url));
const report=await runXdr({root,moduleKey:'known-cve'});
const logFile=new URL('../alerts.log',import.meta.url);
const denyFile=new URL('../temporary-deny.json',import.meta.url);
await writeFile(logFile,'');
await writeFile(denyFile,'[]\n');
for(let index=0;index<fixture.alerts.length;index++){
  const item=fixture.alerts[index], decision=report.decisions[index];
  if(item.id!==decision.alertId)throw new Error('Alert ID order mismatch');
  await respond(item,decision,{now:fixed,persist:true});
}
const rules=JSON.parse(await readFile(denyFile,'utf8'));
const lines=(await readFile(logFile,'utf8')).trim().split('\n').filter(Boolean);
if(rules.length!==report.counts.block || lines.length!==(report.counts.block+report.counts.alert))
  throw new Error('Saved notification and dynamic deny counts are inconsistent');
let normalBlocked=0;
for(let i=0;i<fixture.alerts.length;i++){
  const item=fixture.alerts[i],decision=report.decisions[i];
  const access=await evaluateAccess(item.data.srcip,fixed.getTime());
  const ordinary=!(item.rule.mitre??[]).includes('T1190') && item.rule.level<=3;
  if(ordinary && (decision.action==='block'||access.action==='deny'))normalBlocked++;
  if(decision.action==='block' && access.action!=='deny')
    throw new Error('No ZTNA deny rule for '+item.id);
  if(decision.action==='block' &&
     (await evaluateAccess(item.data.srcip,fixed.getTime()+16*60000)).action!=='allow')
    throw new Error('Expired ZTNA rule still blocks '+item.id);
}
if(normalBlocked)throw new Error('An ordinary web request was incorrectly denied');
console.log(JSON.stringify({schema:report.schema,counts:report.counts,
  total:report.decisions.length,normalBlocked,alertsLogged:lines.length,
  temporaryDenyRules:rules.length}));
