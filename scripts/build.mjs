import {readFile,writeFile,copyFile,mkdir} from 'node:fs/promises';
const root=new URL('../',import.meta.url);
const file=path=>new URL(path,root);
const fixture=JSON.parse(await readFile(file('xdr/fixtures/known-cve.json'),'utf8'));
const result=JSON.parse(await readFile(file('xdr/known-cve/result.json'),'utf8'));
const denied=JSON.parse(await readFile(file('xdr/temporary-deny.json'),'utf8'));
if(fixture.schema!=='aleph.xdr.fixture.v1'||fixture.moduleKey!=='known-cve'
  ||!Array.isArray(fixture.alerts)||fixture.alerts.length!==24)
  throw new Error('Official known-cve fixture contract mismatch');
if(result.schema!=='aleph.xdr.result.v1'||result.moduleKey!=='known-cve'
  ||!Array.isArray(result.decisions)||result.decisions.length!==fixture.alerts.length)
  throw new Error('Official known-cve results missing or incomplete');
if(!Array.isArray(denied)||denied.length!==result.counts.block)
  throw new Error('Temporary deny policy does not match decisions');
const samples=fixture.alerts.map(alert=>({
  id:alert.id,timestamp:alert.timestamp,
  rule:{level:alert.rule.level,mitre:alert.rule.mitre,description:alert.rule.description},
  data:{srcip:alert.data.srcip,srcuser:alert.data.srcuser??'',
    url:alert.data.url??'',useragent:alert.data.useragent??'',count:alert.data.count??null}
}));
const rows=result.decisions.map((answer,index)=>{
  const event=samples[index];
  if(answer.alertId!==event.id)throw new Error('Decision ID order mismatch');
  return {
    alertId:answer.alertId,action:answer.action,confidence:answer.confidence,reason:answer.reason,
    description:event.rule.description,source:event.data.srcip,level:event.rule.level,
    attempts:event.data.count,normal:!event.rule.mitre.includes('T1190')&&event.rule.level<=3
  };
});
const report={
  schema:'aleph.xdr.result.v1',moduleKey:'known-cve',
  generatedAt:'2026-10-13T00:00:00.000Z',counts:result.counts,
  fixtureCount:fixture.alerts.length,normalBlocked:rows.filter(x=>x.normal&&x.action==='block').length,
  temporaryDenyRules:denied.map(x=>({id:x.id,source:x.source,alertId:x.alertId,expiresAt:x.expiresAt})),
  results:rows
};
if(report.normalBlocked)throw new Error('Normal event was blocked');
await mkdir(file('public/'),{recursive:true});
await writeFile(file('public/report.json'),JSON.stringify(report,null,2)+'\n');
await writeFile(file('public/samples.json'),JSON.stringify({alerts:samples},null,2)+'\n');
for(const [from,to] of [
  ['index.html','public/index.html'],
  ['styles.css','public/styles.css'],
  ['app.js','public/app.js'],
  ['xdr/known-cve/decide.mjs','public/decide.mjs']
])await copyFile(file(from),file(to));
console.log(JSON.stringify({siteReady:true,fixtureCount:report.fixtureCount,
  counts:report.counts,normalBlocked:report.normalBlocked}));
