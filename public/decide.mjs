// XDR-03 | CVE-2021-44228 (Log4Shell) | MITRE ATT&CK T1190
// Standalone judge contract: no imports, no filesystem, no network, no side effects.
// Constants mirror xdr/known-cve/patterns.json (no runtime access to that file).
const PATTERNS = Object.freeze({
  lookup: 'T1190-Log4Shell-JNDI-Remote-Lookup',
  repeated: 'T1190-Log4Shell-Multi-Surface',
  scanner: 'T1190-Known-CVE-Scanner-Signal',
  mention: 'T1190-CVE-Reference-Only',
  normal: 'T1190-Normal-Web-Access'
});
const asObject = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const asString = value => typeof value === 'string' ? value : '';
const first = (...values) => values.find(v => v !== undefined && v !== null && v !== '') ?? null;
function parseNumber(value) {
  if (typeof value === 'number') return Number.isFinite(value) && value >= 0 && value <= 1e6 ? value : null;
  if (typeof value === 'string' && /^\s*\d+(?:\.\d+)?\s*$/.test(value)) {
    const n = Number(value);
    return n <= 1e6 ? n : null;
  }
  return null;
}
function validSource(value) {
  if(typeof value !== 'string') return false;
  const source=value.trim();
  if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(source))return source.split('.').every(part => Number(part) <= 255);
  return source.includes(':') && /^[0-9a-f:]{2,45}$/i.test(source);
}
function normalize(value) {
  let normalized=asString(value).slice(0,8192);
  for(let i=0;i<3;i++) {
    try {
      const decoded=decodeURIComponent(normalized.replace(/\+/g,' '));
      if(decoded===normalized)break;
      normalized=decoded;
    }catch {break;}
  }
  normalized=normalized.toLowerCase()
    .replace(/[$][{]\s*(?:lower|upper):([a-z])\s*[}]/g,'$1')
    .replace(/\\u0024/gi,'$').replace(/\\u007b/gi,'{').replace(/\\u007d/gi,'}');
  return normalized;
}
function hasRemoteLookup(raw) {
  // Match a complete lookup directive + known JNDI remote scheme.
  // Strings are ONLY inspected; this module never evaluates or fetches them.
  const input=normalize(raw);
  return /[$][{]\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop)\s*:\s*[/][/][^\s}]{1,200}[}]/i.test(input);
}
function collect(alert) {
  const a=asObject(alert), d=asObject(a.data), req=asObject(a.request), embedded=asObject(d.request);
  const rule=asObject(a.rule), headers=asObject(d.headers), reqHeaders=asObject(req.headers);
  const nestedHeaders=asObject(embedded.headers);
  const desc=[asString(rule.description),asString(a.description),asString(d.description)].join(' ').toLowerCase();
  const locations=[
    d.url,d.uri,d.request_uri,d.requestUri,d.query,d.args,d.useragent,d.user_agent,d.userAgent,
    d.referer,d.referrer,d.cookie,d.payload,d.request_line,
    req.url,req.uri,req.query,req.path,
    embedded.url,embedded.uri,embedded.query,
    a.url,a.uri,a.query,a.full_log,d.full_log,
    ...Object.values(headers),...Object.values(reqHeaders),...Object.values(nestedHeaders)
  ].filter(value => typeof value === 'string');
  const present=locations.filter(hasRemoteLookup).length;
  const source=first(d.srcip,d.src_ip,d.source_ip,d.client_ip,d.remote_addr,
    a.srcip,a.src_ip,a.source_ip,a.client_ip,asObject(a.source).ip);
  const level=parseNumber(first(rule.level,a.rule_level,a.level,d.level)) ?? 0;
  const count=parseNumber(first(d.count,d.frequency,d.attemptCount,d.request_count,
    a.count,a.frequency,rule.frequency)) ?? 0;
  const mitre=Array.isArray(rule.mitre) && rule.mitre.some(v =>
    v === 'T1190' || (v && typeof v === 'object' && v.id === 'T1190'));
  const clearDescription=/cve[- ]2021[- ]44228|log4shell|원격\s*조회|jndi/.test(desc);
  const scanner=/점검\s*도구|스캐너|scanner|vulnerability\s*scan|probe|점검\s*흔적/.test(desc);
  const mention=/cve[- ]2021[- ]44228|jndi|log4j|취약점|lookup|조회\s*형태|머리글/.test(desc)
    || locations.some(value => /\bcve-2021-44228\b|\bjndi\b|\blog4j\b/i.test(value));
  return {present,sourceOk:validSource(source),level,count,mitre,clearDescription,scanner,mention};
}
export function decide(alert) {
  const e=collect(alert);
  const reply=(confidence,reason)=>({
    action: confidence >= .85 ? 'block' : confidence >= .5 ? 'alert' : 'record',
    confidence, reason
  });
  // A full remote lookup is strong evidence even in a single request. Repetition
  // increases confidence, but is not a mandatory condition for Log4Shell.
  const confirmed=e.present>0 && e.sourceOk && e.level>=10 && (e.mitre || e.clearDescription);
  if(confirmed)return reply(e.present>=2 || e.count>=4 ? .99 : .97,
    e.present>=2 || e.count>=4 ? PATTERNS.repeated : PATTERNS.lookup);
  // A payload without corroboration, a scanner hint or a CVE name mentioned in
  // educational content cannot create a blocking rule.
  if(e.present>0)return reply(.72,PATTERNS.lookup);
  if(e.scanner && (e.mitre || e.level>=5))return reply(.63,PATTERNS.scanner);
  if((e.mitre && e.level>=5) || (e.mention && e.level>=5))
    return reply(.56,PATTERNS.mention);
  return reply(.07,PATTERNS.normal);
}
