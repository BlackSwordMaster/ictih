/* ICTIH static simulator: all information remains in this browser's localStorage. */
const STORAGE_KEY = 'ictih-security-events-v1';
const eventTypes = {
  'Port scan': { target: '/network-gateway', severity: 'Low', category: 'Port scan', weight: 5 },
  'Failed login': { target: '/customer/login', severity: 'Medium', category: 'Failed authentication', weight: 10 },
  'Weak credential attempt': { target: '/admin/login', severity: 'High', category: 'Failed authentication', weight: 10 },
  'SQL injection attempt': { target: '/claims/search', severity: 'High', category: 'SQL injection', weight: 20 },
  'Directory/file enumeration': { target: '/documents/', severity: 'Medium', category: 'Port scan', weight: 5 },
  'Privilege escalation attempt': { target: '/admin/users', severity: 'Critical', category: 'Privilege escalation', weight: 25 },
  'Suspicious database query': { target: '/api/policies', severity: 'High', category: 'SQL injection', weight: 20 },
  'Sensitive-data access': { target: '/customer/records', severity: 'High', category: 'Sensitive data access', weight: 20 },
  'Data-exfiltration simulation': { target: '/export/policies', severity: 'Critical', category: 'Data exfiltration', weight: 20 }
};
let events = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
const $ = id => document.getElementById(id);
const escapeHtml = value => String(value || '—').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
function save() { localStorage.setItem(STORAGE_KEY, JSON.stringify(events)); }
function showToast(text) { const t = $('toast'); t.textContent = text; t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 2400); }
function formatTime(value) { return new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }); }
function simulate(name) {
  const info = eventTypes[name], ip = $('sourceIp').value.trim() || '192.0.2.105', user = $('username').value.trim();
  events.unshift({ id: crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(), timestamp: new Date().toISOString(), sourceIp: ip, target: info.target, username: user, eventType: name, category: info.category, severity: info.severity, detected: true, riskWeight: info.weight, simulation: true });
  save(); render(); showToast(`${name} recorded locally.`);
}
function riskScore() { return Math.min(100, Math.round(events.reduce((sum, event) => sum + event.riskWeight, 0) / 2)); }
function level(score) { return score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'ELEVATED' : 'LOW'; }
function render() {
  const total = events.length, detected = events.filter(e => e.detected).length, high = events.filter(e => ['High','Critical'].includes(e.severity)).length, score = riskScore();
  $('totalEvents').textContent = total; $('detectedEvents').textContent = detected; $('highEvents').textContent = high; $('lastEvent').textContent = total ? formatTime(events[0].timestamp).split(',')[1].trim() : '—';
  $('riskScore').textContent = score; $('riskLevel').textContent = level(score); $('riskPill').style.background = score >= 75 ? '#8c1d18' : score >= 50 ? '#9a4b05' : '#062f4f';
  $('eventCount').textContent = total ? `${total} synthetic event${total === 1 ? '' : 's'} stored in this browser.` : 'No events recorded.';
  $('eventRows').innerHTML = events.length ? events.map(e => `<tr><td>${formatTime(e.timestamp)}</td><td>${escapeHtml(e.sourceIp)}</td><td>${escapeHtml(e.eventType)}</td><td>${escapeHtml(e.target)}</td><td>${escapeHtml(e.username)}</td><td><span class="severity ${e.severity}">${e.severity}</span></td><td><span class="detected">Yes</span></td></tr>`).join('') : '<tr><td colspan="7" style="text-align:center;color:#64748b;padding:25px">Run a safe simulation to begin collecting events.</td></tr>';
  drawChart(); drawSeverity();
}
function drawChart() {
  const canvas = $('typeChart'), ctx = canvas.getContext('2d'), counts = {};
  Object.keys(eventTypes).forEach(k => counts[k] = 0); events.forEach(e => counts[e.eventType] = (counts[e.eventType] || 0) + 1);
  const entries = Object.entries(counts).filter(([,n]) => n).slice(0, 6); ctx.clearRect(0,0,canvas.width,canvas.height);
  if (!entries.length) { ctx.fillStyle='#64748b'; ctx.font='14px system-ui'; ctx.fillText('No events to chart yet', 175, 105); return; }
  const max = Math.max(...entries.map(([,n])=>n)); entries.forEach(([name,n],i) => { const y=18+i*32, w=(n/max)*260; ctx.fillStyle='#e6eef6'; ctx.fillRect(155,y,270,17); ctx.fillStyle='#0969da'; ctx.fillRect(155,y,w,17); ctx.fillStyle='#334e68'; ctx.font='11px system-ui'; ctx.fillText(name.length>22?name.slice(0,21)+'…':name,0,y+13); ctx.fillStyle='#fff'; ctx.fillText(n,160,y+13); });
}
function drawSeverity() { const levels=['Low','Medium','High','Critical'], max=Math.max(1,...levels.map(l=>events.filter(e=>e.severity===l).length)); $('severityBars').innerHTML=levels.map(l=>{const n=events.filter(e=>e.severity===l).length;return `<div class="severity-row ${l.toLowerCase()}"><span>${l}</span><div class="bar-bg"><div class="bar" style="width:${n/max*100}%"></div></div><b>${n}</b></div>`}).join(''); }
function download(kind) { const csvHeaders=['timestamp','sourceIp','target','username','eventType','category','severity','detected','riskWeight','simulation']; let blob, filename;
  if(kind==='csv') { const rows=[csvHeaders.join(','),...events.map(e=>csvHeaders.map(h=>`"${String(e[h] ?? '').replaceAll('"','""')}"`).join(','))]; blob=new Blob([rows.join('\n')],{type:'text/csv'}); filename='ictih-security-events.csv'; }
  else { blob=new Blob([JSON.stringify(events,null,2)],{type:'application/json'}); filename='ictih-security-events.json'; }
  const url=URL.createObjectURL(blob), a=document.createElement('a');a.href=url;a.download=filename;a.click();URL.revokeObjectURL(url);showToast(`${filename} downloaded.`);
}
function loadDemo() { if(events.length && !confirm('Add demonstration data to the current local event log?')) return; const names=['Port scan','Failed login','Weak credential attempt','SQL injection attempt','Directory/file enumeration','Privilege escalation attempt','Sensitive-data access','Data-exfiltration simulation']; names.forEach((name,i)=>{const d=eventTypes[name];events.push({id:`demo-${Date.now()}-${i}`,timestamp:new Date(Date.now()-i*3600000).toISOString(),sourceIp:`192.0.2.${105+i}`,target:d.target,username:i%2?'unknown':'demo-user',eventType:name,category:d.category,severity:d.severity,detected:true,riskWeight:d.weight,simulation:true});});events.sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp));save();render();showToast('Demonstration data loaded locally.'); }
Object.keys(eventTypes).forEach(name=>{const button=document.createElement('button');button.textContent=name;button.addEventListener('click',()=>simulate(name));$('simButtons').append(button);});
$('loadDemo').addEventListener('click',loadDemo); $('resetData').addEventListener('click',()=>{if(confirm('Remove all locally stored ICTIH event data from this browser?')){events=[];save();render();showToast('Local event data reset.');}}); $('exportCsv').addEventListener('click',()=>download('csv')); $('exportJson').addEventListener('click',()=>download('json')); $('demoLogin').addEventListener('click',()=>showToast('Demo sign-in complete. No data was sent or stored.')); render();
