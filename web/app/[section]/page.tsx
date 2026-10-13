'use client';
import {useParams,useRouter} from 'next/navigation';
import {useEffect,useMemo,useState} from 'react';
import Link from 'next/link';
import {ArrowRight,Play,Plus,Trash2,RotateCcw,Upload,ExternalLink,Copy} from 'lucide-react';

type Script={name:string;categories:string[];runnable:boolean;availability:"enabled"|"admin_approved"|"review_required"|"lab_review_required"|"lab_approved"|"high_risk"|"lab_disabled"|"unselectable";labOnly:boolean;source:string};
type Config={profiles:string[];scripts:Script[];libraries:string[];scope:string[];allowedHostnames:string[];maxTargets:number;maxDuration:number;maxSteps:number;maxSessions:number;adminApprovalConfigured:boolean;labModeEnabled:boolean;labAllowedIPs:string[]};
type Job={id:string;target:string;profile:string;status:string;created:string;steps?:{status:string}[]};
type Step={profile:string;ports:string;timing:number;scripts:string[];version:boolean;traceroute:boolean;reason:boolean;skip_discovery:boolean;flags:string};
type Custom={filename:string;bytes:number;status:string};
const newStep=():Step=>({profile:'services',ports:'',timing:3,scripts:[],version:false,traceroute:false,reason:true,skip_discovery:false,flags:''});
const basicProfiles:Record<string,string[]>={quick:['-sT','-F'],full_tcp:['-sT','-p','1-65535'],services:['-sT','-sV','--version-light'],discovery:['-sn'],udp_top:['-sU','--top-ports','20'],os:['-O'],web:['-sT','-sV','-p','80,443,8080,8443'],tls:['-sT','-p','443,8443'],windows:['-sT','-p','139,445,3389']};
const profileScripts:Record<string,string[]>={web:['http-title','http-headers','http-security-headers'],tls:['ssl-cert'],windows:['smb-os-discovery','smb-protocols','smb2-security-mode','rdp-ntlm-info']};
function flagsFor(s:Step){
  if(s.flags.trim())return s.flags.trim();
  const flags=[...(basicProfiles[s.profile]||basicProfiles.services)];
  if(s.ports){for(const op of ['-p','--top-ports']){const i=flags.indexOf(op);if(i>=0)flags.splice(i,2);}flags.push('-p',s.ports);}
  if(s.version&&!flags.includes('-sV')&&s.profile!=='discovery')flags.push('-sV');
  if(s.traceroute&&s.profile!=='discovery')flags.push('--traceroute');
  if(s.reason)flags.push('--reason');
  if(s.skip_discovery)flags.push('-Pn');
  flags.push(`-T${s.timing}`);
  return flags.join(' ');
}
function localCommand(s:Step,target:string,i:number){
  const defaults=s.flags.trim()?[]:(profileScripts[s.profile]||[]);
  const scripts=[...new Set([...defaults,...s.scripts])];
  const parts=['nmap',flagsFor(s),scripts.length?`--script ${scripts.join(',')}`:'', '--max-rate 150 --max-retries 2', `-oA <session>/scan-${i+1}`,target||'<target>'];
  return parts.filter(Boolean).join(' ');
}
const INTEL=[
  {name:'Vulners',url:'https://vulners.com/search',desc:'Security advisory and exploit intelligence'},
  {name:'Exploit Database',url:'https://www.exploit-db.com/',desc:'Searchable public exploit reference index'},
  {name:'NVD',url:'https://nvd.nist.gov/vuln/search',desc:'NIST CVE reference data'},
  {name:'OSV',url:'https://osv.dev/',desc:'Open-source dependency advisories'},
  {name:'GitHub Advisories',url:'https://github.com/advisories',desc:'Ecosystem security notices'},
  {name:'CISA KEV',url:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',desc:'Known exploited vulnerability catalog'},
];
function errorText(value:unknown){return value instanceof Error?value.message:String(value)}

export default function Section(){
  const {section}=useParams<{section:string}>();const router=useRouter();
  const [cfg,setCfg]=useState<Config|null>(null),[jobs,setJobs]=useState<Job[]>([]);
  const [target,setTarget]=useState('127.0.0.1'),[steps,setSteps]=useState<Step[]>([newStep()]),[chosen,setChosen]=useState(0);
  const [lookup,setLookup]=useState(''),[category,setCategory]=useState('all'),[showAll,setShowAll]=useState(false);
  const [preview,setPreview]=useState<string[]>([]),[resolved,setResolved]=useState<string[]>([]);
  const [previewError,setPreviewError]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState('');
  const [custom,setCustom]=useState<Custom[]>([]),[uploadError,setUploadError]=useState(''),[uploading,setUploading]=useState(false);
  const [authorized,setAuthorized]=useState(false),[labMode,setLabMode]=useState(false),[labConfirmed,setLabConfirmed]=useState(false),[labReviewAcknowledged,setLabReviewAcknowledged]=useState(false);
  const [adminToken,setAdminToken]=useState(''),[approvalNote,setApprovalNote]=useState(''),[scopeTarget,setScopeTarget]=useState('');
  const [adminMessage,setAdminMessage]=useState(''),[adminBusy,setAdminBusy]=useState(false);
  useEffect(()=>{
    fetch('/api/profiles').then(r=>r.json()).then(setCfg).catch(()=>setError('Scanner service unavailable'));
    fetch('/api/scans').then(r=>r.json()).then(v=>Array.isArray(v)&&setJobs(v)).catch(()=>{});
    if(section==='scripts')refreshCustom();
  },[section]);
  const payload=useMemo(()=>({target,steps,authorization_confirmed:authorized,lab_mode:labMode,lab_confirmed:labConfirmed}),[target,steps,authorized,labMode,labConfirmed]);
  useEffect(()=>{
    if(section!=='new')return;
    let active=true;
    const timer=setTimeout(async()=>{
      try{const r=await fetch('/api/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const d=await r.json();if(!active)return;
        if(!r.ok){setPreview([]);setResolved([]);setPreviewError(d.detail||'Cannot preview');return;}
        setPreview(d.commands.map((c:string[])=>c.join(' ')));setResolved(d.resolvedTargets);setPreviewError('');
      }catch{if(active)setPreviewError('Preview service unavailable');}
    },320);
    return()=>{active=false;clearTimeout(timer)};
  },[payload,section]);
  function update(index:number,part:Partial<Step>){setSteps(previous=>previous.map((s,i)=>i===index?{...s,...part}:s))}
  function toggleScript(index:number,name:string){setSteps(old=>old.map((s,i)=>i===index?{...s,scripts:s.scripts.includes(name)?s.scripts.filter(x=>x!==name):[...s.scripts,name]}:s))}
  function addStep(){if(steps.length>=3)return;setSteps(old=>[...old,newStep()]);setChosen(steps.length)}
  function removeStep(index:number){if(steps.length===1)return;setSteps(old=>old.filter((_,i)=>i!==index));setChosen(0)}
  async function launch(){setBusy(true);setError('');try{
    const r=await fetch('/api/scans',{method:'POST',headers:{'Content-Type':'application/json',...(labMode?{'X-Admin-Token':adminToken}:{})},body:JSON.stringify(payload)});
    const d=await r.json();if(!r.ok)throw new Error(d.detail||'Unable to launch');router.push('/scan/'+d.id);
  }catch(e){setError(errorText(e))}finally{setBusy(false)}}
  async function adminPost(endpoint:string,body:Record<string,string|boolean>){
    setAdminBusy(true);setAdminMessage('');
    try{
      const r=await fetch('/api/'+endpoint,{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Token':adminToken},body:JSON.stringify(body)});
      const d=await r.json();if(!r.ok)throw new Error(d.detail||'Approval failed');
      setAdminMessage(`Approved ${d.target||d.name}. The decision is recorded in the admin audit trail.`);
      const profileResponse=await fetch('/api/profiles');if(profileResponse.ok)setCfg(await profileResponse.json());
    }catch(e){setAdminMessage(errorText(e))}finally{setAdminBusy(false)}
  }
  async function refreshCustom(){try{const r=await fetch('/api/custom-scripts');const d=await r.json();setCustom(d.items||[])}catch{}}
  async function uploadFile(file?:File){if(!file)return;setUploadError('');setUploading(true);try{
    if(file.size>100000)throw new Error('Maximum 100 KB per file');
    const content=await file.text();const r=await fetch('/api/custom-scripts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:file.name,content})});const d=await r.json();
    if(!r.ok)throw new Error(d.detail||'Upload rejected');await refreshCustom();
  }catch(e){setUploadError(errorText(e))}finally{setUploading(false)}}
  const catalog=cfg?.scripts||[];
  const filtered=catalog.filter(s=>(category==='all'||(category==='runnable'?s.runnable:s.categories.includes(category)))&&s.name.toLowerCase().includes(lookup.toLowerCase()));
  const visible=showAll?filtered:filtered.slice(0,90);
  const selected=steps[chosen]||steps[0];
  const chosenLabScripts=steps.flatMap(s=>s.scripts).filter(name=>catalog.find(c=>c.name===name)?.labOnly);
  const manualNames=steps.flatMap(s=>[...s.flags.matchAll(/(?:^|\s)--script\s+([^\s]+)/g)]
    .flatMap(match=>match[1].split(',')));
  const usesPrivateLab=[...chosenLabScripts,...manualNames].some(name=>catalog.some(script=>script.name===name&&script.labOnly));
  const availabilityLabel=(s:Script)=>s.availability==='enabled'?'Enabled':s.availability==='admin_approved'?'Admin approved':s.availability==='lab_approved'?'Private lab approved':s.availability==='lab_review_required'?'Lab review needed':s.availability==='lab_disabled'?'Enable private lab mode':s.availability==='review_required'?'Review needed':'Not directly selectable';
  if(section==='new')return <>
    <div className="eyebrow">SCAN BUILDER · AUTHORIZED ASSESSMENTS</div><h1 className="heading">Design a scan session</h1>
    <p className="subtitle">Choose an authorized IP, hostname or HTTP(S) URL. Administrators can register newly approved targets under Settings. Combine eligible NSE checks and run one to three commands sequentially. Administrator-reviewed lab-category NSE checks are available only in private single-host sessions.</p>
    <div className="panel"><h2>Target and ordered session steps</h2>
      <div className="field"><label>Target IP, CIDR, hostname or HTTP(S) URL (URLs are scanned by resolved IP; paths are ignored)</label><input className="input mono" value={target} onChange={e=>setTarget(e.target.value)} placeholder="127.0.0.1, 10.0.0.5 or https://approved.example"/></div>
      <div className="stepbar">{steps.map((s,i)=><button key={i} className={'stepbtn '+(i===chosen?'active':'')} onClick={()=>setChosen(i)}>Step {i+1}<small>{s.profile.replaceAll('_',' ')} · {s.scripts.length} custom checks</small></button>)}{steps.length<3&&<button className="btn" onClick={addStep}><Plus size={15}/> Add step</button>}</div>
    </div>
    <div className="grid2"><div>
      <div className="panel"><div className="panelhead"><h2>Step {chosen+1} · Scan options</h2>{steps.length>1&&<button className="btn" onClick={()=>removeStep(chosen)}><Trash2 size={14}/> Remove</button>}</div>
        <div className="field"><label>Profile</label><select value={selected.profile} onChange={e=>update(chosen,{profile:e.target.value})}>{(cfg?.profiles||Object.keys(basicProfiles)).map(p=><option key={p} value={p}>{p.replaceAll('_',' ').toUpperCase()}</option>)}</select></div>
        <div className="field"><label>Ports (optional override)</label><input className="input mono" value={selected.ports} onChange={e=>update(chosen,{ports:e.target.value})} placeholder="22,80,443 or 1-1024"/></div>
        <div className="field"><label>Timing T{selected.timing} (T0–T4)</label><input type="range" min="0" max="4" value={selected.timing} onChange={e=>update(chosen,{timing:Number(e.target.value)})} style={{width:'100%',accentColor:'#43d9ba'}}/></div>
        <div className="checks">{([['version','Version detection'],['traceroute','Traceroute'],['reason','Reason for port status'],['skip_discovery','Skip host discovery']] as const).map(([name,label])=><label key={name} className="check"><input type="checkbox" checked={selected[name]} onChange={e=>update(chosen,{[name]:e.target.checked})}/>{label}</label>)}</div>
        <div className="field"><label>Editable Nmap command options</label><textarea rows={3} className="input mono" value={flagsFor(selected)} onChange={e=>update(chosen,{flags:e.target.value})} spellCheck={false}/>
          <p className="hint">Change options directly here. The scanner validates each flag and appends the scoped target, script selection, rate limits and output location. Arbitrary shell commands are not accepted.</p>
          {selected.flags&&<button className="btn" onClick={()=>update(chosen,{flags:''})}><RotateCcw size={13}/> Regenerate from profile</button>}
        </div>
      </div>
      <div className="panel"><div className="panelhead"><h2>Combined NSE inspection scripts</h2><span className="badge">{selected.scripts.length} selected</span></div>
        <input className="input" value={lookup} onChange={e=>{setLookup(e.target.value);setShowAll(false)}} placeholder="Filter NSE script names…"/>
        <div className="chips" style={{marginTop:10}}>{['runnable','all','safe','discovery','vuln','intrusive','brute','exploit','dos','fuzzer'].map(c=><button key={c} className={'chip '+(category===c?'selected':'')} onClick={()=>{setCategory(c);setShowAll(false)}}>{c}</button>)}</div>
        <p className="hint">Enabled checks can be combined. Other checks can be reviewed individually on /scripts. Approved brute-force, exploit, DoS and fuzzing NSE checks require private lab mode, explicit allowlisting and acknowledgement. Off-target scripts stay blocked.</p>
        <div className="scriptlist">{visible.map(s=><div key={s.name} className="scriptrow"><label className="check"><input type="checkbox" disabled={!s.runnable||(s.labOnly&&!labMode)||(!selected.scripts.includes(s.name)&&selected.scripts.length>=40)} checked={selected.scripts.includes(s.name)} onChange={()=>toggleScript(chosen,s.name)}/><span className="mono">{s.name}</span></label><span className="hint">{s.availability==='lab_approved'?'Private lab only':s.availability==='lab_review_required'?'Lab review needed':s.availability==='admin_approved'?'Admin approved':s.availability==='enabled'?'Enabled':s.availability==='review_required'?'Needs review':'Not executable'}</span></div>)}</div>
        {filtered.length>visible.length&&<button className="btn" onClick={()=>setShowAll(true)}>Show all {filtered.length} matches</button>}
        <p className="hint">Select up to 40 scripts per step. <Link className="link" href="/scripts">Browse full catalog <ArrowRight size={12}/></Link></p>
      </div>
    </div><div className="panel"><h2>Live command preview · {steps.length} ordered {steps.length===1?'step':'steps'}</h2>
      {steps.map((s,i)=><div className="commandpreview" key={i}><div className="panelhead"><strong>#{i+1} — {s.profile.toUpperCase()}</strong><button className="btn" onClick={()=>navigator.clipboard?.writeText(preview[i]||localCommand(s,target,i))}><Copy size={13}/> Copy</button></div><pre className="terminal smallterminal">{preview[i]||localCommand(s,target,i)}</pre></div>)}
      {resolved.length>0&&<p className="hint">Pinned IP targets: {resolved.join(', ')}. DNS names are resolved before Nmap runs.</p>}
      {previewError&&<div className="error">Validation: {previewError}</div>}{error&&<div className="error">{error}</div>}
      <div className="panel" style={{marginBottom:16,padding:16}}><label className="check"><input type="checkbox" checked={labMode} onChange={e=>setLabMode(e.target.checked)}/><span>Private lab mode — only one RFC1918/loopback/private IPv6 host; administrator-reviewed lab-category NSE scripts</span></label>
        {labMode&&<div className="field" style={{marginTop:12}}><label>Administrator token (required for lab-category scans; not saved)</label><input className="input" type="password" autoComplete="off" value={adminToken} onChange={e=>setAdminToken(e.target.value)}/></div>}
      </div>
      <label className="check approvalcheck"><input type="checkbox" checked={authorized} onChange={e=>setAuthorized(e.target.checked)}/><span>I have verified written authorization for these exact targets and assessment methods, and accept the operational impact.</span></label>
      {usesPrivateLab&&<div className="panel"><strong>Private-lab restricted NSE execution</strong><p className="hint">Restricted checks may interrupt, crash, alter, or lock out the lab service. This does not certify a target as safe or authorized. Only a single pinned IP listed in LAB_ALLOWED_IPS is accepted, and the scanner enforces each script approval. Use an independently isolated network; these checks can interrupt services.</p><p className="hint">Configured private lab targets: {(cfg?.labAllowedIPs||[]).join(', ')||'none'}</p><label className="check approvalcheck"><input type="checkbox" checked={labConfirmed} onChange={e=>setLabConfirmed(e.target.checked)}/><span>I have isolated the lab, obtained authorization for disruptive techniques, and accept the potential damage or outage.</span></label></div>}
      <button className="btn primary" disabled={busy||!authorized||(usesPrivateLab&&!labConfirmed)||!!previewError||!preview.length} onClick={launch}><Play size={16}/>{busy?'Starting…':`Start ${steps.length}-step session`}</button>
    </div></div></>;
  if(section==='history')return <><div className="toolbar"><div><div className="eyebrow">AUDIT TRAIL</div><h1 className="heading">Scan history</h1><p className="subtitle">Review session status, ordered steps, command output and exports.</p></div><Link className="btn primary" href="/new">New scan</Link></div><div className="panel tablewrap"><table><thead><tr><th>Target</th><th>First profile</th><th>Steps</th><th>Created</th><th>Status</th><th>Details</th></tr></thead><tbody>{jobs.map(j=><tr key={j.id}><td className="mono">{j.target}</td><td>{j.profile}</td><td>{j.steps?.length||1}</td><td>{new Date(j.created).toLocaleString()}</td><td><span className={'badge '+j.status}>{j.status}</span></td><td><Link className="link" href={'/scan/'+j.id}>Inspect <ArrowRight size={14}/></Link></td></tr>)}</tbody></table>{!jobs.length&&<div className="empty">No assessments recorded yet.</div>}</div></>;
  if(section==='scripts')return <><div className="eyebrow">NMAP SCRIPTING ENGINE</div><h1 className="heading">NSE and custom library</h1>
    <p className="subtitle">Browse every script installed with Nmap. Brute-force, exploit, DoS and fuzzing-category scripts can be individually enabled for approved, exact-IP private labs; off-target scripts remain reference-only. Availability depends on the installed Nmap release.</p>
    <div className="stats"><div className="stat"><div className="statlabel">INSTALLED SCRIPTS</div><div className="statvalue">{catalog.length}</div></div><div className="stat"><div className="statlabel">RUNNABLE SCRIPTS</div><div className="statvalue green">{catalog.filter(x=>x.runnable).length}</div></div><div className="stat"><div className="statlabel">NOT ENABLED</div><div className="statvalue">{catalog.filter(x=>!x.runnable).length}</div></div><div className="stat"><div className="statlabel">INSTALLED NSE LIBRARIES</div><div className="statvalue">{cfg?.libraries?.length||0}</div></div></div>
    <div className="panel"><div className="panelhead"><h2>Installed script catalog</h2><span className="badge">{filtered.length} matches</span></div>
      <input className="input" placeholder="Search installed NSE names" value={lookup} onChange={e=>{setLookup(e.target.value);setShowAll(false)}}/>
      <div className="chips" style={{margin:'12px 0 20px'}}>{['all','runnable','safe','default','discovery','vuln','exploit','intrusive','dos','brute','external','fuzzer'].map(c=><button key={c} className={'chip '+(category===c?'selected':'')} onClick={()=>{setCategory(c);setShowAll(false)}}>{c}</button>)}</div>
      <div className="cataloggrid">{visible.map(s=><div key={s.name} className="catalogitem"><div><a className="link mono" target="_blank" rel="noreferrer" href={'https://nmap.org/nsedoc/scripts/'+encodeURIComponent(s.name)+'.html'}>{s.name} <ExternalLink size={12}/></a><p className="hint">{s.categories.join(' · ')}</p></div><div className="catalogactions"><span className={'badge '+(s.runnable?'completed':'')}>{s.availability==='enabled'?'Enabled':s.availability==='admin_approved'?'Approved':s.availability==='lab_approved'?'Private lab approved':s.availability==='lab_review_required'?'Lab review needed':s.availability==='lab_disabled'?'Lab mode disabled':s.availability==='review_required'?'Review needed':'Not executable'}</span>{(s.availability==='review_required'||s.availability==='lab_review_required')&&<button className="btn mini" disabled={adminBusy||!cfg?.adminApprovalConfigured} title="Requires administrator review and approval note" onClick={()=>void adminPost('nse-approvals',{name:s.name,note:approvalNote,lab_acknowledged:labReviewAcknowledged})}>Approve</button>}</div></div>)}</div>
      {filtered.length>visible.length&&<button className="btn" onClick={()=>setShowAll(true)}>Show all {filtered.length} entries</button>}
    </div>
    <div className="panel"><h2>Administrator script approvals</h2><p className="hint">Administrators can review and enable additional diagnostic checks individually. Brute-force, exploit, DoS and fuzzing-category scripts require private lab mode, one exact private IP allowlisted in .env, a separate risk acknowledgement, and an administrator token at launch. External, broadcast and target-expansion scripts remain blocked. Other intrusive-tagged NSE scripts require individual administrator review. Version-category scripts are invoked by Nmap service detection.</p>
      <div className="grid2"><div className="field"><label>Administrator token (not stored in the browser)</label><input type="password" className="input" autoComplete="off" value={adminToken} onChange={e=>setAdminToken(e.target.value)} placeholder="ADMIN_TOKEN"/></div><div className="field"><label>Review and authorization note (min 10 characters)</label><input className="input" value={approvalNote} onChange={e=>setApprovalNote(e.target.value)} placeholder="Risk reviewed for permitted assessment"/></div></div>
      <label className="check approvalcheck"><input type="checkbox" checked={labReviewAcknowledged} onChange={e=>setLabReviewAcknowledged(e.target.checked)}/><span>For high-risk scripts: I have reviewed the selected NSE script and confirm the lab is isolated, controlled and approved for disruptive testing.</span></label>
      <p className="hint">Private lab mode: {cfg?.labModeEnabled?'configured':'off'} · Exact allowed IPs: {(cfg?.labAllowedIPs||[]).join(', ')||'none'}. Adjust .env and restart the scanner to change lab mode.</p>
      {!cfg?.adminApprovalConfigured&&<p className="error">Administrative approvals are disabled until ADMIN_TOKEN is configured in .env.</p>}{adminMessage&&<p className="hint">{adminMessage}</p>}
    </div>
    <div className="panel"><h2>Bundled NSE libraries ({cfg?.libraries?.length||0})</h2><p className="hint">Installed nselib modules used by Nmap scripts, available for documentation lookup. Libraries are not independently launched as scans.</p><div className="chips" style={{marginTop:15}}>{(cfg?.libraries||[]).map(name=><a key={name} className="chip" target="_blank" rel="noreferrer" href={'https://nmap.org/nsedoc/lib/'+encodeURIComponent(name)+'.html'}>{name}</a>)}</div></div>
    <div className="panel"><h2>Import a custom .nse script or .lua library</h2><p className="hint">{custom.length} custom file(s) awaiting review. Upload to the scanner's private quarantine folder for review. Lua/NSE extensions can execute arbitrary code, so uploads are never loaded or executed automatically. Maximum 100 KB per file; identical names cannot be overwritten.</p>
      <label className="btn" style={{marginTop:10,display:'inline-flex'}}><Upload size={15}/>{uploading?'Uploading…':'Select script or library'}<input hidden type="file" accept=".nse,.lua" disabled={uploading} onChange={e=>{void uploadFile(e.target.files?.[0]);e.currentTarget.value=''}}/></label>
      {uploadError&&<div className="error">{uploadError}</div>}
      <div className="tablewrap" style={{marginTop:20}}><table><thead><tr><th>Filename</th><th>Size</th><th>Status</th></tr></thead><tbody>{custom.map(f=><tr key={f.filename}><td className="mono">{f.filename}</td><td>{f.bytes} bytes</td><td><span className="badge">{f.status}</span></td></tr>)}</tbody></table>{!custom.length&&<p className="hint">No custom files uploaded.</p>}</div>
      <p className="hint">Official references: <a className="link" href="https://nmap.org/nsedoc/" target="_blank" rel="noreferrer">NSEDoc (scripts and libraries)</a> and <a className="link" href="https://nmap.org/book/data-files-nse.html" target="_blank" rel="noreferrer">NSE library locations</a>.</p>
    </div>
    <div className="panel"><h2>Vulnerability intelligence references</h2><p className="hint">These are external research portals, not installed scanners or automatically verified findings.</p><div className="cataloggrid">{INTEL.map(x=><a className="catalogitem" key={x.name} target="_blank" rel="noreferrer" href={x.url}><div><strong>{x.name} <ExternalLink size={12}/></strong><p className="hint">{x.desc}</p></div></a>)}</div></div>
  </>;
  if(section==='settings')return <><div className="eyebrow">ASSESSMENT POLICY</div><h1 className="heading">Scanner settings</h1><p className="subtitle">Scope is enforced by the scanner backend, not the browser. URL and hostname targets must resolve into approved networks or be explicitly authorized by the administrator.</p>
    <div className="panel"><h2>Approved network CIDRs</h2><div className="chips" style={{marginTop:18}}>{(cfg?.scope||[]).map(s=><span key={s} className="chip mono">{s}</span>)}</div><h2 style={{marginTop:25}}>Approved DNS hostnames</h2><div className="chips" style={{marginTop:12}}>{(cfg?.allowedHostnames||[]).map(s=><span key={s} className="chip mono">{s}</span>)}{!cfg?.allowedHostnames?.length&&<span className="hint">No additional hostnames configured</span>}</div><p className="hint">These are enforced server-side. Preconfigured entries come from the scanner environment; additional administrator-approved entries are stored in data/approvals.json. An authorization note is recorded for each new entry.</p></div>
    <div className="panel"><h2>Register a new authorized target</h2><p className="hint">After independently confirming written authorization, enter an exact hostname, HTTP(S) URL or bounded IP/CIDR. The scanner will accept approved targets without restarting or editing the initial target list.</p>
      <div className="field"><label>Hostname, URL, IP address or CIDR</label><input className="input mono" value={scopeTarget} onChange={e=>setScopeTarget(e.target.value)} placeholder="https://authorized.example or 203.0.113.10"/></div>
      <div className="field"><label>Administrator token (not saved by this page)</label><input type="password" autoComplete="off" className="input" value={adminToken} onChange={e=>setAdminToken(e.target.value)}/></div>
      <div className="field"><label>Authorization reference / scope note (at least 10 characters)</label><input className="input" value={approvalNote} onChange={e=>setApprovalNote(e.target.value)} placeholder="Approved under engagement XYZ, confirmed on date"/></div>
      <button className="btn primary" disabled={adminBusy||!cfg?.adminApprovalConfigured||!scopeTarget.trim()||approvalNote.trim().length<10} onClick={()=>void adminPost('authorizations',{target:scopeTarget,note:approvalNote})}>Register approved target</button>
      {!cfg?.adminApprovalConfigured&&<p className="error">Set a unique ADMIN_TOKEN (16 or more characters) in .env, then restart the scanner to enable approvals.</p>}{adminMessage&&<p className="hint">{adminMessage}</p>}
    </div>
    <div className="panel"><h2>Restricted NSE private lab</h2><p className="hint">To enable extra categories against only your private training box, set LAB_MODE_ENABLED=true and LAB_ALLOWED_IPS=your_private_lab_IP in .env. For example, 192.168.56.10. Also include that address in ALLOWED_CIDRS. Restart Docker, visit /scripts, review and individually approve each lab script, then confirm the extra checkbox on /new.</p><p className="hint">Current lab mode: {cfg?.labModeEnabled?'enabled':'disabled'}; exact lab IPs: {(cfg?.labAllowedIPs||[]).join(', ')||'none'}.</p><p className="hint">.env entries are scope controls, not proof of consent. The app does not permit target-expanding broadcasts, arbitrary commands, or auto-execution of uploaded Lua.</p></div>
    <div className="stats"><div className="stat"><div className="statlabel">MAX ADDRESSES / SESSION</div><div className="statvalue">{cfg?.maxTargets||'—'}</div></div><div className="stat"><div className="statlabel">MAX STEP DURATION</div><div className="statvalue">{cfg?.maxDuration||'—'}<small style={{fontSize:12}}> sec</small></div></div><div className="stat"><div className="statlabel">STEPS / SESSION</div><div className="statvalue">{cfg?.maxSteps||3}</div></div><div className="stat"><div className="statlabel">CONCURRENT SESSIONS</div><div className="statvalue">{cfg?.maxSessions||2}</div></div></div></>;
  return <div className="panel">Page not found. <Link href="/" className="link">Go home</Link></div>;
}
