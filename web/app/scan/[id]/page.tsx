'use client';
import {useParams} from 'next/navigation';
import {useEffect,useState} from 'react';
import Link from 'next/link';
import {Download,Square,ArrowLeft,ExternalLink,Copy} from 'lucide-react';
type Port={port:number;protocol:string;state:string;service:string;product:string;version:string};
type Host={address:string;status:string;ports:Port[]};
type Finding={host:string;port:string|null;id:string;output:string};type Results={hosts:Host[];summary:{hosts:number;openPorts:number};findings?:Finding[]};
type Step={profile:string;status:string;command:string[];exitCode:number|null};
type Detail={id:string;target:string;resolvedTargets?:string[];profile:string;status:string;created:string;activeStep?:number;command:string[];steps?:Step[];results:Results;stepResults?:Results[]};
const INTEL=[{name:'Vulners',url:'https://vulners.com/search'},{name:'Exploit Database',url:'https://www.exploit-db.com/'},{name:'NVD',url:'https://nvd.nist.gov/vuln/search'},{name:'OSV',url:'https://osv.dev/'},{name:'GitHub Advisories',url:'https://github.com/advisories'},{name:'CISA KEV',url:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'}];
export default function ScanDetail(){
  const {id}=useParams<{id:string}>();const [data,setData]=useState<Detail|null>(null),[log,setLog]=useState(''),[error,setError]=useState('');
  const [tab,setTab]=useState<'results'|'logs'|'command'|'intel'>('results'),[chosen,setChosen]=useState(0);
  useEffect(()=>{let active=true;async function update(){try{
    const [res,logs]=await Promise.all([fetch('/api/scans/'+id,{cache:'no-store'}).then(r=>r.json()),fetch('/api/scans/'+id+'/logs').then(r=>r.json())]);
    if(!active)return;if(res.detail)throw Error(res.detail);setData(res);setLog(logs.text||'');
  }catch(e){if(active)setError(String(e))}}void update();const t=setInterval(()=>void update(),2200);return()=>{active=false;clearInterval(t)}},[id]);
  async function cancel(){const r=await fetch('/api/scans/'+id+'/cancel',{method:'POST'});if(!r.ok)setError('Cancellation failed')}
  const steps=data?.steps||[{profile:data?.profile||'services',status:data?.status||'queued',command:data?.command||[],exitCode:null}];
  const index=Math.min(chosen,steps.length-1);
  const selected=steps[index];const results=data?.stepResults?.[index]||data?.results;
  return <><Link href="/history" className="link"><ArrowLeft size={14}/> Scan history</Link>
    <div className="toolbar" style={{marginTop:18}}><div><div className="eyebrow">SEQUENTIAL ASSESSMENT SESSION</div><h1 className="heading mono">{data?.target||'Loading assessment…'}</h1><p className="subtitle">{data?.created?new Date(data.created).toLocaleString():''} · {steps.length} ordered {steps.length===1?'step':'steps'}</p></div>
    <div style={{display:'flex',gap:10,alignItems:'center'}}><span className={'badge '+(data?.status||'')}>{data?.status||'loading'}</span>{['running','queued'].includes(data?.status||'')&&<button className="btn" onClick={cancel}><Square size={14}/> Cancel session</button>}</div></div>
    {error&&<div className="error">{error}</div>}
    <div className="stats"><div className="stat"><div className="statlabel">HOSTS · SELECTED STEP</div><div className="statvalue">{results?.summary.hosts||0}</div></div><div className="stat"><div className="statlabel">OPEN PORTS · SELECTED STEP</div><div className="statvalue green">{results?.summary.openPorts||0}</div></div><div className="stat"><div className="statlabel">SESSION STATUS</div><div className="statvalue" style={{fontSize:21,textTransform:'capitalize'}}>{data?.status||'…'}</div></div><div className="stat"><div className="statlabel">CURRENT STEP</div><div className="statvalue">{data?.activeStep===null||data?.activeStep===undefined?'—':`${data.activeStep+1}/${steps.length}`}</div></div></div>
    <div className="panel"><h2>Ordered commands</h2><div className="stepbar">{steps.map((s,i)=><button key={i} className={'stepbtn '+(i===index?'active':'')} onClick={()=>setChosen(i)}>#{i+1} {s.profile}<small><span className={'badge '+s.status}>{s.status}</span></small></button>)}</div><p className="hint">Steps execute in order. If a step fails or is cancelled, later steps do not run.</p></div>
    <div className="panel"><div className="toolbar" style={{marginBottom:22}}><div className="chips">{(['results','logs','command','intel'] as const).map(t=><button key={t} onClick={()=>setTab(t)} className={'chip '+(tab===t?'selected':'')}>{t.toUpperCase()}</button>)}</div>
      <div className="chips">{['xml','nmap','gnmap','json','csv','log'].map(f=><a key={f} className="btn" style={{padding:'8px 10px',fontSize:11}} href={'/api/scans/'+id+'/export/'+f+'?step='+index} download><Download size={13}/>{f.toUpperCase()}</a>)}</div></div>
      {tab==='results'&&<div><div className="tablewrap"><table><thead><tr><th>Host</th><th>Port</th><th>State</th><th>Service</th><th>Product / Version</th></tr></thead><tbody>{results?.hosts.flatMap(h=>h.ports.map(p=><tr key={h.address+':'+p.protocol+':'+p.port}><td className="mono">{h.address}</td><td className="mono">{p.port}/{p.protocol}</td><td><span className={'badge '+(p.state==='open'?'completed':'')}>{p.state}</span></td><td>{p.service}</td><td className="muted">{p.product} {p.version}</td></tr>))}</tbody></table>{!results?.hosts.length&&<div className="empty">Results appear when Nmap finishes writing XML for this step.</div>}</div>
        {!!results?.findings?.length&&<div style={{marginTop:25}}><h2>NSE inspection output ({results.findings.length})</h2>{results.findings.map((f,i)=><div key={i} className="commandpreview"><strong className="mono">{f.id} — {f.host}{f.port?':'+f.port:''}</strong><pre className="terminal smallterminal">{f.output||'(No script output)'}</pre></div>)}</div>}
      </div>}
      {tab==='logs'&&<pre className="terminal">{log||'Waiting for scanner output…'}</pre>}
      {tab==='command'&&<><div className="toolbar"><h2>Step {index+1} · Validated command</h2><button className="btn" onClick={()=>navigator.clipboard?.writeText(selected?.command.join(' ')||'')}><Copy size={14}/> Copy</button></div><pre className="terminal">{selected?.command.join(' ')||''}</pre></>}
      {tab==='intel'&&<><h2>Research databases</h2><p className="hint">Use identified service names and versions to research vulnerabilities. These portals are references, not confirmed findings, and are not contacted by this scanner.</p><div className="cataloggrid">{INTEL.map(x=><a className="catalogitem" key={x.name} href={x.url} target="_blank" rel="noreferrer"><strong>{x.name} <ExternalLink size={13}/></strong></a>)}</div></>}
    </div></>;
}
