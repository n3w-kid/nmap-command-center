import { NextRequest, NextResponse } from 'next/server';
export const dynamic='force-dynamic';
async function proxy(req:NextRequest,ctx:{params:Promise<{path:string[]}>}){
  const {path}=await ctx.params;
  const url=new URL(req.url);
  const upstream=`${process.env.SCANNER_URL||'http://scanner:8000'}/${path.map(encodeURIComponent).join('/')}${url.search}`;
  try {
    const headersOut:Record<string,string>={'content-type':req.headers.get('content-type')||'application/json'};
    const adminToken=req.headers.get('x-admin-token');if(adminToken)headersOut['x-admin-token']=adminToken;
    const response=await fetch(upstream,{method:req.method,headers:headersOut,body:['POST','PUT','PATCH'].includes(req.method)?await req.text():undefined,cache:'no-store',signal:AbortSignal.timeout(35000)});
    const headers=new Headers();
    for(const key of ['content-type','content-disposition']){const v=response.headers.get(key);if(v)headers.set(key,v)}
    headers.set('cache-control','no-store');
    return new NextResponse(response.body,{status:response.status,headers});
  } catch {return NextResponse.json({detail:'Scanner service unavailable'},{status:502})}
}
export {proxy as GET,proxy as POST};
