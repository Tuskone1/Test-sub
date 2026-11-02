#!/usr/bin/env python3
"""Build an Xray JSON subscription. Do not run untrusted full configs from sources."""
import base64, concurrent.futures, copy, datetime, hashlib, ipaddress, json, os, random, re, shutil, socket, subprocess, sys, tempfile, time, urllib.parse, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SETTINGS = json.loads((ROOT / 'settings.json').read_text(encoding='utf-8'))
OUTPUT = ROOT / 'output' / 'subscription.json'
REPORT = ROOT / 'output' / 'report.json'
NAMES = {'DE':'🇩🇪 Германия', 'FI':'🇫🇮 Финляндия', 'SE':'🇸🇪 Швеция', 'NL':'🇳🇱 Нидерланды', 'US':'🇺🇸 США', 'OTHER':'🌍 Другие страны', 'BYPASS':'🇪🇺 Обход'}
ORDER = ['DE','FI','SE','NL','US','OTHER','BYPASS']
RU_DOMAINS = ['domain:ru','domain:su','domain:xn--p1ai','domain:vk.com','domain:userapi.com','domain:mail.ru','domain:ok.ru','domain:yandex.ru','domain:wink.ru','domain:more.tv','domain:kion.ru','domain:sfera.fm']
PROBE = SETTINGS.get('probe_url', 'https://cp.cloudflare.com/generate_204')

def timestamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
def save(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp=path.with_suffix('.tmp'); tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2)+'\n', encoding='utf-8'); os.replace(tmp,path)
def check_address(host):
    if not host or len(host)>253 or host.lower() in ('localhost','localhost.localdomain') or host.lower().endswith(('.local','.internal','.localhost')): return False
    try: return ipaddress.ip_address(host).is_global
    except ValueError: return bool(re.fullmatch(r'[A-Za-z0-9.-]+', host))
def normalize(src):
    text=src.decode('utf-8-sig', errors='replace').strip()
    if '://' not in text[:10000]:
        try: text=base64.urlsafe_b64decode(text + '='*((-len(text))%4)).decode('utf-8-sig', errors='replace')
        except Exception: return ''
    return text

def parse_link(link):
    if len(link)>8192: return None
    try:
        u=urllib.parse.urlsplit(link.strip()); q=urllib.parse.parse_qs(u.query, keep_blank_values=True)
        get=lambda k, default='': q.get(k,[default])[0]
        host=u.hostname; port=u.port or (443 if u.scheme in ('hysteria2','hy2') else None)
        if u.scheme not in ('vless','trojan','hysteria2','hy2') or not check_address(host) or not port or not 1<=port<=65535 or '@' not in u.netloc: return None
        credential=urllib.parse.unquote(u.netloc.rsplit('@',1)[0])
        if not credential or len(credential)>256: return None
        if u.scheme in ('hysteria2','hy2'):
            # Do not silently disable verification or ignore features that change connection semantics.
            if any(get(k,'0').lower() in ('1','true') for k in ('allowInsecure','insecure')): return None
            if any(get(k) for k in ('pinSHA256','pinsha256','mport','ports','hop-interval','hopInterval')): return None
            obfs=get('obfs','').lower()
            if obfs not in ('','salamander'): return None
            obfs_password=get('obfs-password') or get('obfsPassword')
            if obfs and not obfs_password: return None
            sni=get('sni',host)
            if not sni or len(sni)>253: return None
            tls={'serverName':sni,'alpn':['h3'],'allowInsecure':False}
            alpn=get('alpn')
            if alpn and alpn != 'h3': return None
            stream={'network':'hysteria','security':'tls','tlsSettings':tls,'hysteriaSettings':{'version':2,'auth':credential}}
            if obfs: stream['finalmask']={'udp':[{'type':'salamander','settings':{'password':obfs_password}}]}
            outbound={'protocol':'hysteria','settings':{'version':2,'address':host,'port':port},'streamSettings':stream}
            return {'outbound':outbound,'priority':1,'label':urllib.parse.unquote(u.fragment)[:256]}
        if u.scheme=='vless' and not re.fullmatch(r'[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}', credential): return None
        transport=get('type','tcp').lower(); security=get('security','tls' if u.scheme=='trojan' else '').lower()
        if transport not in ('tcp','ws','grpc','xhttp') or security not in ('tls','reality'): return None
        # Do not silently downgrade certificate verification.
        if get('allowInsecure','0').lower() in ('1','true') or get('insecure','0').lower() in ('1','true'): return None
        if security=='reality' and not get('pbk'): return None
        if get('headerType','none') not in ('','none'): return None
        if get('encryption','none') not in ('','none'): return None
        sni=get('sni',host); fingerprint=get('fp','chrome')
        if len(sni)>253 or len(fingerprint)>64: return None
        stream={'network':transport,'security':security}
        if security=='reality':
            r={'serverName':sni,'fingerprint':fingerprint,'publicKey':get('pbk'),'shortId':get('sid'),'spiderX':get('spx','/')}
            if get('pqv'): r['mldsa65Verify']=get('pqv')
            stream['realitySettings']=r
        else:
            tls={'serverName':sni,'fingerprint':fingerprint,'allowInsecure':False}
            if get('alpn'): tls['alpn']=[x for x in get('alpn').split(',') if x]
            stream['tlsSettings']=tls
        if transport=='tcp': stream['tcpSettings']={'header':{'type':'none'}}
        elif transport=='ws':
            w={'path':get('path','/') or '/'}
            if get('host'): w['headers']={'Host':get('host')}
            stream['wsSettings']=w
        elif transport=='grpc': stream['grpcSettings']={'serviceName':get('serviceName')}
        elif transport=='xhttp':
            x={'path':get('path','/') or '/'}
            if get('host'): x['host']=get('host')
            if get('mode'): x['mode']=get('mode')
            if get('extra'):
                extra=json.loads(get('extra'))
                if not isinstance(extra,dict) or len(get('extra'))>4096: return None
                x['extra']=extra
            stream['xhttpSettings']=x
        if u.scheme=='vless':
            user={'id':credential,'encryption':'none'}
            if get('flow'): user['flow']=get('flow')
            settings={'vnext':[{'address':host,'port':port,'users':[user]}]}
        else: settings={'servers':[{'address':host,'port':port,'password':credential}]}
        outbound={'protocol':u.scheme,'settings':settings,'streamSettings':stream,'mux':{'enabled':False}}
        return {'outbound':outbound,'priority':0 if u.scheme=='vless' and transport=='tcp' and security=='reality' else 1, 'label':urllib.parse.unquote(u.fragment)[:256]}
    except (ValueError,TypeError,KeyError,json.JSONDecodeError): return None

def safe_target(host):
    try:
        return bool(host) and all(ipaddress.ip_address(item[4][0]).is_global for item in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM))
    except (OSError,ValueError): return False

def inferred_group(label):
    # A backup's own label is only a hint, not verified geolocation.
    label=label.lower()
    patterns={'DE':r'🇩🇪|germany|deutschland|герман|\bde\b', 'FI':r'🇫🇮|finland|финлян|\bfi\b', 'SE':r'🇸🇪|sweden|швеци|\bse\b', 'NL':r'🇳🇱|netherlands|nederland|нидерланд|\bnl\b', 'US':r'🇺🇸|united states|\busa\b|сша|\bus\b'}
    matches=[k for k,v in patterns.items() if re.search(v,label)]
    return matches[0] if len(matches)==1 else None

def fetch_source(url):
    if not url.startswith('https://'): raise ValueError('HTTPS required')
    request=urllib.request.Request(url, headers={'User-Agent':'Happ/4.5.6','Accept':'text/plain, */*'})
    with urllib.request.urlopen(request, timeout=20) as r:
        if not r.geturl().startswith('https://'): raise ValueError('HTTPS redirect required')
        data=r.read(4*1024*1024+1)
        if len(data)>4*1024*1024: raise ValueError('source too large')
    return normalize(data)

def out_host(out):
    st=out['settings']; return st.get('address') or (st.get('vnext') or st.get('servers'))[0]['address']

def alloc_port():
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def config_for_test(out,port):
    o=copy.deepcopy(out); o['tag']='proxy'
    return {'log':{'loglevel':'error'}, 'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'http','settings':{}}], 'outbounds':[o], 'routing':{'rules':[{'type':'field','inboundTag':[], 'outboundTag':'proxy'}]}}

def test_one(item, probe_url=None):
    if not safe_target(out_host(item['outbound'])): return None
    port=alloc_port(); conf=config_for_test(item['outbound'],port)
    # Simplify routing: the only outbound is necessarily used.
    conf.pop('routing',None)
    t0=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='subcheck-') as d:
        p=Path(d)/'config.json'; p.write_text(json.dumps(conf),encoding='utf-8')
        proc=subprocess.Popen(['xray','run','-config',str(p)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            ready=False
            for _ in range(30):
                if proc.poll() is not None: break
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1): ready=True; break
                except OSError: time.sleep(.1)
            if not ready: return None
            start=time.monotonic()
            r=subprocess.run(['curl','--silent','--show-error','--output','/dev/null','--write-out','%{http_code}', '--max-time',str(SETTINGS.get('timeout_seconds',10)), '--noproxy','', '--proxy',f'http://127.0.0.1:{port}', probe_url or PROBE],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=int(SETTINGS.get('timeout_seconds',10))+3)
            if r.returncode!=0 or r.stdout.strip() not in ('200','204'): return None
            item['latency_ms']=round((time.monotonic()-start)*1000); return item
        except (subprocess.TimeoutExpired,OSError): return None
        finally:
            proc.terminate()
            try: proc.wait(timeout=2)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()

def inbounds():
    return [{'listen':'127.0.0.1','port':10808,'protocol':'socks','settings':{'auth':'noauth','udp':True},'sniffing':{'enabled':True,'destOverride':['http','tls','quic']},'tag':'socks'}, {'listen':'127.0.0.1','port':10809,'protocol':'http','settings':{},'tag':'http'}]

def profile(name, nodes, burst=False):
    outs=[]
    for i,n in enumerate(nodes,1):
        o=copy.deepcopy(n['outbound']);o['tag']=f'node-{i:03d}'; outs.append(o)
    rules=[{'type':'field','ip':['geoip:private'],'outboundTag':'block'}, {'type':'field','domain':RU_DOMAINS,'outboundTag':'direct'}]
    routing={'domainStrategy':'AsIs','rules':rules}
    config={'remarks':name,'log':{'loglevel':'warning'},'inbounds':inbounds(), 'outbounds':outs+[{'tag':'direct','protocol':'freedom'},{'tag':'block','protocol':'blackhole'}], 'routing':routing}
    if len(outs)>1:
        strategy={'type':'leastLoad','settings':{'expected':1,'tolerance':0.25}} if burst else {'type':'leastPing'}
        routing['balancers']=[{'tag':'auto','selector':['node-'],'strategy':strategy,'fallbackTag':'node-001'}]
        rules.append({'type':'field','network':'tcp,udp','balancerTag':'auto'})
        if burst:
            # Separate comparison profile; measurements occur from the user's device.
            config['burstObservatory']={'subjectSelector':['node-'],'pingConfig':{'destination':PROBE,'interval':'1m','sampling':3,'timeout':'5s'}}
        else:
            config['observatory']={'subjectSelector':['node-'],'probeUrl':PROBE,'probeInterval':'1m','enableConcurrency':True}
    else: rules.append({'type':'field','network':'tcp,udp','outboundTag':'node-001'})
    return config

def read_previous():
    try:
        profiles=json.loads(OUTPUT.read_text(encoding='utf-8')); report=json.loads(REPORT.read_text(encoding='utf-8'))
        if not isinstance(profiles,list) or not isinstance(report,dict): return [],{}
        return profiles,report
    except (OSError,ValueError): return [],{}

def previous_nodes(profiles, name):
    for p in profiles:
        if p.get('remarks')==name:
            return [{'outbound':{k:copy.deepcopy(v) for k,v in o.items() if k!='tag'}, 'priority':0 if o.get('protocol')=='vless' and o.get('streamSettings',{}).get('security')=='reality' and o.get('streamSettings',{}).get('network')=='tcp' else 1} for o in p.get('outbounds',[]) if o.get('tag','').startswith('node-')]
    return []

def main():
    OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    if SETTINGS.get('mode')=='manual':
        manual=json.loads((ROOT/'manual.json').read_text(encoding='utf-8'))
        if not isinstance(manual,list) or not manual or not all(isinstance(x,dict) and isinstance(x.get('outbounds'),list) for x in manual):
            raise SystemExit('manual.json must contain a non-empty JSON array of Xray configs; previous output unchanged')
        save(OUTPUT,manual); save(REPORT,{'mode':'manual','updated_utc':timestamp(),'message':'Manual profiles; no automatic tests performed.'}); return
    if SETTINGS.get('mode')!='auto': raise SystemExit('settings.json mode must be auto or manual')
    if not shutil.which('xray') or not shutil.which('curl'): raise SystemExit('xray and curl are required')
    old,old_report=read_previous(); groups={x:[] for x in ORDER}; source_reports=[]; seen={x:set() for x in ORDER}
    limit=max(1,min(int(SETTINGS.get('max_candidates_per_source',30)),100))
    sources=list(SETTINGS['sources'])
    # Optional URL goes in GitHub Actions secrets, never in this public file.
    if os.environ.get('EXTRA_SOURCE_URL', '').strip():
        sources.append({'group':'BACKUP','url':os.environ['EXTRA_SOURCE_URL'].strip()})
    for source in sources:
        group=source['group']; report={'group':group}
        try:
            raw=fetch_source(source['url']); found=[]
            for line in raw.splitlines():
                line=line.strip()
                if not line.startswith(('vless://','trojan://','hysteria2://','hy2://')): continue
                item=parse_link(line)
                if not item: continue
                target=(inferred_group(item['label']) or 'OTHER') if group=='BACKUP' else group
                if target not in groups: continue
                key=hashlib.sha256(json.dumps(item['outbound'],sort_keys=True).encode()).hexdigest()
                if key in seen[target]: continue
                found.append((target,key,item))
            # Reserve test slots for Reality, Hysteria2 and other supported protocols.
            # Sorting only by Reality here would starve Hysteria in large feeds.
            random.shuffle(found)
            reality=[x for x in found if x[2]['priority']==0]
            hy=[x for x in found if x[2]['outbound']['protocol']=='hysteria']
            other=[x for x in found if x[2]['priority']!=0 and x[2]['outbound']['protocol']!='hysteria']
            picked=[]
            quotas=[(reality,(limit+1)//2),(hy,(limit+2)//4),(other,limit//4)]
            for pool,quota in quotas:
                take=pool[:quota];picked.extend(take);del pool[:len(take)]
            for pool in (reality,hy,other):
                take=pool[:max(0,limit-len(picked))];picked.extend(take)
            found=picked[:limit]
            for target,key,item in found:
                if key not in seen[target]: seen[target].add(key); groups[target].append(item)
            report.update({'status':'ok','candidates_added':len(found)})
        except Exception as e: report.update({'status':'error','error_type':type(e).__name__})
        source_reports.append(report)
        print(f"Source {group}: {report['status']} ({report.get('candidates_added',0)} candidates)",flush=True)
    all_items=[(g,item) for g in ORDER for item in groups[g]]
    checked={x:[] for x in ORDER}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,min(int(SETTINGS.get('workers',8)),16))) as ex:
        futs={ex.submit(test_one,i):g for g,i in all_items}
        for fut in concurrent.futures.as_completed(futs):
            try:
                result=fut.result()
                if result: checked[futs[fut]].append(result)
            except Exception as e: print('Test error:',type(e).__name__,flush=True)
    # Re-test the best initial candidates against a second HTTPS destination.
    # Require both tests to succeed instead of trusting a single lucky response.
    first_pass={g:list(checked[g]) for g in ORDER}
    finalists=[]
    for group in ORDER:
        ranked=sorted(first_pass[group],key=lambda n:n['latency_ms'])
        preferred=next((n for n in ranked if n['priority']==0),None)
        pool=(([preferred] if preferred else []) + [n for n in ranked if n is not preferred])[:10]
        for item in pool:
            item['first_latency_ms']=item['latency_ms']; finalists.append((group,item))
    verified={x:[] for x in ORDER}
    verify_url=SETTINGS.get('verify_url','https://www.gstatic.com/generate_204')
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,min(int(SETTINGS.get('workers',8)),16))) as ex:
        futs={ex.submit(test_one,item,verify_url):group for group,item in finalists}
        for fut in concurrent.futures.as_completed(futs):
            try:
                result=fut.result()
                if result:
                    result['latency_ms']=max(result['first_latency_ms'],result['latency_ms'])
                    verified[futs[fut]].append(result)
            except Exception as e: print('Verification error:',type(e).__name__,flush=True)
    checked=verified
    max_n=max(1,min(int(SETTINGS.get('max_per_group',5)),5)); selected={}; stats={}; now=timestamp()
    for g in ORDER:
        # First slot is the fastest working VLESS/TCP/Reality, if any.
        # Remaining slots are the fastest of all protocols, including Hysteria2.
        ranked=sorted(checked[g], key=lambda i:i['latency_ms'])
        preferred=next((n for n in ranked if n['priority']==0),None)
        nodes=(([preferred] if preferred else []) + [n for n in ranked if n is not preferred])[:max_n]
        if nodes: state='fresh'; tested_at=now
        else:
            nodes=previous_nodes(old,NAMES[g]); state='previous' if nodes else 'empty'
            tested_at=(old_report.get('groups',{}).get(g,{}) or {}).get('last_success_utc') if nodes else None
        selected[g]=nodes
        stats[g]={'status':state,'candidates_tested':len(groups[g]),'first_passed':len(first_pass[g]),'passed':len(checked[g]),'selected':len(nodes),'hysteria2_tested':sum(x['outbound']['protocol']=='hysteria' for x in groups[g]),'hysteria2_passed':sum(x['outbound']['protocol']=='hysteria' for x in checked[g]),'hysteria2_selected':sum(x['outbound']['protocol']=='hysteria' for x in nodes),'last_success_utc':tested_at}
        print(f"{g}: {state}; passed={len(checked[g])}; selected={len(nodes)}",flush=True)
    profiles=[]; normal=[n for g in ORDER[:-1] for n in selected[g]]
    if normal:
        profiles.append(profile('🌐 Автовыбор',normal))
        if len(normal)>1: profiles.append(profile('🧪 Автовыбор Burst',normal,burst=True))
    for g in ORDER[:-1]:
        if selected[g]: profiles.append(profile(NAMES[g], selected[g]))
    bypass=selected['BYPASS']
    if bypass:
        profiles.append(profile('🇪🇺 Автовыбор Обход',bypass))
        if len(bypass)>1: profiles.append(profile('🧪 Автовыбор Обход Burst',bypass,burst=True))
        profiles.append(profile(NAMES['BYPASS'],bypass)) # stores all nodes for future fallback
        for idx,node in enumerate(bypass,1): profiles.append(profile(f'🇪🇺 Обход #{idx}',[node]))
    if not profiles:
        print('No working servers and no previous profiles: output unchanged.',flush=True)
        save(REPORT,{'mode':'auto','updated_utc':now,'status':'no_working_servers','sources':source_reports,'groups':stats})
        if not OUTPUT.exists(): save(OUTPUT,[])
        return
    save(OUTPUT,profiles); save(REPORT,{'mode':'auto','updated_utc':now,'probe_url':PROBE,'verify_url':verify_url,'sources':source_reports,'groups':stats, 'notes':['Latency is measured from GitHub runner, not user device.','Backup country inferred from source label, not independently verified.','Bypass status is not verified against your network whitelist.', 'Burst and leastLoad profiles are experimental comparisons, not guaranteed improvements.']})

if __name__=='__main__': main()
