#!/usr/bin/env python3
"""Build an Xray JSON subscription. Do not run untrusted full configs from sources."""
import base64, concurrent.futures, copy, datetime, hashlib, ipaddress, json, os, random, re, shutil, socket, subprocess, sys, tempfile, time, urllib.parse, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SETTINGS = json.loads((ROOT / 'settings.json').read_text(encoding='utf-8'))
OUTPUT = ROOT / 'output' / 'subscription.json'
REPORT = ROOT / 'output' / 'report.json'
# User's existing five countries plus additional independently labelled feeds.
NAMES = {
    'DE':'🇩🇪 Германия', 'FI':'🇫🇮 Финляндия', 'SE':'🇸🇪 Швеция', 'NL':'🇳🇱 Нидерланды', 'US':'🇺🇸 США',
    'GB':'🇬🇧 Великобритания', 'FR':'🇫🇷 Франция', 'PL':'🇵🇱 Польша', 'CA':'🇨🇦 Канада',
    'TR':'🇹🇷 Турция', 'ES':'🇪🇸 Испания', 'CZ':'🇨🇿 Чехия', 'CH':'🇨🇭 Швейцария',
    'AT':'🇦🇹 Австрия', 'NO':'🇳🇴 Норвегия', 'JP':'🇯🇵 Япония',
    'RU':'🇷🇺 Россия', 'HK':'🇭🇰 Гонконг', 'SG':'🇸🇬 Сингапур', 'BR':'🇧🇷 Бразилия',
    'MD':'🇲🇩 Молдова', 'UA':'🇺🇦 Украина', 'BY':'🇧🇾 Беларусь', 'IN':'🇮🇳 Индия',
    'LT':'🇱🇹 Литва', 'RO':'🇷🇴 Румыния', 'RS':'🇷🇸 Сербия', 'UZ':'🇺🇿 Узбекистан', 'BYPASS':'🇪🇺 Обход'
}
COUNTRIES = ['DE','FI','SE','NL','US','GB','FR','PL','CA','TR','ES','CZ','CH','AT','NO','JP','RU','HK','SG','BR','MD','UA','BY','IN','LT','RO','RS','UZ']
ORDER = COUNTRIES + ['BYPASS']
EXTRA_COUNTRIES = COUNTRIES[5:16]
RU_DOMAINS = ['domain:ru','domain:su','domain:xn--p1ai','domain:vk.com','domain:userapi.com','domain:mail.ru','domain:ok.ru','domain:yandex.ru','domain:wink.ru','domain:more.tv','domain:kion.ru','domain:sfera.fm']
JSON_SOURCE_URLS = [
    'https://raw.githubusercontent.com/gooseteam-hackers/freevpn-cracks/refs/heads/main/subscription_auto.txt',
    'https://pozor.bond/sub/aeryxvpn',
    'https://pozor.bond/sub/9xnb9v67465y'
]
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
    if text.startswith(('[','{')): return text
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
    # Country is inferred solely from provider labels; it is not IP geolocation.
    label=label.lower()
    patterns={
        'DE':r'🇩🇪|germany|deutschland|герман|\bde\b',
        'FI':r'🇫🇮|finland|финлян|\bfi\b',
        'SE':r'🇸🇪|sweden|швец|\bse\b',
        'NL':r'🇳🇱|netherlands|nederland|нидерланд|\bnl\b',
        'US':r'🇺🇸|united states|\busa\b|сша|\bus\b',
        'GB':r'🇬🇧|united kingdom|great britain|britain|england|великобритан|англи|\bgb\b|\buk\b',
        'FR':r'🇫🇷|france|франци|франц|\bfr\b',
        'PL':r'🇵🇱|poland|польш|\bpl\b',
        'CA':r'🇨🇦|canada|канад|\bca\b',
        'TR':r'🇹🇷|turkey|türkiye|турци|турец|\btr\b',
        'ES':r'🇪🇸|spain|españa|испани|\bes\b',
        'CZ':r'🇨🇿|czechia|czech republic|чехи|\bcz\b',
        'CH':r'🇨🇭|switzerland|швейцар|\bch\b',
        'AT':r'🇦🇹|austria|австри|\bat\b',
        'NO':r'🇳🇴|norway|норвег|\bnor\b',
        'JP':r'🇯🇵|japan|япони|\bjp\b',
        'RU':r'🇷🇺|russia|росси|\bru\b', 'HK':r'🇭🇰|hong kong|гонконг|\bhk\b',
        'SG':r'🇸🇬|singapore|сингапур|\bsg\b', 'BR':r'🇧🇷|brazil|бразили|\bbr\b',
        'MD':r'🇲🇩|moldova|молдов|\bmd\b', 'UA':r'🇺🇦|ukraine|украин|\bua\b',
        'BY':r'🇧🇾|belarus|беларус|белорус', 'IN':r'🇮🇳|india|инди|\bind\b',
        'LT':r'🇱🇹|lithuania|литв|\blt\b', 'RO':r'🇷🇴|romania|румыни|\bro\b',
        'RS':r'🇷🇸|serbia|серби|\brs\b', 'UZ':r'🇺🇿|uzbekistan|узбекист|\buz\b'
    }
    matches=[k for k,v in patterns.items() if re.search(v,label)]
    return matches[0] if len(matches)==1 else None

def unambiguous_json_country(label):
    """Do not pretend inconsistent country labels are verified locations."""
    labels=re.findall(r'[🇦-🇿]{2}',label)
    if len(set(labels))>1: return None
    flag_code=None
    if labels:
        flag_code=''.join(chr(ord(ch)-0x1F1E6+ord('A')) for ch in labels[0])
    bracket_codes=re.findall(r'\[([A-Za-z]{2})\]',label)
    code=None
    if bracket_codes:
        raw=bracket_codes[0].upper()
        code={'UK':'GB','SW':'SE','TK':'TR','BL':'BE'}.get(raw,raw)
    # An unsupported or conflicting flag/code is never guessed into a country.
    if code and flag_code and code != flag_code: return None
    if code: return code if code in COUNTRIES else None
    if flag_code: return flag_code if flag_code in COUNTRIES else None
    return inferred_group(label)

def safe_sockopt(value):
    if value is None: return None
    if not isinstance(value,dict) or set(value)-{'domainStrategy','tcpKeepAliveIdle','tcpKeepAliveInterval','tcpNoDelay'}:
        raise ValueError('unsupported socket options')
    if len(json.dumps(value))>1024: raise ValueError('socket options too large')
    return copy.deepcopy(value)

def parse_xray_vless(outbound, label):
    """Extract a safe, supported single VLESS outbound; never run input JSON."""
    try:
        if not isinstance(outbound,dict) or outbound.get('protocol')!='vless': return None
        if set(outbound)-{'tag','protocol','settings','streamSettings','mux'}: return None
        if (outbound.get('mux') or {}).get('enabled',False): return None
        settings=outbound['settings']
        if set(settings)-{'vnext'} or len(settings.get('vnext',[]))!=1: return None
        next_hop=settings['vnext'][0]
        if set(next_hop)-{'address','port','users'} or len(next_hop.get('users',[]))!=1: return None
        host=next_hop['address'];port=next_hop['port'];user=next_hop['users'][0]
        if not isinstance(host,str) or not check_address(host) or not isinstance(port,int) or not 1<=port<=65535: return None
        if set(user)-{'id','encryption','flow','level','security'}: return None
        uuid=user.get('id','')
        if not isinstance(uuid,str) or not re.fullmatch(r'[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}',uuid): return None
        if user.get('encryption','none') not in ('','none'): return None
        if user.get('security','auto') not in ('','auto','none'): return None
        new_user={'id':uuid,'encryption':'none'}
        if user.get('flow'): new_user['flow']=user['flow']
        stream=outbound['streamSettings']
        allowed={'network','security','tlsSettings','realitySettings','xhttpSettings','wsSettings','grpcSettings','tcpSettings','finalmask','sockopt'}
        if set(stream)-allowed: return None
        network=stream.get('network','tcp');network='tcp' if network=='raw' else network
        security=stream.get('security')
        if network not in ('tcp','ws','grpc','xhttp') or security not in ('tls','reality'): return None
        output={'network':network,'security':security}
        sockopt=safe_sockopt(stream.get('sockopt'))
        if sockopt is not None: output['sockopt']=sockopt
        src_tls=stream.get('tlsSettings',{}) if security=='tls' else stream.get('realitySettings',{})
        if not isinstance(src_tls,dict): return None
        tls_keys={'serverName','fingerprint','alpn','show','allowInsecure'} if security=='tls' else {'serverName','fingerprint','publicKey','shortId','spiderX','show','mldsa65Verify'}
        if set(src_tls)-tls_keys or src_tls.get('allowInsecure') not in (None,False): return None
        if security=='reality' and not src_tls.get('publicKey'): return None
        safe_tls={k:copy.deepcopy(v) for k,v in src_tls.items() if k in tls_keys-{'show','allowInsecure'}}
        if security=='tls': safe_tls['allowInsecure']=False
        output['tlsSettings' if security=='tls' else 'realitySettings']=safe_tls
        transport_keys={'tcp':('tcpSettings',{'header'}),'ws':('wsSettings',{'path','headers'}),
                        'grpc':('grpcSettings',{'serviceName','multiMode','authority'}),
                        'xhttp':('xhttpSettings',{'path','host','mode','extra','scMaxEachPostBytes','scMaxConcurrentPosts','scMinPostsIntervalMs','xPaddingBytes','noGRPCHeader'})}
        key, permitted=transport_keys[network];opts=stream.get(key,{})
        if not isinstance(opts,dict) or set(opts)-permitted: return None
        if network=='tcp' and opts.get('header',{}).get('type','none')!='none': return None
        if network=='ws' and set(opts.get('headers',{})) - {'Host','host'}: return None
        if network=='xhttp':
            extra=opts.get('extra',{})
            if not isinstance(extra,dict): return None
            if set(extra)-{'scMaxEachPostBytes','scMaxConcurrentPosts','scMinPostsIntervalMs','xPaddingBytes','noGRPCHeader','xmux','noSSEHeader','mode'}: return None
            if len(json.dumps(extra))>4096: return None
        if opts: output[key]=copy.deepcopy(opts)
        mask=stream.get('finalmask')
        if mask is not None:
            if not isinstance(mask,dict) or set(mask)-{'tcp'}: return None
            entries=mask.get('tcp',[])
            if not isinstance(entries,list) or len(entries)>3: return None
            for entry in entries:
                if not isinstance(entry,dict) or set(entry)-{'type','settings'} or entry.get('type')!='fragment': return None
                fragment=entry.get('settings',{})
                if not isinstance(fragment,dict) or set(fragment)-{'delay','length','packets','maxSplit'}: return None
                if any(not isinstance(v,(str,int,float)) or isinstance(v,bool) for v in fragment.values()): return None
            output['finalmask']=copy.deepcopy(mask)
        safe={'protocol':'vless','settings':{'vnext':[{'address':host,'port':port,'users':[new_user]}]},'streamSettings':output,'mux':{'enabled':False}}
        return {'outbound':safe,'priority':0 if network=='tcp' and security=='reality' else 1,'label':str(label)[:256]}
    except (KeyError,TypeError,ValueError,AttributeError): return None

def parse_xray_trojan(outbound, label):
    try:
        if not isinstance(outbound,dict) or outbound.get('protocol')!='trojan': return None
        settings=outbound['settings']; servers=settings['servers']
        if set(settings)-{'servers'} or not isinstance(servers,list) or len(servers)!=1: return None
        server=servers[0]
        if set(server)-{'address','port','password'}: return None
        password=server.get('password')
        if not isinstance(password,str) or not password or len(password)>256: return None
        # Reuse the strict stream parser with a dummy UUID; do not execute source JSON.
        dummy=copy.deepcopy(outbound); dummy['protocol']='vless'
        dummy['settings']={'vnext':[{'address':server['address'],'port':server['port'],'users':[{'id':'00000000-0000-4000-8000-000000000001','encryption':'none'}]}]}
        item=parse_xray_vless(dummy,label)
        if not item: return None
        item['outbound']['protocol']='trojan'
        item['outbound']['settings']={'servers':[{'address':server['address'],'port':server['port'],'password':password}]}
        item['priority']=1
        return item
    except (KeyError,TypeError,ValueError): return None

def parse_xray_hysteria(outbound, label):
    try:
        if not isinstance(outbound,dict) or outbound.get('protocol')!='hysteria': return None
        if set(outbound)-{'tag','protocol','settings','streamSettings','mux'}: return None
        if (outbound.get('mux') or {}).get('enabled',False): return None
        st=outbound['settings']; stream=outbound['streamSettings']
        if set(st)-{'version','address','port'} or st.get('version')!=2: return None
        host=st.get('address');port=st.get('port')
        if not isinstance(host,str) or not check_address(host) or not isinstance(port,int) or not 1<=port<=65535: return None
        if set(stream)-{'network','method','security','tlsSettings','hysteriaSettings','sockopt','finalmask'}: return None
        if stream.get('network',stream.get('method'))!='hysteria' or stream.get('method','hysteria')!='hysteria' or stream.get('security')!='tls': return None
        h=stream.get('hysteriaSettings',{})
        if not isinstance(h,dict) or set(h)-{'version','auth'} or h.get('version')!=2: return None
        auth=h.get('auth')
        if not isinstance(auth,str) or not auth or len(auth)>256: return None
        tls=stream.get('tlsSettings',{})
        if not isinstance(tls,dict) or set(tls)-{'serverName','fingerprint','alpn','allowInsecure','enableSessionResumption'}: return None
        if tls.get('allowInsecure') not in (None,False): return None
        if tls.get('alpn') and tls['alpn']!=['h3']: return None
        safe_tls=copy.deepcopy(tls);safe_tls['allowInsecure']=False;safe_tls.setdefault('alpn',['h3'])
        transport={'network':'hysteria','security':'tls','tlsSettings':safe_tls,'hysteriaSettings':{'version':2,'auth':auth}}
        sockopt=safe_sockopt(stream.get('sockopt'))
        if sockopt is not None: transport['sockopt']=sockopt
        mask=stream.get('finalmask')
        if mask is not None:
            if not isinstance(mask,dict) or set(mask)-{'udp'} or not isinstance(mask.get('udp'),list) or len(mask['udp'])>3: return None
            for entry in mask['udp']:
                if not isinstance(entry,dict) or set(entry)-{'type','settings'} or entry.get('type')!='salamander': return None
                obfs=entry.get('settings',{})
                if not isinstance(obfs,dict) or set(obfs)-{'password'} or not isinstance(obfs.get('password'),str) or len(obfs['password'])>256: return None
            transport['finalmask']=copy.deepcopy(mask)
        safe={'protocol':'hysteria','settings':{'version':2,'address':host,'port':port},'streamSettings':transport}
        return {'outbound':safe,'priority':1,'label':str(label)[:256]}
    except (KeyError,TypeError,ValueError,AttributeError): return None

def parse_xray_json_source(raw):
    """Extract supported outbounds from country and LTE profiles only."""
    try:
        data=json.loads(raw)
        if not isinstance(data,list) or len(data)>2000: return []
        result=[]
        for entry in data:
            if not isinstance(entry,dict): continue
            name=entry.get('remarks','')
            if not isinstance(name,str) or 'автовыбор' in name.lower() or len(name)>512: continue
            target='BYPASS' if re.search(r'(?i)\blte\b|обход\s+глушилок',name) else unambiguous_json_country(name)
            if target not in ORDER: continue
            nodes=entry.get('outbounds',[])
            if not isinstance(nodes,list) or len(nodes)>300: continue
            for outbound in nodes:
                if not isinstance(outbound,dict): continue
                proto=outbound.get('protocol')
                if proto=='vless': item=parse_xray_vless(outbound,name)
                elif proto=='trojan': item=parse_xray_trojan(outbound,name)
                elif proto=='hysteria': item=parse_xray_hysteria(outbound,name)
                else: continue
                if item: result.append((target,item))
        return result
    except (ValueError,TypeError,AttributeError,RecursionError): return []

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

def reference_auto(name, groups):
    """Build one auto profile in the format supplied by the user."""
    nodes=[]
    for group,items in groups:
        for index,item in enumerate(items,1):
            ob=copy.deepcopy(item['outbound'])
            label=NAMES[group]
            ob['tag']=label if index==1 else f'{label} {index}'
            nodes.append(ob)
    if not nodes: return None
    tags=[o['tag'] for o in nodes]
    sock_in, http_in = inbounds()
    http_in['settings']={'allowTransparent':False}
    http_in['sniffing']={'enabled':True,'destOverride':['http','tls','quic']}
    return {
        'log':{'loglevel':'warning'},
        'remarks':name,
        'meta':{'serverDescription':'Сам выбирает конфиг'},
        'burstObservatory':{
            'subjectSelector':tags,
            'pingConfig':{'destination':'http://www.gstatic.com/generate_204','interval':'3m','sampling':5,'timeout':'3s'}
        },
        'inbounds':[sock_in,http_in],
        'outbounds':nodes + [
            {'protocol':'freedom','tag':'direct'},
            {'protocol':'blackhole','settings':{},'tag':'block'},
            {'protocol':'dns','tag':'dns-out'}
        ],
        'stats':{},
        'policy':{'system':{'statsInboundUplink':True,'statsInboundDownlink':True,'statsOutboundUplink':True,'statsOutboundDownlink':True}},
        'routing':{
            'domainStrategy':'AsIs','domainMatcher':'hybrid',
            'balancers':[{'tag':'auto','selector':tags,'fallbackTag':tags[0],
                          'strategy':{'type':'leastLoad','settings':{'expected':1,'maxRTT':'2s','tolerance':0.25}}}],
            'rules':[{'type':'field','ip':['geoip:private'],'outboundTag':'block'},
                     {'type':'field','domain':RU_DOMAINS,'outboundTag':'direct'},
                     {'type':'field','network':'tcp,udp','balancerTag':'auto'}]
        }
    }

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

def previous_bypass_nodes(profiles):
    # Accept both the original aggregate and the new numbered groups.
    aggregate=previous_nodes(profiles,NAMES['BYPASS'])
    if aggregate: return aggregate[:64]
    result=[]; seen=set()
    for number in range(1,9):
        for item in previous_nodes(profiles,f'🇪🇺 Обход #{number}'):
            key=hashlib.sha256(json.dumps(item['outbound'],sort_keys=True).encode()).hexdigest()
            if key not in seen:
                seen.add(key); result.append(item)
    return result[:64]

def split_bypass_groups(nodes):
    """Make up to eight non-overlapping, reasonably balanced groups of <=8."""
    if not nodes: return []
    nodes=nodes[:64]
    count=min(8,(len(nodes)+7)//8)
    sizes=[len(nodes)//count + (1 if i < len(nodes)%count else 0) for i in range(count)]
    groups=[[] for _ in range(count)]
    pool=list(nodes)
    # Put a VLESS/TCP/Reality node first in each group when possible.
    for group in groups:
        idx=next((i for i,n in enumerate(pool) if n.get('priority')==0),None)
        if idx is not None: group.append(pool.pop(idx))
    for i,group in enumerate(groups):
        while len(group)<sizes[i] and pool: group.append(pool.pop(0))
    return groups

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
    # Add these public JSON sources only if not already explicitly configured.
    configured_urls={source.get('url','').split('?',1)[0] for source in sources}
    for url in JSON_SOURCE_URLS:
        if url not in configured_urls: sources.append({'group':'JSON','url':url})
    # Add missing country-labelled public feeds without modifying user's settings.
    configured={source.get('group') for source in sources}
    for code in EXTRA_COUNTRIES:
        if code not in configured:
            sources.append({'group':code,'url':f'https://raw.githubusercontent.com/theakres/VPN/main/countries/{code}','auto_country':True})
    # Optional URL goes in GitHub Actions secrets, never in this public file.
    extra=os.environ.get('EXTRA_SOURCE_URL','').strip()
    if extra and not any(source.get('url')==extra for source in sources):
        sources.append({'group':'BACKUP','url':extra})
    for source in sources:
        group=source['group']; report={'group':group}
        try:
            raw=fetch_source(source['url']); found=[]
            if source['url'].split('?',1)[0] in JSON_SOURCE_URLS:
                candidates=parse_xray_json_source(raw)
            else:
                candidates=[]
                for line in raw.splitlines():
                    line=line.strip()
                    if not line.startswith(('vless://','trojan://','hysteria2://','hy2://')): continue
                    item=parse_link(line)
                    if not item: continue
                    target=inferred_group(item['label']) if group=='BACKUP' else group
                    candidates.append((target,item))
            for target,item in candidates:
                if target not in groups: continue
                key=hashlib.sha256(json.dumps(item['outbound'],sort_keys=True).encode()).hexdigest()
                if key in seen[target]: continue
                found.append((target,key,item))
            source_limit=min(limit,16) if source.get('auto_country') else (min(limit*3,100) if source['url'].split('?',1)[0] in JSON_SOURCE_URLS else limit)
            # Reserve test slots for Reality, Hysteria2 and other supported protocols.
            # Sorting only by Reality here would starve Hysteria in large feeds.
            random.shuffle(found)
            reality=[x for x in found if x[2]['priority']==0]
            hy=[x for x in found if x[2]['outbound']['protocol']=='hysteria']
            other=[x for x in found if x[2]['priority']!=0 and x[2]['outbound']['protocol']!='hysteria']
            picked=[]
            quotas=[(reality,(source_limit+1)//2),(hy,(source_limit+2)//4),(other,source_limit//4)]
            for pool,quota in quotas:
                take=pool[:quota];picked.extend(take);del pool[:len(take)]
            for pool in (reality,hy,other):
                take=pool[:max(0,source_limit-len(picked))];picked.extend(take)
            found=picked[:source_limit]
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
        preferred=[n for n in ranked if n['priority']==0][:(8 if group=='BYPASS' else 1)]
        preferred_ids={id(n) for n in preferred}
        pool=(preferred + [n for n in ranked if id(n) not in preferred_ids])[:(80 if group=='BYPASS' else 15)]
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
    max_n=max(1,min(int(SETTINGS.get('max_per_country',10)),20)); selected={}; stats={}; now=timestamp()
    for g in ORDER:
        # Reserve up to eight Reality nodes for distinct BYPASS groups; all
        # other positions go to fastest verified nodes of any protocol.
        ranked=sorted(checked[g], key=lambda i:i['latency_ms'])
        preferred=[n for n in ranked if n['priority']==0][:(8 if g=='BYPASS' else 1)]
        preferred_ids={id(n) for n in preferred}
        group_limit=64 if g=='BYPASS' else max_n
        nodes=(preferred + [n for n in ranked if id(n) not in preferred_ids])[:group_limit]
        if nodes: state='fresh'; tested_at=now
        else:
            nodes=previous_bypass_nodes(old) if g=='BYPASS' else previous_nodes(old,NAMES[g]); state='previous' if nodes else 'empty'
            tested_at=(old_report.get('groups',{}).get(g,{}) or {}).get('last_success_utc') if nodes else None
        selected[g]=nodes
        stats[g]={'status':state,'candidates_tested':len(groups[g]),'first_passed':len(first_pass[g]),'passed':len(checked[g]),'selected':len(nodes),'hysteria2_tested':sum(x['outbound']['protocol']=='hysteria' for x in groups[g]),'hysteria2_passed':sum(x['outbound']['protocol']=='hysteria' for x in checked[g]),'hysteria2_selected':sum(x['outbound']['protocol']=='hysteria' for x in nodes),'last_success_utc':tested_at}
        print(f"{g}: {state}; passed={len(checked[g])}; selected={len(nodes)}",flush=True)
    profiles=[]; normal_groups=[(g,selected[g][:4]) for g in COUNTRIES if selected[g]]
    if normal_groups: profiles.append(reference_auto('🇪🇺 Автовыбор',normal_groups))
    for g in ORDER[:-1]:
        if selected[g]: profiles.append(profile(NAMES[g], selected[g]))
    bypass=selected['BYPASS']
    if bypass:
        profiles.append(reference_auto('🇪🇺 Автовыбор Обход',[('BYPASS',bypass)]))
        # Each profile has its own disjoint group of up to eight servers.
        for idx, group in enumerate(split_bypass_groups(bypass), 1):
            profiles.append(profile(f'🇪🇺 Обход #{idx}',group))
    if not profiles:
        print('No working servers and no previous profiles: output unchanged.',flush=True)
        save(REPORT,{'mode':'auto','updated_utc':now,'status':'no_working_servers','sources':source_reports,'groups':stats})
        if not OUTPUT.exists(): save(OUTPUT,[])
        return
    save(OUTPUT,profiles); save(REPORT,{'mode':'auto','updated_utc':now,'probe_url':PROBE,'verify_url':verify_url,'sources':source_reports,'groups':stats, 'notes':['Latency is measured from GitHub runner, not user device.','Country labels come from sources and are not independently verified.','Bypass status is not verified against your network whitelist.']})

if __name__=='__main__': main()
