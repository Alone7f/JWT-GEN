import os, sys, json, ssl, gzip, time, http.client, base64
from io import BytesIO
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests, urllib3
from flask import Flask, request, jsonify, Response as FlaskResponse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import MajoRLoGinrEs_pb2

urllib3.disable_warnings()

API_KEY        = "Alone"
WEB_PORT       = 8789
CLIENT_SECRET  = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
CLIENT_VERSION = "1.132.18"
RESPONSE_HEADER_LEN = 64
DEFAULT_REGION = "BD"

AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
AES_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

GPS_URLS = {
    "BD":  "https://clientbp.ppmainecoonghj.com/GetPlayerPersonalShow",
    "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
    "NA":  "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
}
REGION_TO_GPS = {
    "BD":"BD","SG":"BD","TW":"BD","MY":"BD","PK":"BD","TH":"BD","VN":"BD","ID":"BD","ME":"BD",
    "IND":"IND","IN":"IND",
    "EU":"NA","BR":"NA","US":"NA","NA":"NA","RU":"NA","SAC":"NA","EUROPE":"NA",
}
PLATFORM_MAP = {1:"Facebook",2:"VK",4:"Guest",7:"Google",8:"Huawei"}

app = Flask(__name__)

def encrypt_api(b):
    return AES.new(AES_KEY,AES.MODE_CBC,AES_IV).encrypt(pad(b,16))

def _aes_decrypt(data):
    try:
        dec=AES.new(AES_KEY,AES.MODE_CBC,AES_IV).decrypt(data)
        p=dec[-1]
        if 1<=p<=16 and all(b==p for b in dec[-p:]): return dec[:-p]
    except: pass
    return b""

def encode_varint(n):
    out=[]
    while True:
        b=n&0x7F; n>>=7
        if n: b|=0x80
        out.append(b)
        if not n: break
    return bytes(out)

def create_field(num,val):
    if isinstance(val,int): return encode_varint((num<<3)|0)+encode_varint(val)
    if isinstance(val,(str,bytes)):
        v=val.encode() if isinstance(val,str) else val
        return encode_varint((num<<3)|2)+encode_varint(len(v))+v
    return b""

def build_proto(fields):
    return b"".join(create_field(k,v) for k,v in fields.items())

def decode_varint(data,pos):
    result=0;shift=0
    while pos<len(data):
        b=data[pos];pos+=1
        result|=(b&0x7F)<<shift
        if not(b&0x80): break
        shift+=7
    return result,pos

def parse_raw_proto(data):
    fields={};pos=0
    while pos<len(data):
        try:
            tag,pos=decode_varint(data,pos)
            fn=tag>>3;wt=tag&7
            if wt==0: v,pos=decode_varint(data,pos);fields[fn]=v
            elif wt==2:
                l,pos=decode_varint(data,pos);v=data[pos:pos+l];pos+=l
                try: fields[fn]=v.decode('utf-8')
                except: fields[fn]=v
            elif wt==5: pos+=4
            elif wt==1: pos+=8
            else: break
        except: break
    return fields

def decode_jwt(token):
    try:
        parts=token.split(".")
        p=parts[1]+"="*(-len(parts[1])%4)
        return json.loads(base64.urlsafe_b64decode(p).decode())
    except: return {}

_ver_cache={"data":None,"ts":0}
def get_version_config():
    now=time.time()
    if _ver_cache["data"] and (now-_ver_cache["ts"])<3600:
        return _ver_cache["data"]
    try:
        r=requests.get(
            "https://version.ggwhitehawk.com/live/ver.php?version=1.0.0"
            "&lang=en&device=android&channel=android&appstore=googleplay&region=BD"
            "&release_version=OB55&whitelist_version=1.8.1&whitelist_sp_version=1.0.0",
            verify=False,timeout=5)
        d=r.json()
        import urllib.parse as _up
        _p=_up.urlparse(d.get("server_url",""))
        host=_p.netloc or _p.path or "loginbp.ppmainecoonghj.com"
        remote_ver=d.get("remote_version","1.132.18")
        rv=d.get("latest_release_version","OB55")
        result=(host,rv,remote_ver)
    except:
        result=("loginbp.ppmainecoonghj.com","OB55","1.132.18")
    _ver_cache["data"]=result; _ver_cache["ts"]=now
    return result

def get_oauth(uid,password):
    try:
        r=requests.post(
            "https://100067.connect.garena.com/oauth/guest/token/grant",
            headers={"Host":"100067.connect.garena.com","User-Agent":"Dalvik/2.1.0",
                     "Content-Type":"application/x-www-form-urlencoded","Connection":"close"},
            data={"uid":uid,"password":password,"response_type":"token","client_type":"2",
                  "client_secret":CLIENT_SECRET,"client_id":"100067"},
            verify=False,timeout=5)
        if r.status_code==200:
            j=r.json(); return j.get("access_token"),j.get("open_id"),j.get("platform",4)
    except: pass
    return None,None,None

def build_payload(open_id,access_token,region="BD",client_ver=CLIENT_VERSION):
    fields={3:str(datetime.now())[:-7],4:"free fire",5:1,7:client_ver,
        8:"Android OS 15 / API-35 (AP3A.240617.008/T.R4T2.24e2a71-650ec)",
        9:"Handheld",10:"airtel now cirkle",11:"WIFI",12:1666,13:750,14:"360",
        15:"ARM64 FP ASIMD AES | 2000 | 8",16:7723,17:"Mali-G52 MC2",
        18:"OpenGL ES 3.2 v1.r49p1-03bet0.19498e0ae1d5dac223383c39a2e58f04",
        19:"Google|3744f365-78fe-424a-871e-f77a0a095356",20:"103.109.214.50",
        21:"bn",22:open_id,23:"8",24:"Handheld",25:"realme RMX3710",
        26:region,29:access_token,30:1,41:"airtel now cirkle",42:"WIFI",
        57:"7428b253defc164018c604a1ebbfebdf",60:225554,61:155321,62:733,
        64:155845,65:225554,66:155845,67:225554,73:2,
        74:"/data/app/~~ln8dFa29BUuPBtG4A-WwXQ==/com.dts.freefireth/lib/arm64",76:1,
        77:"b8e0cd5e295eee42f5860d3c86e483dd|/data/app/base.apk",
        78:3,79:2,81:"64",83:"2019121229",85:3,86:"OpenGLES2",87:8191,88:8,
        92:9754,93:"android",
        94:"KqsHT+PFj/2sTPjf+unI9C5rnnStUzOFVqOADw9TI8tgL2bTnmzrBM/dEzyqy4BtAVua+w9mgLRIMrjXa67/qXm0pz5uQWsxC6sd8Um7OmMNHRmy",
        95:111207,96:'{"cur_rate":[60,45,90],"support_etc2":false}',
        97:1,99:"4",100:"4",102:"4455414f055f5f0336",104:52972,105:1,
        106:"https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|6b2078db9d22dd98f8e9386a39af8462",
        107:"c8e41b7a93f02d56e1a94c7b8203f5d1"}
    return build_proto(fields)


def get_account_brief_info(open_id, access_token, login_host, rv):
    try:
        proto = create_field(1, open_id)
        body  = encrypt_api(proto)
        ctx   = ssl._create_unverified_context()
        conn  = http.client.HTTPSConnection(login_host, context=ctx, timeout=8)
        conn.request("POST", "/GetAccountBriefInfoBeforeLogin", body=body, headers={
            'User-Agent':      'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Accept':          '*/*',
            'Accept-Encoding': 'deflate, gzip',
            'Authorization':   'Bearer',
            'X-Ga':            'v1 1',
            'X-Ga-Sv':         '1794143783',
            'Releaseversion':  rv,
            'Content-Type':    'application/x-www-form-urlencoded',
            'X-Unity-Version': '2018.4.12f1',
        })
        resp = conn.getresponse(); raw = resp.read()
        if resp.getheader("Content-Encoding") == "gzip":
            with gzip.GzipFile(fileobj=BytesIO(raw)) as f2: raw = f2.read()
        conn.close()
        if resp.status != 200: return None
        f = parse_raw_proto(raw)
        if not f: return None
        nickname = f.get(2, "")
        if isinstance(nickname, bytes):
            try: nickname = nickname.decode('utf-8')
            except: nickname = ""
        level    = str(f.get(5, ""))
        region   = f.get(6, "")
        if isinstance(region, bytes):
            try: region = region.decode('utf-8')
            except: region = ""
        acc_id   = str(f.get(1, ""))
        return {"nickname": nickname.strip(), "level": level, "region": region.strip(), "account_id": acc_id}
    except Exception as e:
        return None

def decode_ban(raw):
    ban_reason=""; ban_time=0; ban_expire=0
    for offset in [RESPONSE_HEADER_LEN,0]:
        blob=raw[offset:] if len(raw)>offset else b""
        if not blob: continue
        rf=parse_raw_proto(blob)
        if 13 not in rf: continue
        nested=rf[13]
        if isinstance(nested,str):
            try: nested=nested.encode()
            except: nested=b""
        if isinstance(nested,bytes):
            nf=parse_raw_proto(nested)
            bt=nf.get(3,0); ban_time=int(bt) if str(bt).isdigit() else 0
            rs=nf.get(4,"")
            if isinstance(rs,bytes):
                try: rs=rs.decode()
                except: rs=""
            if rs.strip(): ban_reason=rs.strip()
            elif nf.get(1,0): ban_reason=f"Violation #{nf.get(1)}"
            ed=nf.get(2,0); ban_expire=int(ed) if isinstance(ed,int) else 0
        break
    return ban_reason,ban_time,ban_expire

def get_player_info(account_id,token,gps_url,release_ver="OB55"):
    try:
        proto=create_field(1,int(account_id))
        body=encrypt_api(proto)
        r=requests.post(gps_url,data=body,headers={
            'User-Agent':'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Authorization':f'Bearer {token}',
            'Content-Type':'application/x-www-form-urlencoded',
            'X-GA':'v1 1','X-GA-SV':'1794143783',
            'ReleaseVersion':release_ver,
            'Accept':'*/*','Accept-Encoding':'deflate, gzip',
        },verify=False,timeout=5)
        raw=r.content
        if len(raw)>=16 and len(raw)%16==0:
            dec=_aes_decrypt(raw)
            if dec and len(dec)>4: raw=dec
        for blob in [raw,raw[RESPONSE_HEADER_LEN:] if len(raw)>RESPONSE_HEADER_LEN else b""]:
            if not blob: continue
            f=parse_raw_proto(blob)
            if f: return f
    except: pass
    return None

def extract_nickname_level(fields):
    nickname=""; level=""
    if not fields: return nickname,level
    acc=fields.get(1)
    if isinstance(acc,bytes):
        sub=parse_raw_proto(acc)
        v=sub.get(3,"")
        if isinstance(v,str) and len(v)>0: nickname=v
        elif isinstance(v,bytes):
            try: nickname=v.decode('utf-8')
            except: pass
        lv=sub.get(6,"")
        if lv: level=str(lv)
    if not nickname:
        acc=fields.get(4)
        if isinstance(acc,bytes):
            sub=parse_raw_proto(acc)
            v=sub.get(3,"")
            if isinstance(v,str) and len(v)>0: nickname=v
            lv=sub.get(6,"")
            if lv: level=str(lv)
    return nickname.strip(),level.strip()

@app.get("/token")
def api_token():
    start=time.time()
    if request.args.get("key","").strip()!=API_KEY:
        return jsonify({"status":"error","message":"Invalid API key"}),403
    uid=request.args.get("uid","").strip()
    password=request.args.get("password","").strip()
    if not uid or not password:
        return jsonify({"status":"error","message":"Missing uid or password"}),400
    if not uid.isdigit() or len(uid)<8:
        return jsonify({"status":"error","message":"Invalid UID"}),400

    at,oid,plat=get_oauth(uid,password)
    if not at:
        return jsonify({"status":"error","message":"OAuth failed"}),400

    host,rv,client_ver=get_version_config()
    payload=build_payload(oid,at,client_ver=client_ver)
    body=encrypt_api(payload)
    try:
        ctx=ssl._create_unverified_context()
        conn=http.client.HTTPSConnection(host,context=ctx,timeout=8)
        conn.request("POST","/MajorLogin",body=body,headers={
            'User-Agent':'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Accept':'*/*','Accept-Encoding':'deflate, gzip','Authorization':'Bearer',
            'X-Ga':'v1 1','X-Ga-Sv':'1794143783','Releaseversion':rv,
            'Content-Type':'application/x-www-form-urlencoded','X-Unity-Version':'2018.4.12f1',
        })
        resp=conn.getresponse(); raw=resp.read()
        if resp.getheader("Content-Encoding")=="gzip":
            with gzip.GzipFile(fileobj=BytesIO(raw)) as f2: raw=f2.read()
        conn.close()
    except Exception as e:
        return jsonify({"status":"error","message":str(e)}),400

    ban_reason,ban_time,ban_expire=decode_ban(raw)
    if ban_reason:
        is_perm=(ban_expire==0)
        import datetime as _dt2
        ff_tz2=_dt2.timezone(_dt2.timedelta(hours=8))
        bds=_dt2.datetime.fromtimestamp(int(ban_time),tz=ff_tz2).strftime("%Y-%m-%d %H:%M:%S") if ban_time>0 else _dt2.datetime.now(ff_tz2).strftime("%Y-%m-%d %H:%M:%S")
        brief=get_account_brief_info(str(oid),at,host,rv)
        b_nick  = brief.get("nickname","Unknown") if brief else "Unknown"
        b_level = brief.get("level","Unknown") if brief else "Unknown"
        b_region= brief.get("region","Unknown") if brief else "Unknown"
        b_accid = brief.get("account_id",None) if brief else None
        b_success = bool(b_nick and b_nick!="Unknown")
        if is_perm:
            return FlaskResponse(json.dumps({
                "success":b_success,
                "nickname":b_nick,
                "account_id":b_accid,
                "level":b_level,
                "region":b_region,
                "reason":ban_reason,
                "ban_type":"permanent_ban",
                "ban_date":bds,
                "remaining_time":"Permanent",
                "timestamp":int(ban_time) if ban_time else int(time.time()),
                "access_token":at,
                "open_id":str(oid),
                "elapsed":f"{time.time()-start:.2f}s",
            },ensure_ascii=False,indent=2),status=200,mimetype="application/json")
        else:
            expire_ts=int(ban_time)+int(ban_expire) if ban_time>0 else int(time.time())+int(ban_expire)
            import datetime as _dt
            ff_tz=_dt.timezone(_dt.timedelta(hours=8))
            es=_dt.datetime.fromtimestamp(expire_ts,tz=ff_tz).strftime("%Y-%m-%d %H:%M:%S")
            rem=int(ban_expire)
            if rem>0:
                d=rem//86400; h=(rem%86400)//3600; m=(rem%3600)//60; s=rem%60
                rs=f"{d}d {h}h {m}m {s}s"
            else: rs="Expired"
            now=int(time.time())
            return FlaskResponse(json.dumps({
                "success":b_success,
                "nickname":b_nick,
                "account_id":b_accid,
                "level":b_level,
                "region":b_region,
                "reason":ban_reason,
                "ban_type":"temporary_ban",
                "ban_date":bds,
                "ban_expire":es,
                "remaining_time":rs,
                "timestamp":now,
                "access_token":at,
                "open_id":str(oid),
                "elapsed":f"{time.time()-start:.2f}s",
            },ensure_ascii=False,indent=2),status=200,mimetype="application/json")

    res=None
    for blob in [raw[RESPONSE_HEADER_LEN:] if len(raw)>RESPONSE_HEADER_LEN else b"",raw]:
        if not blob: continue
        try:
            m=MajoRLoGinrEs_pb2.MajorLoginRes(); m.ParseFromString(blob)
            if m.account_id>0 and m.token: res=m; break
        except: pass
    if not res or not res.token:
        return jsonify({"status":"error","message":"No JWT token received"}),400

    jp=decode_jwt(res.token)
    account_id=str(jp.get("account_id",res.account_id or ""))
    lock_region=res.lock_region or jp.get("lock_region",DEFAULT_REGION)
    platform_id=int(jp.get("external_type",4))
    platform_str=PLATFORM_MAP.get(platform_id,"Guest")
    rel_version=jp.get("release_version",rv)
    server_url=res.server_url or ""
    city=res.ip_city or ""
    state=res.ip_subdivision or ""
    status_str=res.agora_environment or "live"

    gps_key=REGION_TO_GPS.get(lock_region.upper(),"BD")
    gps_url=GPS_URLS.get(gps_key,GPS_URLS["BD"])
    nickname=""; level=""
    if account_id:
        pf=get_player_info(account_id,res.token,gps_url,rel_version)
        nickname,level=extract_nickname_level(pf)

    elapsed=time.time()-start
    return FlaskResponse(json.dumps({
        "success":True,"nickname":nickname,"account_id":account_id,"level":level,
        "region":lock_region,"platform":platform_str,"platformId":platform_id,
        "release_version":rel_version,"access_token":at,"open_id":str(oid),
        "api":server_url,"status":status_str,"state":state,"city":city,
        "elapsed":f"{elapsed:.2f}s","token":res.token,
    },ensure_ascii=False,indent=2),status=200,mimetype="application/json")

# Vercel-এ এই block কখনোই run হবে না (module import হয়, __main__ না)
if __name__=="__main__":
    print(f"JWT API running on port {WEB_PORT}")
    app.run(host="0.0.0.0",port=WEB_PORT,debug=False,threaded=True)