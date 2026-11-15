"""
GPS Debug — নিজের uid/pass দিয়ে JWT নাও, তারপর GPS response এর সব field দেখাও
"""
import os, sys, json, ssl, gzip, time, http.client, base64, requests, urllib3
from io import BytesIO
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import MajoRLoGinrEs_pb2
urllib3.disable_warnings()

AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
AES_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
CLIENT_VERSION = "1.132.18"
RESPONSE_HEADER_LEN = 64

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

def get_oauth(uid,password):
    r=requests.post(
        "https://100067.connect.garena.com/oauth/guest/token/grant",
        headers={"Host":"100067.connect.garena.com","User-Agent":"Dalvik/2.1.0",
                 "Content-Type":"application/x-www-form-urlencoded","Connection":"close"},
        data={"uid":uid,"password":password,"response_type":"token","client_type":"2",
              "client_secret":CLIENT_SECRET,"client_id":"100067"},
        verify=False,timeout=5)
    j=r.json(); return j.get("access_token"),j.get("open_id")

def build_payload(oid,at):
    fields={3:str(datetime.now())[:-7],4:"free fire",5:1,7:CLIENT_VERSION,
        8:"Android OS 15 / API-35 (AP3A.240617.008/T.R4T2.24e2a71-650ec)",
        9:"Handheld",10:"airtel now cirkle",11:"WIFI",12:1666,13:750,14:"360",
        15:"ARM64 FP ASIMD AES | 2000 | 8",16:7723,17:"Mali-G52 MC2",
        18:"OpenGL ES 3.2 v1.r49p1-03bet0.19498e0ae1d5dac223383c39a2e58f04",
        19:"Google|3744f365-78fe-424a-871e-f77a0a095356",20:"103.109.214.50",
        21:"bn",22:oid,23:"8",24:"Handheld",25:"realme RMX3710",
        26:"BD",29:at,30:1,41:"airtel now cirkle",42:"WIFI",
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
    return b"".join(create_field(k,v) for k,v in fields.items())

# ── STEP 1: Login ──
UID = input("UID: ").strip()
PWD = input("Password: ").strip()

print("\n[1] OAuth...")
at,oid = get_oauth(UID,PWD)
print(f"    at={at[:15] if at else None}")

print("[2] Version config...")
vr=requests.get(
    f"https://version.ggwhitehawk.com/live/ver.php?version={CLIENT_VERSION}"
    "&lang=en&device=android&channel=android&appstore=googleplay&region=BD"
    "&release_version=OB55&whitelist_version=1.8.1&whitelist_sp_version=1.0.0",
    verify=False,timeout=5)
vd=vr.json()
import urllib.parse as _up
_p=_up.urlparse(vd.get("server_url",""))
host=_p.netloc or _p.path or "loginbp.ppmainecoonghj.com"
rv=vd.get("latest_release_version","OB55")
print(f"    host={host} rv={rv}")

print("[3] MajorLogin...")
body=encrypt_api(build_payload(oid,at))
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
print(f"    HTTP={resp.status} len={len(raw)}")

m=MajoRLoGinrEs_pb2.MajorLoginRes()
for blob in [raw[RESPONSE_HEADER_LEN:] if len(raw)>RESPONSE_HEADER_LEN else b"",raw]:
    try:
        m.ParseFromString(blob)
        if m.account_id>0 and m.token: break
    except: pass

print(f"    account_id={m.account_id} region={m.lock_region}")
token=m.token
account_id=str(m.account_id)
lock_region=m.lock_region or "BD"

jp=decode_jwt(token)
print(f"    JWT nickname={jp.get('nickname','?')}")

# ── STEP 2: GPS ──
gps_key=REGION_TO_GPS.get(lock_region.upper(),"BD")
gps_url=GPS_URLS.get(gps_key,GPS_URLS["BD"])
print(f"\n[4] GetPlayerPersonalShow → {gps_url}")
print(f"    account_id={account_id}")

proto=create_field(1,int(account_id))
gps_body=encrypt_api(proto)
print(f"    request hex: {gps_body.hex()}")

r=requests.post(gps_url,data=gps_body,headers={
    'User-Agent':'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
    'Authorization':f'Bearer {token}',
    'Content-Type':'application/x-www-form-urlencoded',
    'X-GA':'v1 1','X-GA-SV':'1794143783',
    'ReleaseVersion':rv,
    'Accept':'*/*','Accept-Encoding':'deflate, gzip',
},verify=False,timeout=8)
print(f"    HTTP={r.status_code} len={len(r.content)}")

raw_gps=r.content
print(f"    raw hex: {raw_gps.hex()[:80]}")

# try decrypt
dec=_aes_decrypt(raw_gps)
if dec and len(dec)>4:
    print(f"    decrypted len={len(dec)}")
    print(f"    dec hex: {dec.hex()[:80]}")
    raw_gps=dec

print(f"\n=== GPS ALL FIELDS ===")
for label,blob in [("raw",raw_gps),("raw+64",raw_gps[64:] if len(raw_gps)>64 else b"")]:
    if not blob: continue
    f=parse_raw_proto(blob)
    if not f: continue
    print(f"-- offset={label} --")
    for k,v in f.items():
        if isinstance(v,bytes):
            try: vs=v.decode('utf-8')
            except: vs=v.hex()[:60]
            print(f"  field {k}: {vs[:60]}")
            nf=parse_raw_proto(v)
            if nf:
                for nk,nv in nf.items():
                    if isinstance(nv,bytes):
                        try: nvs=nv.decode('utf-8')
                        except: nvs=nv.hex()[:40]
                    else: nvs=nv
                    print(f"    nested {nk}: {nvs}")
        else:
            print(f"  field {k}: {v}")
    break
