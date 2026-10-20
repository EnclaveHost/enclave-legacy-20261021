"""Verify CARs and reconstruct replicas with bounded RAM; public artifacts only."""
import sys, pathlib, json, hashlib, urllib.request
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent.parent/'wasm'))
from ipfs_fetch import _uvarint, _cid_info, _parse_dagpb, _unixfs_data, cid_str_to_bytes, RAW_CODEC, DAGPB_CODEC, SHA2_256

def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def varint(f):
 value=0
 for shift in range(0,70,7):
  c=f.read(1)
  if not c:raise ValueError('truncated varint')
  value|=(c[0]&127)<<shift
  if not c[0]&128:return value
 raise ValueError('oversized varint')
def reconstruct(car,target,entry):
 with open(car,'rb') as f:
  size=car.stat().st_size;hlen=varint(f)
  if hlen>1<<20 or f.tell()+hlen>size:raise ValueError('bad CAR header')
  f.seek(hlen,1);blocks={}
  while f.tell()<size:
   length=varint(f);start=f.tell()
   if length>4<<20 or start+length>size:raise ValueError('bad CAR block length')
   block=f.read(length);cid,info,pos=_cid_info(block,0)
   if pos>length or info['mh_code']!=SHA2_256 or len(info['digest'])!=32 or hashlib.sha256(block[pos:]).digest()!=info['digest']:raise ValueError('CAR block hash mismatch')
   blocks[cid]=(start+pos,length-pos,info['codec'])
   if len(blocks)>100000:raise ValueError('too many blocks')
  stack=[cid_str_to_bytes(entry['cid'])];total=0;visits=0;out=target.with_suffix('.verified-part');digest=hashlib.sha256()
  with open(out,'wb') as w:
   while stack:
    visits+=1
    if visits>16*len(blocks)+entry['bytes']//4096+4096:raise ValueError('DAG work budget exceeded')
    offset,length,codec=blocks[stack.pop()];f.seek(offset);block=f.read(length)
    if codec==RAW_CODEC:payload=block
    elif codec==DAGPB_CODEC:
     links,body=_parse_dagpb(block)
     if links:stack.extend(reversed(links));continue
     payload=_unixfs_data(body)
    else:raise ValueError('unsupported block codec')
    total+=len(payload)
    if total>entry['bytes']:raise ValueError('object exceeds manifest size')
    w.write(payload);digest.update(payload)
  if total!=entry['bytes'] or digest.hexdigest()!=entry['sha256']:raise ValueError('reconstructed object mismatch')
  out.replace(target)

def main():
 manifest,directory=sys.argv[1:3];source=sys.argv[3] if len(sys.argv)>3 else None
 root=pathlib.Path(directory);root.mkdir(parents=True,exist_ok=True)
 entries=json.load(open(manifest))['verifiedObjects']
 if not isinstance(entries,list) or len(entries)>4096:raise ValueError('bounded replica manifest required')
 for e in entries:
  if type(e.get('bytes')) is not int or not 0<=e['bytes']<=1<<30:raise ValueError('artifact size must be 0..1 GiB')
  for k in ['sha256','carSha256']:
   if not isinstance(e.get(k),str) or len(e[k])!=64 or any(c not in '0123456789abcdef' for c in e[k]):raise ValueError('manifest digest required')
 for i,e in enumerate(entries):
  cid=e['cid']
  if not cid.startswith('b') or any(c not in 'abcdefghijklmnopqrstuvwxyz234567' for c in cid):raise ValueError('invalid CID')
  car=root/(cid+'.car');raw=root/(cid+'.bin')
  if not car.exists() or sha(car)!=e['carSha256']:
   if not source:raise ValueError('missing valid CAR '+cid)
   tmp=car.with_suffix('.download')
   with urllib.request.urlopen(source+'/ipfs/'+cid+'?format=car&dag-scope=all',timeout=60) as r,open(tmp,'wb') as w:
    total=0
    while True:
     b=r.read(1<<20)
     if not b:break
     total+=len(b)
     if total>e['bytes']+max(2<<20,e['bytes']//10):raise ValueError('oversized replica response')
     w.write(b)
   if sha(tmp)!=e['carSha256']:raise ValueError('download digest mismatch '+cid)
   tmp.replace(car)
  reconstruct(car,raw,e)
  print(json.dumps({'verified':i+1,'total':len(entries),'cid':cid}),flush=True)
if __name__=='__main__':main()
