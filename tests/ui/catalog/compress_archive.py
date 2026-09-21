"""Losslessly optimize the screenshot ZIP and keep its image manifests accurate."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from PIL import Image
import collections,csv,hashlib,io,json,os,struct,time,zipfile,zlib
ROOT=Path(__file__).resolve().parents[3]
SOURCE=ROOT/'target/SirinVPN-screenshot-catalog-2026-09-12.zip'
DEST=ROOT/'target/SirinVPN-screenshot-catalog-2026-09-12-compressed.zip'
STAGE=ROOT/'.cache/screenshot-catalog-2026-09-12/lossless-compression'
PREFIX='SirinVPN-screenshot-catalog/'
LIMIT=512_000_000

def chunks(data):
 assert data[:8]==b'\x89PNG\r\n\x1a\n'
 offset=8
 while offset<len(data):
  size=struct.unpack('>I',data[offset:offset+4])[0];kind=data[offset+4:offset+8];body=data[offset+8:offset+8+size]
  assert zlib.crc32(kind+body)&0xffffffff==struct.unpack('>I',data[offset+8+size:offset+12+size])[0]
  yield kind,body
  offset+=size+12
 assert offset==len(data)

def png_chunk(kind,body):return struct.pack('>I',len(body))+kind+body+struct.pack('>I',zlib.crc32(kind+body)&0xffffffff)

def main():
 STAGE.mkdir(parents=True,exist_ok=True);start=time.monotonic();results={};completed=0
 with zipfile.ZipFile(SOURCE) as source:
  entries=source.infolist();pngs=[e for e in entries if e.filename.endswith('.png')]
  def optimize(entry):
   raw=source.read(entry);new=raw;changed=False
   with Image.open(io.BytesIO(raw)) as original:
    original.load()
    if original.mode=='RGBA' and original.getchannel('A').getextrema()==(255,255):
     encoded=io.BytesIO();original.convert('RGB').save(encoded,format='PNG',optimize=True,compress_level=9)
     generated=list(chunks(encoded.getvalue()));ancillary=[]
     for kind,body in chunks(raw):
      if kind[0]&32:
       # The removed alpha channel was uniformly opaque. Keep color-space,
       # background and other PNG metadata; sBIT now describes three channels.
       if kind==b'sBIT':body=body[:3]
       ancillary.append((kind,body))
     new=b'\x89PNG\r\n\x1a\n'+png_chunk(*generated[0])+b''.join(png_chunk(k,b) for k,b in ancillary)+b''.join(png_chunk(k,b) for k,b in generated[1:] if not k[0]&32)
     with Image.open(io.BytesIO(new)) as restored:
      restored.load()
      assert original.size==restored.size
      assert original.convert('RGBA').tobytes()==restored.convert('RGBA').tobytes(),entry.filename
     if len(new)>=len(raw):new=raw
     else:changed=True
   path=STAGE/entry.filename;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(new)
   return entry.filename,{'path':str(path),'bytes':len(new),'sha256':hashlib.sha256(new).hexdigest(),'optimized':changed,'original_bytes':len(raw)}
  with ThreadPoolExecutor(max_workers=8) as pool:
   for name,result in pool.map(optimize,pngs):
    results[name]=result;completed+=1
    if completed%200==0:print(f'Checked {completed}/{len(pngs)} PNGs',flush=True)
  optimized=sum(r['optimized'] for r in results.values());saved=sum(r['original_bytes']-r['bytes'] for r in results.values())
  print(f'PNG optimization complete: {optimized} files; {saved:,} bytes saved; decoded pixels unchanged.',flush=True)
  manifest=json.loads(source.read(PREFIX+'manifest.json'))
  for s in manifest['screenshots']:
   r=results[PREFIX+s['path']];s.update(bytes=r['bytes'],sha256=r['sha256'])
  for scenario in manifest['scenarios']:
   for f in scenario['files']:
    r=results[PREFIX+f['path']];f.update(bytes=r['bytes'],sha256=r['sha256'])
  report={'method':'Lossless PNG encoding; uniformly opaque alpha channels omitted. Original color metadata retained.','screenshots':len(pngs),'optimized_pngs':optimized,'png_bytes_saved':saved,'verification':'Decoded RGBA pixels and dimensions matched exactly for every re-encoded image. All other screenshots are byte-identical.','original_archive_bytes':SOURCE.stat().st_size,'byte_limit':LIMIT}
  manifest['compression']=report
  replacements={PREFIX+'manifest.json':(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode()}
  original_csv=io.StringIO(source.read(PREFIX+'screenshots.csv').decode());reader=csv.DictReader(original_csv);buffer=io.StringIO();writer=csv.DictWriter(buffer,fieldnames=reader.fieldnames);writer.writeheader()
  for row in reader:
   r=results[PREFIX+row['path']];row.update(bytes=r['bytes'],sha256=r['sha256']);writer.writerow(row)
  replacements[PREFIX+'screenshots.csv']=buffer.getvalue().encode()
  for doc in ['README.md','VALIDATION.md']:
   replacements[PREFIX+doc]=source.read(PREFIX+doc)+f'\nLossless archive optimization: {optimized} PNGs were re-encoded with identical decoded pixels and full original resolution. All {len(pngs)} screenshots, thumbnails and supporting files are retained. PNG hashes in manifest.json and screenshots.csv describe these optimized copies.\n'.encode()
  print('Writing compressed ZIP...',flush=True)
  temporary=DEST.with_suffix('.zip.tmp')
  with zipfile.ZipFile(temporary,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9,allowZip64=True) as z:
   for entry in entries:
    if entry.filename in results:data=Path(results[entry.filename]['path']).read_bytes()
    else:data=replacements.get(entry.filename)
    if data is None:data=source.read(entry)
    info=zipfile.ZipInfo(entry.filename,date_time=entry.date_time);info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=entry.external_attr
    z.writestr(info,data,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
   z.writestr(PREFIX+'COMPRESSION.json',json.dumps(report,indent=2)+'\n')
 assert temporary.stat().st_size<LIMIT,f'Archive still too large: {temporary.stat().st_size:,}'
 print('Checking archive integrity and every image hash...',flush=True)
 with zipfile.ZipFile(temporary) as z:
  assert z.testzip() is None
  assert len(z.namelist())==len(set(z.namelist()))
  assert sum(n.endswith('.png') for n in z.namelist())==len(pngs)
  for s in manifest['screenshots']:
   data=z.read(PREFIX+s['path']);assert len(data)==s['bytes'];assert hashlib.sha256(data).hexdigest()==s['sha256']
  assert set(e.filename for e in entries).issubset(z.namelist())
 temporary.replace(DEST)
 with DEST.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
 DEST.with_suffix('.zip.sha256').write_text(digest+'  '+DEST.name+'\n')
 report.update(archive=str(DEST),archive_bytes=DEST.stat().st_size,sha256=digest,elapsed_seconds=round(time.monotonic()-start,1),limit_headroom_bytes=LIMIT-DEST.stat().st_size)
 (STAGE/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)

if __name__=='__main__':main()
