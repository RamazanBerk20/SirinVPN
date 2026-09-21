"""Make smaller, independently readable review uploads without splitting a scenario."""
import csv,io,json,zipfile,collections,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];OUT=ROOT/'target/screenshot-catalog-2026-09-12';DEST=ROOT/'target/SirinVPN-review-batches-2026-09-12';DEST.mkdir(exist_ok=True)
m=json.loads((OUT/'manifest.json').read_text());index=[]
for platform in ['desktop']:
 bycase=collections.defaultdict(list)
 for s in m['screenshots']:
  if s['platform']==platform:bycase[(s['family'],s['scenario'])].append(s)
 batches=[];batch=[];size=0
 for key,shots in sorted(bycase.items()):
  nextsize=sum(s['bytes'] for s in shots)
  if batch and size+nextsize>85*1024**2:batches.append(batch);batch=[];size=0
  batch+=shots;size+=nextsize
 if batch:batches.append(batch)
 for number,shots in enumerate(batches,1):
  name=f'{platform}-{number:02d}-{shots[0]["family"]}-to-{shots[-1]["family"]}.zip';path=DEST/name
  buffer=io.StringIO();writer=csv.DictWriter(buffer,fieldnames=['platform','family','scenario','description','path','width','height','sha256']);writer.writeheader();writer.writerows({k:s[k] for k in writer.fieldnames} for s in shots)
  with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1) as z:
   for s in shots:z.write(OUT/s['path'],s['path'])
   z.writestr('BATCH-INDEX.csv',buffer.getvalue());z.writestr('README.md',f'# SirinVPN review batch\n\n{len(shots)} original {platform} screenshots across {len(set(s["scenario"] for s in shots))} scenarios. This is part {number} of {len(batches)} for {platform}. It is a subset of the complete archive. BATCH-INDEX.csv lists exactly the images included here. Read REVIEW_WITH_CHATGPT.md and coverage.md for the review instructions and scope.\n\nAll server data are fictional. Current production UI components are rendered in native shells. Native operating-system surfaces and native tray/confirmation previews are documented in the full manifest. No real server identity is included.\n')
   for doc in ['REVIEW_WITH_CHATGPT.md','coverage.md']:z.write(OUT/doc,doc)
  with zipfile.ZipFile(path) as z:
   assert z.testzip() is None
   assert sum(n.endswith('.png') for n in z.namelist())==len(shots)
  index.append({'file':name,'platform':platform,'images':len(shots),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
  print(name,len(shots),round(path.stat().st_size/1024**2,1),'MiB',flush=True)
(DEST/'batches.json').write_text(json.dumps(index,indent=2)+'\n')
(DEST/'README.md').write_text('# Smaller SirinVPN review archives\n\nThese independently readable ZIPs contain the same original screenshots as the full archive, divided into smaller uploads without splitting a scenario. Every PNG appears in exactly one batch. Each ZIP includes its own filename index and review instructions.\n\n'+'\n'.join(f'- [{b["file"]}]({b["file"]}) — {b["images"]} images, {b["bytes"]/1024**2:.1f} MiB' for b in index)+'\n')
assert sum(b['images'] for b in index)==len(m['screenshots'])
print('Verified total:',sum(b['images'] for b in index),flush=True)
