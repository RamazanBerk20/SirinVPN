"""Synthetic desktop checks for saved SSH logins, verification help, and alignment."""
from pathlib import Path
import json
from playwright.sync_api import expect, sync_playwright
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'.cache/vps-follow-up';OUT.mkdir(parents=True,exist_ok=True)
FIXTURE=(ROOT/'tests/ui/fixtures.js').read_text()
expect.set_options(timeout=10000)
with sync_playwright() as pw:
 browser=pw.chromium.launch()
 errors=[]
 def page_for(scenario='connected',extra='',size=(1220,780)):
  p=browser.new_page(viewport={'width':size[0],'height':size[1]},reduced_motion='reduce')
  p.on('pageerror',lambda e: errors.append(str(e)))
  p.add_init_script(f'window.__sirinPlatform="desktop";window.__sirinScenario={json.dumps(scenario)};'+FIXTURE+extra)
  p.goto('http://127.0.0.1:1420',wait_until='networkidle')
  p.evaluate('document.documentElement.dataset.windowChrome="custom"')
  return p
 p=page_for()
 p.locator('.metrics-details').filter(has_text='Device counters & connection details').locator('summary').click()
 # Copy controls must not increase one metric's value row height.
 rows=p.locator('.metrics-details').filter(has_text='Device counters & connection details').locator('dl > div')
 offsets=rows.evaluate_all('''rows=>rows.slice(0,3).map(r=>{let a=document.createRange(),b=document.createRange();a.selectNodeContents(r.querySelector('dt'));b.selectNodeContents(r.querySelector('dd .mono')||r.querySelector('dd'));return b.getBoundingClientRect().top-a.getBoundingClientRect().bottom})''')
 assert max(offsets)-min(offsets)<2,offsets
 rows.first.scroll_into_view_if_needed()
 p.screenshot(path=str(OUT/'device-counters.png'))
 p.get_by_role('navigation',name='Main navigation').get_by_role('button',name='Devices',exact=False).click()
 p.locator('.device-row-summary').first.click()
 row=p.locator('.device-facts > div').filter(has_text='Identity fingerprint').first
 alignment=row.evaluate('''r=>{let a=r.querySelector('dt'),b=r.querySelector('.copy-value .mono');let ra=document.createRange(),rb=document.createRange();ra.selectNodeContents(a);rb.selectNodeContents(b);return {label:ra.getBoundingClientRect().bottom,value:rb.getBoundingClientRect().bottom}}''')
 assert abs(alignment['label']-alignment['value'])<=3,alignment
 p.screenshot(path=str(OUT/'device-identity.png'))
 p.get_by_role('navigation',name='Main navigation').get_by_role('button',name='Settings',exact=False).click()
 p.get_by_role('tab',name='Connection',exact=True).click()
 for size in [(1220,780),(1024,680)]:
  p.set_viewport_size({'width':size[0],'height':size[1]})
  p.evaluate('document.querySelector(".workspace").scrollTop=250')
  tops=p.evaluate('''()=>({workspace:document.querySelector('.workspace').getBoundingClientRect().top,tabs:document.querySelector('.settings-tabs').getBoundingClientRect().top})''')
  assert abs(tops['workspace']-tops['tabs'])<1,tops
 p.screenshot(path=str(OUT/'settings-scroll.png'))
 p.close()
 # Returning to a maintenance dialog uses the saved login immediately.
 extra='window.__sirinSavedSshLogins={"vpn.example.com":{username:"admin",ssh_port:2222,authentication:"password",private_key_path:null}};'
 p=page_for('disconnected',extra)
 p.get_by_role('navigation',name='Main navigation').get_by_role('button',name='Settings',exact=False).click()
 p.get_by_role('tab',name='VPS maintenance',exact=True).click()
 p.get_by_role('button',name='Update VPS software',exact=False).click()
 p.get_by_role('button',name='Continue to VPS setup',exact=True).click()
 expect(p.get_by_text('Saved SSH login',exact=True)).to_be_visible()
 expect(p.get_by_label('SSH password',exact=True)).to_have_count(0)
 p.screenshot(path=str(OUT/'saved-ssh-login.png'))
 p.get_by_role('button',name='Read VPS release state',exact=True).click()
 expect(p.get_by_text('Signed baseline not registered',exact=True)).to_be_visible()
 payload=p.evaluate("window.__sirinCommandArguments.find(c=>c.command==='manage_vps_release').args.input.ssh")
 assert payload['authentication']=='saved' and payload['ssh_port']==2222 and payload['password'] is None,payload
 assert p.evaluate("window.__sirinCommands.filter(c=>c==='save_ssh_login').length")==0
 p.close()
 # Setup explains how to verify the key using a public-key-only command.
 p=page_for('onboarding')
 p.get_by_label('IP address or hostname',exact=True).fill('new.example.com')
 p.get_by_role('button',name='SSH agent',exact=True).click()
 p.get_by_role('button',name='Verify VPS',exact=False).click()
 expect(p.get_by_role('button',name='Copy verification command',exact=True)).to_be_visible()
 expect(p.get_by_text('Open this VPS on your hosting provider',exact=False)).to_be_visible()
 expect(p.get_by_role('button',name='Fingerprint matches — inspect network',exact=True)).to_be_visible()
 p.screenshot(path=str(OUT/'verify-setup.png'))
 p.close(); browser.close()
 assert not errors,errors
print(json.dumps({'checks':['VPN address matches adjacent value spacing','Device fingerprint text aligns with its label','Sticky settings tabs meet the title bar at both laptop widths','Saved password is reused without a password field or secret IPC payload','Initial setup includes a copyable public-key verification command'],'alignment':alignment,'metric_offsets':offsets},indent=2))
