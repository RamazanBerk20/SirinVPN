"""Exercise member actions with synthetic IPC; never touches a real VPS."""
from pathlib import Path
import json
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / '.cache/member-lifecycle'
OUT.mkdir(parents=True, exist_ok=True)
FIXTURE = (ROOT / 'tests/ui/fixtures.js').read_text()
EXTRA = '''
const lifecycleInvoke = window.__TAURI_INTERNALS__.invoke;
window.__sirinMembership = {members:[
  {id:member,name:"You",role:"owner",devices:[{id:device,member_id:member,name:"My Linux desktop",client_tunnel_address:"10.77.0.2"}]},
  {id:"family",name:"Family",role:"member",devices:[
    {id:"phone",member_id:"family",name:"Android phone",client_tunnel_address:"10.77.0.3",recent_handshake:true},
    {id:"laptop",member_id:"family",name:"Work laptop",client_tunnel_address:"10.77.0.4",recent_handshake:true}]},
  {id:"other",name:"Other",role:"member",devices:[{id:"other-phone",member_id:"other",name:"Other phone",client_tunnel_address:"10.77.0.5"}]}
],active_invitations:[],port_forwards:[{protocol:"tcp",public_port:18080,device_port:8080,device_id:"phone"}]};
window.__TAURI_INTERNALS__.invoke = async (command,args) => {
  if(command === "server_configuration") return {...await lifecycleInvoke(command,args),member_lifecycle_enabled:window.__lifecycleAvailable !== false};
  if(["update_member_suspension","revoke_member_devices"].includes(command)) {
    window.__sirinCommands.push(command);window.__sirinCommandArguments.push({command,args});
    const target=window.__sirinMembership.members.find(m=>m.id===args.input.member_id);
    if(command === "update_member_suspension") target.suspended=args.input.suspended;
    else {
      if(args.input.confirmed !== true) throw new Error("Unconfirmed revocation");
      window.__sirinMembership.port_forwards=window.__sirinMembership.port_forwards.filter(f=>!target.devices.some(d=>d.id===f.device_id));
      window.__sirinMembership.members=window.__sirinMembership.members.filter(m=>m.id!==target.id);
    }
    return structuredClone(window.__sirinMembership);
  }
  return lifecycleInvoke(command,args);
};
'''
expect.set_options(timeout=10000)
with sync_playwright() as pw:
    browser = pw.chromium.launch()
    page = browser.new_page(viewport={'width': 1220, 'height': 780}, reduced_motion='reduce')
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.add_init_script('window.__sirinPlatform="desktop";window.__sirinScenario="connected";' + FIXTURE + EXTRA)
    page.goto('http://127.0.0.1:1420', wait_until='networkidle')
    navigation = page.get_by_role('navigation', name='Main navigation')
    navigation.get_by_role('button', name='Devices', exact=False).click()
    expect(page.get_by_role('button', name='Actions for Android phone')).to_be_visible()

    def action(label, accept=True):
        page.get_by_role('button', name='Actions for Android phone').click()
        def confirm(dialog):
            assert 'Family' in dialog.message
            (dialog.accept if accept else dialog.dismiss)()
        page.once('dialog', confirm)
        page.get_by_role('menuitem', name=label, exact=True).click()

    action('Suspend member', False)
    assert page.evaluate('window.__sirinCommands.includes("update_member_suspension")') is False
    action('Suspend member')
    expect(page.locator('.device-row[data-suspended="true"]')).to_have_count(2)
    expect(page.get_by_text('Suspended', exact=True)).to_have_count(2)
    page.get_by_role('button', name='Actions for Android phone').click()
    expect(page.get_by_role('menuitem', name='Add device for Family', exact=False)).to_be_disabled()
    bounds = page.evaluate('''()=>({menu:document.querySelector('[role="menu"]').getBoundingClientRect().top,
                                workspace:document.querySelector('.workspace').getBoundingClientRect().top})''')
    assert bounds['menu'] >= bounds['workspace'] + 8, bounds
    page.screenshot(path=str(OUT / 'member-menu.png'))
    page.keyboard.press('Escape')
    page.screenshot(path=str(OUT / 'suspended.png'))
    # Saved forwards remain listed as paused, and suspended devices leave the target chooser.
    navigation.get_by_role('button', name='Settings', exact=False).click()
    page.get_by_role('tab', name='Network', exact=True).click()
    expect(page.get_by_text('Paused', exact=False).first).to_be_visible()
    expect(page.get_by_role('option', name='Family', exact=False)).to_have_count(0)
    navigation.get_by_role('button', name='Devices', exact=False).click()
    action('Reactivate member')
    expect(page.locator('.device-row[data-suspended="true"]')).to_have_count(0)
    action('Revoke all member devices')
    expect(page.get_by_role('button', name='Actions for Android phone')).to_have_count(0)
    expect(page.get_by_role('button', name='Actions for Work laptop')).to_have_count(0)
    expect(page.get_by_role('button', name='Actions for Other phone')).to_be_visible()
    assert page.evaluate('window.__sirinMembership.port_forwards.length') == 0
    page.screenshot(path=str(OUT / 'revoked.png'))
    # The same view on an older VPS communicates the required upgrade.
    page.evaluate('window.__lifecycleAvailable=false')
    page.get_by_role('button', name='Refresh devices', exact=True).click()
    expect(page.get_by_text('Update VPS software to enable member suspension', exact=False)).to_be_visible()
    page.get_by_role('button', name='Actions for Other phone').click()
    expect(page.get_by_role('menuitem', name='Suspend member')).to_have_count(0)
    browser.close()
    assert not errors, errors
print(json.dumps({'passed': ['cancel', 'suspend every member device', 'paused forwards', 'reactivate', 'bulk revoke', 'retain other members', 'legacy VPS capability']}, indent=2))
