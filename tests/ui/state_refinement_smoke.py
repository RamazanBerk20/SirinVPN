"""Synthetic UI state/scrolling tests; firewall evidence comes from network tests."""
import json
from pathlib import Path
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / ".cache/state-refinement"
OUT.mkdir(parents=True, exist_ok=True)
FIXTURE = Path(__file__).with_name("fixtures.js").read_text()
SERVER = "123e4567-e89b-42d3-a456-426614174000"
checks = []
expect.set_options(timeout=10000)
with sync_playwright() as pw:
    browser = pw.chromium.launch()
    page = browser.new_page(viewport={"width":1220,"height":780}, reduced_motion="reduce", locale="tr-TR")
    page.add_init_script('window.__sirinPlatform="desktop";window.__sirinScenario="connected";' + FIXTURE)
    page.goto("http://127.0.0.1:1420", wait_until="networkidle")
    nav = page.get_by_role("navigation", name="Main navigation")
    policy = {"kill_switch":True,"automatic_reconnect":False,"connect_on_startup":True}
    page.evaluate("p => window.__sirinLocalOverride={policy:p,supervisor_status_known:true,kill_switch_state:'armed',kill_switch_enabled:true,allow_lan:true,startup_service_enabled:true,connect_on_startup:true,tunnel_uptime_seconds:24}", policy)
    expect(page.locator(".connection-facts")).to_contain_text("Armed")
    expect(page.locator(".device-traffic")).to_contain_text("00:24")
    expect(page.locator(".protection-evidence")).to_have_count(0)
    assert page.locator(".resource-grid").evaluate("el=>el.getBoundingClientRect().bottom<=innerHeight"), "Connected protection + LAN summary must fit"
    page.screenshot(path=str(OUT / "connected.png"))
    page.get_by_text("Device counters & connection details", exact=False).click()
    expect(page.get_by_text("Internet IPv6 blocked · local network allowed", exact=True)).to_be_visible()
    expect(page.get_by_text("412,890", exact=True)).to_be_visible()
    checks.append("Connected LAN/protection Home fits 1220×780; verified IPv6, 00:24 duration, and English packet grouping on a Turkish host locale")
    page.evaluate("window.__sirinLocalOverride.supervisor_status_known=undefined")
    expect(page.locator(".protection-evidence")).to_have_text("IPv6 verification unavailable")
    checks.append("Missing enforcement evidence remains visible from the main protection status")
    nav.get_by_role("button", name="Settings", exact=True).click()
    page.get_by_role("tab", name="Keys & recovery", exact=True).click()
    page.set_viewport_size({"width":958,"height":620})
    sidebar = page.locator(".sidebar")
    before = sidebar.bounding_box()
    logo = page.locator(".sidebar .brand").bounding_box()
    page.locator(".workspace").hover()
    page.mouse.wheel(0, 1200)
    page.wait_for_function("document.querySelector('.workspace').scrollTop>0")
    assert sidebar.bounding_box() == before
    assert page.locator(".sidebar .brand").bounding_box() == logo
    assert page.evaluate("scrollY") == 0
    assert abs(before["y"] + before["height"] - 620) < 1
    assert page.locator(".settings-tabs").bounding_box()["y"] >= 38
    # Keyboard focus must stay beneath the sticky tab row in the content pane.
    buttons = page.locator(".settings-panel button:enabled")
    buttons.last.focus()
    page.keyboard.press("Shift+Tab")
    page.wait_for_function("document.activeElement.getBoundingClientRect().top >= document.querySelector('.settings-tabs').getBoundingClientRect().bottom")
    assert sidebar.bounding_box() == before
    page.screenshot(path=str(OUT / "recovery-scrolled.png"))
    checks.append("Wheel and keyboard scrolling keep the title bar/sidebar fixed and settings controls visible at 958×620")
    page.get_by_role("tab", name="Connection", exact=True).click()
    page.get_by_role("switch", name="Connect on system startup").check()
    page.get_by_role("switch", name="Kill switch", exact=True).check()
    page.get_by_role("button", name="Save preferences", exact=True).click()
    expect(page.locator(".startup-connection-state")).to_contain_text("enabled for this server")
    nav.get_by_role("button", name="Home", exact=True).click()
    page.evaluate("window.__sirinLocalOverride={startup_service_enabled:false}")
    page.get_by_role("button", name="Disconnect & release block", exact=True).click()
    expect(page.locator(".connection-facts")).to_contain_text("Not active · enabled for next connection")
    expect(page.get_by_role("button", name="Refresh current state")).to_have_count(0)
    nav.get_by_role("button", name="Devices", exact=True).click()
    page.get_by_role("button", name="Open Home", exact=True).click()
    expect(nav.get_by_role("button", name="Home", exact=True)).to_have_attribute("aria-current", "page")
    nav.get_by_role("button", name="Settings", exact=True).click()
    page.get_by_role("tab", name="Connection", exact=True).click()
    expect(page.get_by_role("switch", name="Connect on system startup")).to_be_checked()
    expect(page.locator(".startup-connection-state")).to_contain_text("Not active")
    before_connects = page.evaluate("window.__sirinCommands.filter(c=>c==='connect_server_with_policy').length")
    page.get_by_role("button", name="Connect & activate startup", exact=True).click()
    page.wait_for_function("n=>window.__sirinCommands.filter(c=>c==='connect_server_with_policy').length===n+1", arg=before_connects)
    checks.append("Manual Disconnect retains saved switches, exposes inactive startup, hides unusable metrics refresh, and gives explicit Home/activation actions")
    page.get_by_role("tab", name="Network", exact=True).click()
    expect(page.locator(".settings-panel")).to_contain_text("Configuration changes use verified SSH access")
    nav.get_by_role("button", name="Home", exact=True).click()
    page.evaluate("window.__sirinServerOverride={peer_activity_supported:false,recently_active_peer_count:undefined}")
    page.get_by_role("button", name="Review VPS update", exact=True).click()
    expect(page.get_by_role("dialog")).to_contain_text("Update")
    expect(page.get_by_role("dialog").get_by_role("button", name="Continue to VPS setup")).to_be_disabled()
    assert not page.evaluate("window.__sirinCommands.includes('repair_server')")
    page.keyboard.press("Escape")
    checks.append("Older VPS activity has an update review; maintenance keeps its explicit local disconnect and SSH gate")
    # Text enlargement: preserve controls, scroll containment and horizontal access.
    page.set_viewport_size({"width":1220,"height":780})
    page.add_style_tag(content=":root {font-size:32px}")
    page.get_by_role("tab", name="Keys & recovery", exact=True).click()
    assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
    assert page.locator(".workspace").evaluate("el=>el.scrollWidth<=el.clientWidth")
    checks.append("Recovery at 200% root text size preserves horizontal containment")
    browser.close()
(OUT / "ui-state-checks.json").write_text(json.dumps(checks, indent=2) + "\n")
print(json.dumps(checks, indent=2))
