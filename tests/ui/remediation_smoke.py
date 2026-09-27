"""Rendered remediation states; synthetic native responses, no real VPN operations.

Start pinned pnpm --dir apps/desktop dev on 127.0.0.1:1420, then run with
Python Playwright/Chromium. Output is local-only, fictional screenshots and JSON.
"""
import json
import argparse
from pathlib import Path
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, default=ROOT / "target/remediation-evidence/ui")
OUT = parser.parse_args().output
OUT.mkdir(parents=True)  # Preserve prior failures/screenshots; use a fresh run directory.
FIXTURE = (ROOT / "tests/ui/fixtures.js").read_text()
STORAGE = """
const invokeNative = window.__TAURI_INTERNALS__.invoke;
let storage = {supported:true,policy:'secure_store_required',pending_cleanup:1,profiles:[{
  server_id:'fixture',name:'A long synthetic server name for storage status',storage:{
    backend:'private_file',protection:'permissions_only',availability:'available',cleanup_pending:false}}]};
window.__sirinCleanupFails = true;
window.__TAURI_INTERNALS__.invoke = async (command, args) => {
  if(command !== 'credential_storage') return invokeNative(command, args);
  if(args.action === 'allow_private_file') storage.policy = 'allow_private_file';
  if(args.action === 'require_secure') storage.policy = 'secure_store_required';
  if(args.action === 'retry_cleanup') {
    if(window.__sirinCleanupFails) throw 'Credential cleanup is incomplete. Unlock the keyring and retry.';
    storage.pending_cleanup = 0;
  }
  if(args.action === 'migrate') storage.profiles[0].storage = {
    backend:'keyring',protection:'system_secure_store',availability:'available',cleanup_pending:false};
  return structuredClone(storage);
};
"""
checks, errors = [], []
expect.set_options(timeout=10000)

with sync_playwright() as pw:
    browser = pw.chromium.launch()
    for width, height in [(1220, 780), (1024, 680)]:
        page = browser.new_page(viewport={"width": width, "height": height}, reduced_motion="reduce")
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.add_init_script('window.__sirinPlatform="desktop";window.__sirinScenario="disconnected";' + FIXTURE + STORAGE)
        page.goto("http://127.0.0.1:1420", wait_until="networkidle")
        page.get_by_role("navigation", name="Main navigation").get_by_role("button", name="Settings", exact=False).click()
        page.get_by_role("tab", name="General", exact=True).click()
        card = page.locator("section").filter(has=page.get_by_role("heading", name="Credential storage", exact=True)).last
        allow = card.get_by_role("button", name="Allow file fallback", exact=True)
        expect(allow).to_be_disabled()
        consent = card.get_by_role("switch")
        for selected in (False, True):
            if selected:
                consent.focus()
                page.keyboard.press("Space")
                expect(consent).to_be_checked()
            card.screenshot(path=str(OUT / f"{width}-consent-{selected}.png"))
            width_px, height_px, thumb = consent.evaluate("el => [el.getBoundingClientRect().width, el.getBoundingClientRect().height, getComputedStyle(el, '::after').content]")
            assert width_px > height_px and thumb not in ("none", "normal"), "Storage consent must use the preference switch track and thumb"
        switch = page.get_by_role("switch", name="Interface animations", exact=True)
        width_px, height_px, thumb = switch.evaluate("el => [el.getBoundingClientRect().width, el.getBoundingClientRect().height, getComputedStyle(el, '::after').content]")
        assert width_px > height_px and thumb not in ("none", "normal"), "Preference switch must retain its track and thumb"
        expect(allow).to_be_enabled()
        allow.focus()
        page.keyboard.press("Enter")
        expect(card.get_by_role("status")).to_contain_text("not encrypted")
        card.get_by_role("button", name="Retry credential cleanup", exact=True).click()
        expect(card.get_by_role("alert")).to_contain_text("cleanup is incomplete")
        card.scroll_into_view_if_needed()
        page.screenshot(path=str(OUT / f"{width}-partial-cleanup.png"))
        page.evaluate("window.__sirinCleanupFails = false")
        card.get_by_role("button", name="Retry credential cleanup", exact=True).click()
        expect(card.get_by_role("button", name="Retry credential cleanup", exact=True)).to_have_count(0)
        card.get_by_role("button", name="Migrate to keyring", exact=True).click()
        expect(card.get_by_text("System keyring · available", exact=True)).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "Horizontal overflow"
        page.screenshot(path=str(OUT / f"{width}-migrated.png"))
        checks.append({"viewport": [width, height], "consent_keyboard": True,
                       "consistent_preference_switches": True,
                       "partial_cleanup_retry": True, "migration_acknowledged": True})
        page.close()
    page = browser.new_page(viewport={"width": 1024, "height": 680})
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.add_init_script('window.__sirinPlatform="desktop";' + FIXTURE + """
window.__sirinServerOverride={authorization_recovery:{health:'recovery_failed',generation:3,
  containment_verified:false,committed:true}};
""")
    page.goto("http://127.0.0.1:1420", wait_until="networkidle")
    expect(page.get_by_text("Server authorization enforcement is unavailable. Do not rely on this server until recovery succeeds.", exact=True)).to_be_visible()
    page.screenshot(path=str(OUT / "authorization-unverified.png"))
    checks.append({"authorization_failure_visible": True})
    page.close()
    for width, height, font in [(320, 640, 100), (390, 844, 125)]:
        page = browser.new_page(viewport={"width": width, "height": height},
            user_agent="Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 Chrome/143.0.0.0 Mobile Safari/537.36",
            reduced_motion="reduce")
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.add_init_script('window.__sirinPlatform="android";' + FIXTURE + """
window.__sirinServerOverride={authorization_recovery:{health:'recovery_failed',generation:3,
  containment_verified:false,committed:true}};
const native = window.__TAURI_INTERNALS__.invoke;
window.__TAURI_INTERNALS__.invoke = async (command, args) => {
  if(command === 'android_watch' || command === 'android_unwatch') return null;
  if(command === 'plugin:app|registerListener' || command === 'plugin:app|removeListener') return null;
  if(command === 'android_call') return {ok: args.command === 'android_snapshot'
    ? {status:local(),phase:'connected',generation:1,sequence:1,quick_profile:id,operation:null}
    : await native(args.command, args.args)};
  return native(command,args);
};
""")
        page.goto("http://127.0.0.1:1420", wait_until="networkidle")
        page.add_style_tag(content=f"html {{ font-size: {font}% !important; }}")
        expect(page.get_by_text("Server authorization enforcement is unavailable. Do not rely on this server until recovery succeeds.", exact=True)).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "Mobile horizontal overflow"
        page.screenshot(path=str(OUT / f"android-{width}-{font}-recovery.png"), full_page=True)
        checks.append({"platform": "synthetic Android browser", "viewport": [width, height],
                       "font_percent": font, "authorization_failure_visible": True, "reduced_motion": True})
        page.close()
    browser.close()

assert not errors, errors
report = {"fixture": "synthetic browser; no native enforcement claim", "checks": checks, "errors": errors}
(OUT / "results.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
