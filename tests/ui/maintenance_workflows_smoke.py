"""Maintenance layout and behavior with synthetic native replies; no live VPN operations."""
import json
import re
from pathlib import Path
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / ".cache/maintenance-ui-2026-09-08/screenshots"
OUT.mkdir(parents=True, exist_ok=True)
FIXTURES = (ROOT / "tests/ui/fixtures.js").read_text() + (ROOT / "tests/ui/maintenance_fixtures.js").read_text()
expect.set_options(timeout=10000)
errors, checks = [], []


def capture(page, name):
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), name
    page.screenshot(path=str(OUT / f"{name}.png"))


def modal_geometry(page, name):
    dialog = page.get_by_role("dialog")
    header, body = dialog.locator(".dialog-header"), dialog.locator(".dialog-body")
    before = header.bounding_box()
    body.evaluate("el => { el.scrollTop = el.scrollHeight; }")
    after = header.bounding_box()
    assert all(abs(before[key] - after[key]) < 1 for key in ["x", "y", "width", "height"]), name
    rect = dialog.bounding_box()
    assert rect["y"] >= 0 and rect["y"] + rect["height"] <= page.viewport_size["height"] + 1, (name, rect)
    assert dialog.evaluate("el => el.scrollWidth <= el.clientWidth"), name
    for _ in range(16):
        page.keyboard.press("Tab")
        assert dialog.evaluate("el => el.contains(document.activeElement)"), (name, "focus escaped")
    body.evaluate("el => { el.scrollTop = el.scrollHeight; }")
    capture(page, name + "-scrolled")
    body.evaluate("el => { el.scrollTop = 0; }")


def settings(page, tab=None):
    page.get_by_role("navigation", name="Mobile navigation" if page.viewport_size["width"] < 761 else "Main navigation").get_by_role("button", name=re.compile("Settings")).click()
    if tab:
        page.get_by_role("tab", name=tab, exact=True).click()


def maintenance(page, label):
    settings(page, "VPS maintenance")
    page.get_by_role("button", name=re.compile(label)).click()
    page.get_by_role("button", name="Continue to VPS setup", exact=True).click()
    dialog = page.get_by_role("dialog")
    expect(dialog.locator(".dialog-header h2")).to_be_focused()
    dialog.get_by_role("button", name="SSH agent", exact=True).click()
    return dialog


with sync_playwright() as pw:
    browser = pw.chromium.launch()
    for width, height in [(1220, 780), (1024, 680), (390, 844)]:
        def page_for(scenario="disconnected", extra=""):
            page = browser.new_page(viewport={"width": width, "height": height}, reduced_motion="reduce")
            page.set_default_timeout(10000)
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.add_init_script(f'window.__sirinPlatform="desktop";window.__sirinScenario={json.dumps(scenario)};' + FIXTURES + extra)
            page.goto("http://127.0.0.1:1420", wait_until="networkidle")
            return page

        page = page_for(extra="window.__maintenance.holdRepair = true;")
        dialog = maintenance(page, "Repair VPS configuration")
        modal_geometry(page, f"{width}-repair-preparation")
        dialog.get_by_role("button", name="Repair VPS", exact=True).click()
        expect(dialog.get_by_role("heading", name="Repairing SirinVPN", exact=True)).to_be_visible()
        expect(dialog.get_by_role("button", name="Close", exact=True)).to_be_disabled()
        page.keyboard.press("Escape")
        expect(dialog).to_be_visible()
        capture(page, f"{width}-repair-running")
        page.evaluate("window.__finishRepair()")
        expect(dialog.get_by_role("heading", name="Repair complete", exact=True)).to_be_visible()
        expect(dialog.get_by_text("None configured", exact=True)).to_be_visible()
        capture(page, f"{width}-repair-complete")
        dialog.get_by_text("Network requirements · review if needed", exact=True).click()
        ports = dialog.locator(".network-port-list li").all()
        boxes = [item.bounding_box() for item in ports]
        assert len(boxes) == 3
        for i, a in enumerate(boxes):
            for b in boxes[i+1:]:
                assert a["x"] + a["width"] <= b["x"] + 1 or b["x"] + b["width"] <= a["x"] + 1 or a["y"] + a["height"] <= b["y"] + 1 or b["y"] + b["height"] <= a["y"] + 1, boxes
        modal_geometry(page, f"{width}-repair-network")
        dialog.get_by_role("button", name="Return to Home", exact=True).click()
        expect(dialog).to_have_count(0)
        page.close()

        page = page_for()
        dialog = maintenance(page, "Update VPS software")
        dialog.get_by_role("button", name="Continue", exact=True).click()
        expect(dialog.get_by_role("heading", name="Set up updates for My private VPS", exact=True)).to_be_visible()
        expect(dialog.get_by_role("checkbox", name="Automatic security updates")).to_have_count(0)
        dialog.get_by_label("Release source", exact=True).fill("https://releases.example.org/")
        capture(page, f"{width}-update-setup")
        dialog.get_by_role("button", name="Verify release", exact=True).click()
        expect(dialog.get_by_role("button", name="Finish setup", exact=True)).to_be_enabled()
        assert not page.evaluate("window.__sirinCommandArguments.some(x => x.command === 'manage_vps_release' && x.args.input.operation.action === 'install')")
        capture(page, f"{width}-update-setup-review")
        dialog.get_by_role("button", name="Finish setup", exact=True).click()
        expect(dialog.get_by_text("Update setup is complete. The installed release has been verified.", exact=True)).to_be_visible()
        page.keyboard.press("Escape")
        page.close()

        page = page_for(extra="window.__maintenance.configured=true;window.__maintenance.source='https://releases.example.org/';")
        dialog = maintenance(page, "Update VPS software")
        dialog.get_by_role("button", name="Continue", exact=True).click()
        expect(dialog.get_by_text("1.0.1", exact=True)).to_be_visible()
        expect(dialog.get_by_role("textbox", name="Release source", exact=True)).to_have_count(0)
        dialog.get_by_role("button", name="Check for updates", exact=True).click()
        expect(dialog.get_by_role("button", name="Install update 1.0.2", exact=True)).to_be_enabled()
        capture(page, f"{width}-update-review")
        modal_geometry(page, f"{width}-update")
        dialog.get_by_role("checkbox", name="Automatic security updates", exact=True).check()
        expect(dialog.get_by_text("Disabled on the VPS · Changes not yet saved", exact=True)).to_be_visible()
        page.evaluate("window.__maintenance.failSchedule=true")
        dialog.get_by_role("button", name="Save schedule", exact=True).click()
        expect(dialog.get_by_text("Could not save the schedule.", exact=True)).to_be_visible()
        capture(page, f"{width}-schedule-failed")
        page.keyboard.press("Escape")
        page.close()

        page = page_for("connected")
        settings(page, "VPS maintenance")
        trigger = page.get_by_role("button", name="Run diagnostics", exact=True)
        trigger.click()
        dialog = page.get_by_role("dialog")
        expect(dialog.get_by_text("0 need attention · 1 to review · 25 passed", exact=True)).to_be_visible()
        expect(dialog.get_by_text("Provider firewall and public reachability", exact=True)).to_be_visible()
        assert dialog.locator(".diagnostic-row strong").first.inner_text() == "Provider firewall and public reachability"
        assert not dialog.locator(".diagnostic-passed").evaluate("el => el.open")
        capture(page, f"{width}-diagnostics-review-first")
        dialog.get_by_text("Passed checks · 25", exact=True).click()
        modal_geometry(page, f"{width}-diagnostics-expanded")
        page.keyboard.press("Escape")
        expect(trigger).to_be_focused()
        page.get_by_role("navigation", name="Mobile navigation" if page.viewport_size["width"] < 761 else "Main navigation").get_by_role("button", name=re.compile("Home")).click()
        details = page.locator(".metrics-details").filter(has=page.get_by_text("Device counters & connection details", exact=False))
        details.locator("summary").click()
        expect(details.get_by_text("27.4 ms", exact=True)).to_be_visible()
        capture(page, f"{width}-home-details")
        settings(page, "General")
        wifi = page.get_by_role("region", name="Wi-Fi trust", exact=True)
        expect(wifi.get_by_text("Current network: not marked trusted", exact=True)).to_be_visible()
        expect(wifi.get_by_role("button", name="Trust current Wi-Fi", exact=True)).to_be_enabled()
        page.evaluate("window.__maintenance.wifi.automation_status='waiting_for_network_change';window.__maintenance.wifi.current_network_token='network-two'")
        expect(wifi.get_by_text(re.compile("Automation paused on this network"))).to_be_visible(timeout=8000)
        expect(wifi.get_by_role("button", name="Trust current Wi-Fi", exact=True)).to_be_disabled()
        capture(page, f"{width}-wifi-paused")
        page.close()

        page = page_for("onboarding")
        page.get_by_role("button", name="Recovery key", exact=True).click()
        page.get_by_role("textbox", name="Recovery key", exact=True).fill("sirr1.synthetic-local-recovery-material")
        page.get_by_role("button", name="Review recovery key", exact=True).click()
        expect(page.get_by_label("New Owner device name", exact=True)).to_be_visible()
        assert not page.evaluate("window.__sirinCommands.some(x => ['connect_server','connect_server_with_policy','recover_owner_access'].includes(x))")
        capture(page, f"{width}-fresh-client-recovery")
        page.get_by_role("checkbox", name=re.compile("Revoke all old Owner device identities")).check()
        page.get_by_role("button", name="Recover Owner access", exact=True).click()
        expect(page.get_by_role("navigation", name="Mobile navigation" if page.viewport_size["width"] < 761 else "Main navigation")).to_be_visible()
        assert page.evaluate("window.__sirinCommands.includes('recover_owner_access')")
        page.close()
        checks.append({"width": width, "height": height, "repair_result_and_busy_guard": True,
                       "setup_review_and_routine_update": True, "schedule_failure_visible": True,
                       "persistent_header_and_focus_trap": True, "diagnostics_order_and_focus_return": True,
                       "private_tunnel_latency": True, "wifi_pause_and_network_change_guard": True,
                       "fresh_client_recovery_without_existing_credentials": True})
    browser.close()
assert not errors, errors
report = {"synthetic_native_replies": True, "checks": checks, "page_errors": errors}
(OUT.parent / "visual-checks.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
