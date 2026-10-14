"""VPS push-subscription UI checks with synthetic native channel events."""
import json
from pathlib import Path
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / ".cache/status-stream"
OUT.mkdir(parents=True, exist_ok=True)
FIXTURE = Path(__file__).with_name("fixtures.js").read_text()
expect.set_options(timeout=10000)

with sync_playwright() as pw:
    browser = pw.chromium.launch()
    page = browser.new_page(viewport={"width": 1220, "height": 780}, reduced_motion="reduce")
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.add_init_script('window.__sirinPlatform="desktop";window.__sirinScenario="connected";' + FIXTURE)
    page.goto("http://127.0.0.1:1420", wait_until="networkidle")
    overview = page.get_by_role("region", name="Server", exact=True)
    expect(overview.get_by_role("status")).to_have_text("Live")
    expect(page.get_by_role("button", name="Refresh current state")).to_have_count(0)
    cpu = overview.locator(".metric strong").first
    expect(cpu).to_have_text("12.4%")
    page.evaluate("window.__sirinServerOverride={cpu_usage_basis_points:4567}")
    expect(cpu).to_have_text("45.7%")
    expect(overview.get_by_role("status")).to_have_text("Live")
    assert page.evaluate("window.__sirinCommands.filter(c=>c==='server_status').length") == 0
    assert page.evaluate("window.__sirinCommands.filter(c=>c==='subscribe_server_status').length") == 1
    expect(page.locator(".device-traffic .metric strong").first).to_contain_text("KB/s")
    duration = page.locator(".device-traffic .metric").filter(has_text="Connected for").locator("strong")
    for _ in range(3):
        previous = duration.inner_text()
        expect(duration).not_to_have_text(previous, timeout=1600)
    page.screenshot(path=str(OUT / "live.png"))

    page.evaluate("window.__sirinRemoteFails=true")
    expect(overview.get_by_role("status")).to_have_text("Reconnecting…")
    expect(page.get_by_role("button", name="Disconnect", exact=True)).to_be_enabled()
    expect(overview.locator(".resource-grid")).to_have_count(0)
    page.evaluate("window.__sirinRemoteFails=false")
    expect(overview.get_by_role("status")).to_have_text("Live")

    page.evaluate("window.__sirinStreamMode='polling'")
    expect(overview.get_by_role("status")).to_have_text("Updating")
    expect(overview.get_by_text("Update the server software", exact=False)).to_be_visible()
    page.evaluate("window.__sirinStreamMode='live'")
    expect(overview.get_by_role("status")).to_have_text("Live")

    page.get_by_role("button", name="Disconnect", exact=True).click()
    expect(overview.get_by_role("status")).to_have_text("Unavailable")
    page.wait_for_function("window.__sirinCommands.includes('unsubscribe_server_status')")
    expect(overview.locator(".resource-grid")).to_have_count(0)
    assert not errors, errors
    page.close()
    # Both SSH maintenance workflows share the host-key gate: (menu item, submit, proceed, completion heading, command).
    workflows = [
        ("Update VPS software", "Continue", "Continue", "Set up updates for My private VPS", "manage_vps_release"),
        ("Repair VPS configuration", "Repair server", "Repair server", "Repair complete", "repair_server"),
    ]
    for item, submit, proceed, completed, command in workflows:
        for status in ["unknown", "trusted", "changed"]:
            page = browser.new_page(viewport={"width": 1220, "height": 780}, reduced_motion="reduce")
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.add_init_script('window.__sirinPlatform="desktop";window.__sirinScenario="disconnected";' + FIXTURE + f'window.__sirinSshTrust={json.dumps(status)};')
            page.goto("http://127.0.0.1:1420", wait_until="networkidle")
            page.get_by_role("navigation", name="Main navigation").get_by_role("button", name="Settings", exact=False).click()
            page.get_by_role("tab", name="VPS maintenance", exact=True).click()
            page.get_by_role("button", name=item, exact=False).click()
            page.get_by_role("button", name="Continue", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.get_by_role("button", name="SSH agent", exact=True).click()
            dialog.get_by_role("button", name=submit, exact=True).click()
            if status != "trusted":
                expect(dialog.get_by_role("heading", name="Server key changed" if status == "changed" else "Verify this server")).to_be_visible()
                expect(dialog.get_by_role("button", name=proceed, exact=True)).to_be_disabled()
                assert page.evaluate(f"window.__sirinCommands.filter(c=>c==='{command}').length") == 0
                page.screenshot(path=str(OUT / f"{command}-ssh-{status}.png"))
                dialog.get_by_role("checkbox", name="I verified", exact=False).check()
                dialog.get_by_role("button", name=proceed, exact=True).click()
            expect(dialog.get_by_role("heading", name=completed, exact=True)).to_be_visible()
            assert page.evaluate("window.__sirinCommands.filter(c=>c==='trust_ssh_host').length") == (0 if status == "trusted" else 1)
            sent = page.evaluate(f"window.__sirinCommandArguments.find(c=>c.command==='{command}').args.input")
            assert (sent.get("ssh") or sent)["host_key_sha256"] == "SHA256:" + "A" * 43, sent
            page.close()
    assert not errors, errors
    browser.close()

checks = ["Pushed CPU reading updates over a single subscription without snapshot requests",
    "Stable Live indicator and no manual refresh button", "Stream interruption and recovery preserve local VPN",
    "Legacy polling is labelled honestly", "Disconnect cancels the subscription and clears metrics",
    "Tunnel duration changes every second between local samples",
    "Trusted VPS update and repair skip fingerprint review; unknown and changed keys require explicit verification"]
(OUT / "checks.json").write_text(json.dumps(checks, indent=2) + "\n")
print(json.dumps(checks, indent=2))
