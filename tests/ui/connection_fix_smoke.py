"""Check the September 8 GUI fixes using synthetic native responses only.

Start Vite on 127.0.0.1:1420; run with Python Playwright and Chromium.
No real helper installation, SSH request, or VPN operation is performed.
"""
import json
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / ".cache/connection-fix-2026-09-08/screenshots"
OUT.mkdir(parents=True, exist_ok=True)
FIXTURE = (ROOT / "tests/ui/fixtures.js").read_text()
expect.set_options(timeout=10000)
checks = []
errors = []


def capture(page, name):
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), name
    assert page.locator('[role="alert"]').evaluate_all(
        "items => items.every(item => item.textContent.trim().length > 0)"
    ), (name, "Empty error box")
    page.screenshot(path=str(OUT / f"{name}.png"))


with sync_playwright() as pw:
    browser = pw.chromium.launch()
    for width, height in [(1220, 780), (1024, 680)]:
        def page_for(scenario, extra=""):
            page = browser.new_page(viewport={"width": width, "height": height}, reduced_motion="reduce")
            page.set_default_timeout(10000)
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.add_init_script(
                f'window.__sirinPlatform="desktop";window.__sirinScenario={json.dumps(scenario)};'
                + FIXTURE + extra
            )
            page.goto("http://127.0.0.1:1420", wait_until="networkidle")
            return page

        page = page_for("disconnected")
        page.get_by_role("navigation", name="Main navigation").get_by_role("button", name="Settings", exact=False).click()
        wifi = page.locator(".settings-card").filter(has=page.get_by_role("heading", name="Wi-Fi trust"))
        expect(wifi.get_by_text("Current Wi-Fi is untrusted", exact=True)).to_be_visible()
        expect(wifi.get_by_role("alert")).to_have_count(0)
        wifi.scroll_into_view_if_needed()
        capture(page, f"{width}-wifi-no-empty-error")
        page.get_by_role("button", name="Review local component", exact=True).click()
        dialog = page.get_by_role("dialog")
        expect(dialog.get_by_role("button", name="Update local VPN component", exact=True)).to_be_enabled()
        capture(page, f"{width}-component-review")
        dialog.get_by_role("button", name="Update local VPN component", exact=True).click()
        expect(dialog.get_by_role("status")).to_contain_text("The local VPN component is updated")
        assert page.evaluate("window.__sirinCommandArguments.some(item => item.command === 'install_local_vpn_component' && item.args.confirmed === true)")
        page.keyboard.press("Escape")
        page.get_by_role("tab", name="VPS maintenance", exact=True).click()
        page.get_by_role("button", name="Update VPS software", exact=False).click()
        page.get_by_role("button", name="Continue to VPS setup", exact=True).click()
        dialog = page.get_by_role("dialog")
        dialog.get_by_role("button", name="SSH agent", exact=True).click()
        dialog.get_by_role("button", name="Read VPS release state", exact=True).click()
        source = dialog.get_by_label("HTTPS release directory", exact=True)
        expect(source).to_be_visible()
        expect(dialog.get_by_role("combobox", name="Release channel", exact=True)).to_be_visible()
        assert source.bounding_box()["height"] >= 40
        capture(page, f"{width}-vps-update-fields")
        page.close()

        page = page_for("onboarding", "window.__sirinLoginDelay=1800;")
        page.get_by_label("IP address or hostname", exact=True).fill("vps.example.com")
        expect(page.get_by_text("Checking for a saved SSH login…", exact=True)).to_be_visible()
        username = page.get_by_label("SSH username", exact=True)
        expect(username).to_be_disabled()
        before = username.bounding_box()
        capture(page, f"{width}-ssh-lookup")
        expect(username).to_be_enabled()
        after = username.bounding_box()
        assert all(abs(before[key] - after[key]) < 1 for key in ["x", "y", "width", "height"]), (before, after)
        page.get_by_role("button", name="SSH agent", exact=True).click()
        page.get_by_role("button", name="Verify VPS", exact=False).click()
        confirm = page.get_by_role("button", name="Fingerprint matches — inspect network", exact=True)
        expect(confirm).to_have_count(1)
        expect(page.get_by_role("button", name="Install SirinVPN", exact=True)).to_have_count(0)
        capture(page, f"{width}-fingerprint-confirmation")
        confirm.click()
        expect(page.get_by_role("heading", name="Network inspection complete", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="Install SirinVPN", exact=True)).to_be_enabled()
        assert not page.evaluate("window.__sirinCommands.includes('provision_server')")
        capture(page, f"{width}-network-before-install")
        page.get_by_role("button", name="Install SirinVPN", exact=True).click()
        expect(page.get_by_role("heading", name="Securing your VPS", exact=True)).to_be_visible()
        page.close()
        checks.append({"width": width, "height": height, "wifi_error_absent": True,
                       "component_update_confirmed": True, "release_fields_styled": True,
                       "ssh_fields_stable": True, "network_review_before_install": True})
    browser.close()

assert not errors, errors
report = {"synthetic_native_responses": True, "checks": checks, "page_errors": errors}
(OUT.parent / "visual-checks.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
