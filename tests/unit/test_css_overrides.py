"""Stylesheets must not pile up overrides: every declaration takes effect, and the app shell has one home."""
from pathlib import Path
import re
import unittest

SRC = Path(__file__).resolve().parents[2] / "apps/desktop/src"
SHELL = re.compile(r"(^|[\s,>])\.(app-shell|sidebar|sidebar-heading|sidebar-foot|primary-navigation|server-list|server-row|server-glyph)\b")
# window.css fits the shell under the custom title bar; Android hides the sidebar and restyles the shell.
SHELL_EXEMPT = re.compile(r"android|data-window-chrome|\.workspace|initialization-shell")


def stylesheets():
    """The app's stylesheets in cascade order: styles.css imports, then mobile-native.css (main.tsx)."""
    names = re.findall(r'@import "\./(styles/[^"]+)"', (SRC / "styles.css").read_text())
    return [SRC / name for name in names] + [SRC / "styles/mobile-native.css"]


def split(head):
    """Selectors of a list, split on top-level commas only (not inside :is(), :not() or :has())."""
    parts, depth, current = [], 0, ""
    for char in head:
        depth += (char == "(") - (char == ")")
        if char == "," and not depth:
            parts.append(current.strip())
            current = ""
        else:
            current += char
    return parts + [current.strip()]


def rules(text):
    """(media context, selectors, declarations) for each style rule outside @keyframes."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    found, stack, start = [], [], 0
    for index, char in enumerate(text):
        if char == "{":
            stack.append((" ".join(text[start:index].split()), index + 1))
            start = index + 1
        elif char == "}":
            head, body = stack.pop()
            if not head.startswith("@") and not any(h.startswith("@keyframes") for h, _ in stack):
                properties = [d.split(":", 1)[0].strip().lower() for d in text[body:index].split(";") if ":" in d]
                important = {d.split(":", 1)[0].strip().lower() for d in text[body:index].split(";") if "!important" in d}
                found.append((tuple(h for h, _ in stack), split(head), properties, important))
            start = index + 1
        elif char == ";" and (not stack or stack[-1][0].startswith("@")):
            start = index + 1
    return found


class CssOverrides(unittest.TestCase):
    def test_no_declaration_is_overridden_by_the_same_selector(self):
        # The same selector has the same specificity, so a later rule repeating a property wins; a declaration
        # whose every selector is repeated that way never applies. (Overriding one selector of a list is allowed.)
        last, overridden, owners = {}, {}, {}
        for path in stylesheets():
            for number, (context, selectors, properties, important) in enumerate(rules(path.read_text())):
                rule = (path.name, number)
                for prop in properties:
                    owners[(rule, prop)] = (selectors, prop in important)
                    for selector in selectors:
                        earlier = last.get((context, selector, prop))
                        if earlier and earlier != rule:
                            overridden.setdefault((earlier, prop), set()).add((selector, path.name))
                        last[(context, selector, prop)] = rule
        dead = [f"{rule[0]}: {', '.join(owners[(rule, prop)][0])} {{ {prop} }} is overridden by {sorted({f for _, f in hits})}"
                for (rule, prop), hits in overridden.items()
                if not owners[(rule, prop)][1] and {s for s, _ in hits} >= set(owners[(rule, prop)][0])]
        self.assertEqual(dead, [], "Change the existing declaration instead of overriding it in a later rule")

    def test_shell_rules_live_in_shell_css(self):
        stray = [f"{path.name}: {selector}"
                 for path in stylesheets() if path.name not in {"shell.css", "window.css", "mobile-native.css"}
                 for _, selectors, _, _ in rules(path.read_text())
                 for selector in selectors if SHELL.search(selector) and not SHELL_EXEMPT.search(selector)]
        self.assertEqual(stray, [], "Sidebar, navigation and server-list rules belong in styles/shell.css")


if __name__ == "__main__":
    unittest.main()
