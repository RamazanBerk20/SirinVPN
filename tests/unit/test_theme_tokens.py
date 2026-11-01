"""Stylesheet colours must come from theme tokens so the light and dark palettes stay complete."""
from pathlib import Path
import re
import unittest

STYLES = Path(__file__).resolve().parents[2] / "apps/desktop/src/styles"
LITERAL = re.compile(r"#[0-9a-f]{3,8}\b|\b(?:rgba?|hsla?)\(", re.I)
# Token definitions may hold literals; QR codes need white and masks need opaque black.
EXEMPT = re.compile(r"^\s*--[\w-]+\s*:|qr|mask-image", re.I)


class ThemeTokens(unittest.TestCase):
    def test_rules_use_tokens(self):
        found = [f"{path.name}:{number}: {line.strip()}"
                 for path in sorted(STYLES.glob("*.css"))
                 for number, line in enumerate(path.read_text().splitlines(), 1)
                 if LITERAL.search(line) and not EXEMPT.search(line)]
        self.assertEqual(found, [], "Use var(--…) or color-mix() of tokens instead of colour literals")


if __name__ == "__main__":
    unittest.main()
