"""Review and before/after sheets for full_capture.py runs (system python3 with Pillow).

  python3 tests/ui/catalog/review_sheets.py RUN OUT                 # one sheet per state: desktop and mobile, dark and light
  python3 tests/ui/catalog/review_sheets.py RUN OUT --before OLD    # before (top) and after (bottom) per state, plus diff.json

Only the first screenshot of each state (its top) goes on a sheet; scroll positions stay in the run folder.
"""
import argparse, json, re
from pathlib import Path
from PIL import Image, ImageChops, ImageDraw

VARIANTS = ['desktop-dark', 'mobile-dark', 'desktop-light', 'mobile-light']
HEIGHT = 560


def tops(run):
    found = {}
    for path in Path(run).glob('*/*/*--01-top.webp'):
        variant, family = path.parts[-3], path.parts[-2]
        state = path.name[:-len('--01-top.webp')]
        found.setdefault((family, state), {})[variant] = path
    return found


def strip(images, label, height=HEIGHT):
    """One labelled row of screenshots scaled to a common height."""
    scaled = [image.resize((round(image.width * height / image.height), height)) for image in images]
    row = Image.new('RGB', (sum(i.width for i in scaled) + 8 * (len(scaled) - 1), height + 20), 'white')
    ImageDraw.Draw(row).text((4, 4), label, fill='black')
    x = 0
    for image in scaled:
        row.paste(image, (x, 20))
        x += image.width + 8
    return row


def stack(rows):
    sheet = Image.new('RGB', (max(r.width for r in rows), sum(r.height for r in rows) + 10 * (len(rows) - 1)), 'white')
    y = 0
    for row in rows:
        sheet.paste(row, (0, y))
        y += row.height + 10
    return sheet


def changed(a, b):
    """Share of pixels that differ visibly between two screenshots of the same size."""
    if a.size != b.size:
        return 1.0
    mask = ImageChops.difference(a.convert('L'), b.convert('L')).point(lambda v: 255 if v > 24 else 0)
    return sum(mask.histogram()[255:]) / (a.width * a.height)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('run', type=Path)
    parser.add_argument('out', type=Path)
    parser.add_argument('--before', type=Path)
    parser.add_argument('--filter', default='')
    args = parser.parse_args()
    after = tops(args.run)
    before = tops(args.before) if args.before else {}
    args.out.mkdir(parents=True, exist_ok=True)
    diff = {}
    for (family, state), shots in sorted(after.items()):
        if not re.search(args.filter, f'{family}/{state}'):
            continue
        variants = [v for v in VARIANTS if v in shots]
        if args.before:
            old = before.get((family, state), {})
            pairs = [v for v in variants if v in old]
            if not pairs:
                continue
            diff[f'{family}/{state}'] = {v: round(changed(Image.open(old[v]), Image.open(shots[v])), 3) for v in pairs}
            dark = [v for v in pairs if v.endswith('dark')] or pairs[:2]
            rows = [strip([Image.open(old[v]) for v in dark], f'BEFORE {family}/{state}  ({", ".join(dark)})'),
                    strip([Image.open(shots[v]) for v in dark], 'AFTER')]
        else:
            rows = [strip([Image.open(shots[v]) for v in variants[:2]], f'{family}/{state}  ({", ".join(variants[:2])})')]
            if len(variants) > 2:
                # The light theme at half size: enough to spot unthemed or low-contrast areas.
                rows.append(strip([Image.open(shots[v]) for v in variants[2:]], ', '.join(variants[2:]), HEIGHT // 2))
        folder = args.out / family
        folder.mkdir(exist_ok=True)
        stack(rows).save(folder / f'{state}.webp', quality=82)
    if args.before:
        (args.out / 'diff.json').write_text(json.dumps(diff, indent=1) + '\n')
        print(f'{len(diff)} states compared; {sum(max(v.values()) > .01 for v in diff.values())} changed visibly')


if __name__ == '__main__':
    main()
