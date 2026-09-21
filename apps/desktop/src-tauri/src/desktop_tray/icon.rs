//! Small native state badges, rendered locally from the bundled application icon.
use super::model::IconState;
use tauri::image::Image;

pub fn render(base: &Image<'_>, state: IconState) -> Image<'static> {
    const SIZE: usize = 32;
    let mut pixels = vec![0u8; SIZE * SIZE * 4];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let source = ((y * base.height() as usize / SIZE) * base.width() as usize
                + x * base.width() as usize / SIZE)
                * 4;
            let offset = (y * SIZE + x) * 4;
            pixels[offset..offset + 4].copy_from_slice(&base.rgba()[source..source + 4]);
            if state == IconState::Disconnected {
                let gray = ((u16::from(pixels[offset])
                    + u16::from(pixels[offset + 1])
                    + u16::from(pixels[offset + 2]))
                    / 3) as u8;
                pixels[offset..offset + 3].fill(gray);
                pixels[offset + 3] = (u16::from(pixels[offset + 3]) * 3 / 4) as u8;
            }
        }
    }
    if state == IconState::Disconnected {
        return Image::new_owned(pixels, SIZE as u32, SIZE as u32);
    }
    let color = match state {
        IconState::Connected => [38, 220, 167, 255],
        IconState::Blocked => [66, 197, 248, 255],
        IconState::Progress => [177, 157, 255, 255],
        _ => [255, 195, 83, 255],
    };
    for y in 16i32..32 {
        for x in 16i32..32 {
            let radius = (x - 24).pow(2) + (y - 24).pow(2);
            if radius > 60 {
                continue;
            }
            let pixel = &mut pixels[(y as usize * SIZE + x as usize) * 4..][..4];
            let glyph = match state {
                IconState::Connected => {
                    (21..=24).contains(&x) && y == x + 3 || (24..=28).contains(&x) && y == 51 - x
                }
                IconState::Blocked => {
                    (21..=27).contains(&x) && (24..=28).contains(&y)
                        || (x == 22 || x == 26) && (21..=24).contains(&y)
                        || y == 20 && (23..=25).contains(&x)
                }
                IconState::Progress => {
                    x == 24 && (20..=24).contains(&y) || y == 24 && (24..=27).contains(&x)
                }
                _ => (x == 24 || x == 25) && ((20..=25).contains(&y) || y == 28),
            };
            pixel.copy_from_slice(if radius > 44 || glyph {
                &[7, 15, 30, 255]
            } else {
                &color
            });
        }
    }
    Image::new_owned(pixels, SIZE as u32, SIZE as u32)
}
