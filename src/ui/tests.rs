use super::*;

#[test]
fn password_fields_must_be_filled_and_match() {
    assert!(password_problem("", "").is_some());
    assert!(password_problem("a", "b").is_some());
    assert_eq!(password_problem("a", "a"), None);
}

#[test]
fn blank_database_name_means_any_database() {
    assert_eq!(database_or_any("  "), ANY);
    assert_eq!(database_or_any(" work.kdbx "), "work.kdbx");
}

#[test]
fn folder_stays_watched_while_the_vault_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, format!("folder = {:?}", dir.path())).unwrap();
    let (folder, health) = load_health(Ok(path));
    assert_eq!(folder.as_deref(), Some(dir.path()));
    assert!(health.unwrap_err().starts_with("No vault at"));
}

#[test]
fn set_up_is_offered_until_a_vault_exists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    assert!(can_set_up(&Config::load(&path)));
    std::fs::write(&path, format!("folder = {:?}", dir.path())).unwrap();
    assert!(can_set_up(&Config::load(&path)));
    std::fs::write(dir.path().join("vault.toml"), "").unwrap();
    assert!(!can_set_up(&Config::load(&path)));
}

#[test]
fn set_up_asks_for_a_folder_first() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    assert!(matches!(
        set_up_step(&Config::load(&path)),
        Step::Settings {
            draft: None,
            then_set_up: true
        }
    ));
    std::fs::write(&path, format!("folder = {:?}", dir.path())).unwrap();
    assert!(matches!(
        set_up_step(&Config::load(&path)),
        Step::Create { .. }
    ));
}

#[test]
fn a_picked_folder_or_vault_file_names_the_vault_folder() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.toml");
    let other = dir.path().join("notes.toml");
    std::fs::write(&vault, "").unwrap();
    std::fs::write(&other, "").unwrap();
    assert_eq!(picked_folder(dir.path()), Some(dir.path()));
    assert_eq!(picked_folder(&vault), Some(dir.path()));
    assert_eq!(picked_folder(&other), None);
}

#[test]
fn folders_under_home_show_with_a_tilde() {
    let home = Path::new("/Users/me");
    assert_eq!(tilde(Path::new("/Users/me/Sync/v"), Some(home)), "~/Sync/v");
    assert_eq!(tilde(Path::new("/Volumes/v"), Some(home)), "/Volumes/v");
}

#[test]
fn a_picked_database_names_only_its_file() {
    assert_eq!(
        picked_database(Path::new("/Users/me/Sync/work.kdbx")),
        Some("work.kdbx")
    );
    assert_eq!(picked_database(Path::new("/")), None);
}

const ICONS: [&[u8]; 2] = [
    include_bytes!("../../assets/menubar.pdf"),
    include_bytes!("../../assets/menubar-warning.pdf"),
];

#[test]
fn menu_bar_icons_fill_the_menu_bar_height() {
    for pdf in ICONS {
        let size = template_icon(pdf, "icon").unwrap().size();
        assert_eq!((size.width, size.height), (15.0, 18.0));
    }
}

/// The share of a 30 x 36 px bitmap that AppKit covers when it draws `image` into it.
fn coverage(image: &NSImage) -> f64 {
    use objc2::AllocAnyThread;
    use objc2_app_kit::{NSBitmapImageRep, NSDeviceRGBColorSpace, NSGraphicsContext};
    use objc2_foundation::{NSPoint, NSRect};
    let (w, h) = (30, 36);
    let rep = unsafe {
        NSBitmapImageRep::initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bytesPerRow_bitsPerPixel(
            NSBitmapImageRep::alloc(), std::ptr::null_mut(), w, h, 8, 4, true, false, NSDeviceRGBColorSpace, 0, 0,
        )
    }
    .unwrap();
    let context = NSGraphicsContext::graphicsContextWithBitmapImageRep(&rep).unwrap();
    NSGraphicsContext::saveGraphicsState_class();
    NSGraphicsContext::setCurrentContext(Some(&context));
    image.drawInRect(NSRect::new(
        NSPoint::new(0.0, 0.0),
        NSSize::new(w as f64, h as f64),
    ));
    NSGraphicsContext::restoreGraphicsState_class();
    let row = rep.bytesPerRow() as usize;
    // SAFETY: the bitmap holds `h` rows of `row` bytes.
    let bytes = unsafe { std::slice::from_raw_parts(rep.bitmapData(), row * h as usize) };
    let covered = bytes
        .chunks(row)
        .flat_map(|line| line[..4 * w as usize].chunks(4))
        .filter(|pixel| pixel[3] > 127)
        .count();
    covered as f64 / (w * h) as f64
}

#[test]
fn menu_bar_icons_draw_their_shape() {
    // rsvg-convert turns an SVG mask into a PDF soft mask, which AppKit draws as nothing.
    for pdf in ICONS {
        let image = template_icon(pdf, "icon").unwrap();
        assert!(coverage(&image) > 0.3);
    }
}
