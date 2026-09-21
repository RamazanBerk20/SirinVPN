use super::*;

#[test]
fn library_guards_cannot_release_the_outer_maintenance_lease() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lease");
    let file = File::create(&path).unwrap();
    FileExt::try_lock_exclusive(&file).unwrap();
    let host = SystemServerHost {
        paths: crate::ServerPaths::under(directory.path()),
        maintenance: file,
    };
    let competing = File::open(path).unwrap();
    for _ in 0..3 {
        let guard = host.lock().unwrap();
        assert!(FileExt::try_lock_exclusive(&competing).is_err());
        drop(guard);
        assert!(FileExt::try_lock_exclusive(&competing).is_err());
    }
    drop(host);
    FileExt::try_lock_exclusive(&competing).unwrap();
}
