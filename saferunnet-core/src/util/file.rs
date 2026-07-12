use std::fs;
use std::io;
use std::path::Path;

/// Ensure a directory exists, creating it and all parents if needed.
pub fn ensure_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    fs::create_dir_all(path)
}

/// Atomically write content to a file (write to temp, then rename).
pub fn atomic_write<P: AsRef<Path>>(path: P, content: &[u8]) -> io::Result<()> {
    let path = path.as_ref();
    let dir = path.parent().unwrap_or_else(|| Path::new("."));

    // Write to a temp file in the same directory
    let tmp_path = dir.join(format!(
        ".tmp_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    fs::write(&tmp_path, content)?;
    fs::rename(&tmp_path, path)?;

    Ok(())
}

/// Read a file if it exists, returning None if it doesn't.
pub fn read_file_if_exists<P: AsRef<Path>>(path: P) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_atomic_write_and_read() {
        let dir = env::temp_dir().join("saferunnet_util_test");
        ensure_dir(&dir).unwrap();
        let path = dir.join("test_atomic.txt");

        atomic_write(&path, b"hello world").unwrap();
        let data = read_file_if_exists(&path).unwrap();
        assert_eq!(data, Some(b"hello world".to_vec()));

        // Cleanup
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_read_nonexistent() {
        let result = read_file_if_exists("__nonexistent_file_xyz123__").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_ensure_dir_creates() {
        let dir = env::temp_dir().join("saferunnet_util_ensure");
        // Make sure it's clean
        let _ = fs::remove_dir_all(&dir);
        ensure_dir(&dir).unwrap();
        assert!(dir.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
