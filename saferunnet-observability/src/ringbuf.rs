use parking_lot::Mutex;
use std::sync::Arc;

/// Fixed-size ring buffer of log entries for RPC subscription.
/// Lokinet C++ equivalent: llarp/util/logging/buffer.hpp logRingBuffer
pub struct LogRingBuffer {
    inner: Arc<Mutex<RingBufferInner>>,
}

struct RingBufferInner {
    entries: Vec<String>,
    capacity: usize,
    write_pos: usize,
    count: usize,
}

impl LogRingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RingBufferInner {
                entries: vec![String::new(); capacity],
                capacity,
                write_pos: 0,
                count: 0,
            })),
        }
    }

    /// Push a formatted log line into the buffer
    pub fn push(&self, entry: String) {
        let mut inner = self.inner.lock();
        let pos = inner.write_pos;
        inner.entries[pos] = entry;
        inner.write_pos = (pos + 1) % inner.capacity;
        if inner.count < inner.capacity {
            inner.count += 1;
        }
    }

    /// Get all entries in insertion order (oldest first)
    pub fn entries(&self) -> Vec<String> {
        let inner = self.inner.lock();
        if inner.count == 0 {
            return vec![];
        }
        let start = if inner.count < inner.capacity {
            0
        } else {
            inner.write_pos
        };
        let mut result = Vec::with_capacity(inner.count);
        for i in 0..inner.count {
            let idx = (start + i) % inner.capacity;
            result.push(inner.entries[idx].clone());
        }
        result
    }

    /// Get count of stored entries
    pub fn len(&self) -> usize {
        self.inner.lock().count
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all entries
    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.count = 0;
        inner.write_pos = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_push_and_read() {
        let buf = LogRingBuffer::new(4);
        buf.push("one".into());
        buf.push("two".into());
        assert_eq!(buf.entries(), vec!["one", "two"]);
    }

    #[test]
    fn test_ring_buffer_wraparound() {
        let buf = LogRingBuffer::new(3);
        buf.push("a".into());
        buf.push("b".into());
        buf.push("c".into());
        buf.push("d".into()); // overwrites "a"
        assert_eq!(buf.entries(), vec!["b", "c", "d"]);
    }

    #[test]
    fn test_ring_buffer_empty() {
        let buf = LogRingBuffer::new(10);
        assert!(buf.is_empty());
        assert_eq!(buf.entries(), Vec::<String>::new());
    }
}
